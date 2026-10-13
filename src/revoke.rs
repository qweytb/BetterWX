use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use iced_x86::{
    Code, Instruction, Mnemonic, OpKind, Register,
    code_asm::{
        AsmMemoryOperand, AsmRegister64, CodeAssembler, al, byte_ptr, dword_ptr, eax, edx, esi,
        ptr, qword_ptr, r8, r8d, r9, r9d, r10, r11, r12, r13, r14, r15, rax, rbp, rbx, rcx, rdi,
        rdx, rsi, rsp, sil,
    },
};

use crate::{
    Result,
    feature::{Edit, Feature, Target},
    image::{Image, References, Symbols, functions},
    progress::{Progress, Step},
    xlog,
};

const REVOKE: &str = "kernel::manager::MessageRevokeManager::CoReplaceOriginMessageByRevoke";
const DELETE: &str = "kernel::manager::MessageManager::DeleteMessages";
const SORT: &str = "kernel::manager::MessageStorage::CheckSortSeqIfNeeded";
const ADD: &str = "kernel::manager::MessageStorageImpl::CoAddMessageToDB";
const UNREAD: &str = "kernel::manager::SessionManager::UpdateSessionUnreadWithRevokedMessage";
const SESSION: &str = "kernel::manager::SessionStorageImpl::CoUpdateSessionWithRevokedMessageToDB";
const VIEW: &str = "virtual mmui::ChatMessageViewModel::OnMessageRevoke";
const GROUP: &str = "[group msg]add groupinfo in revoked group msg:";
const SUMMARY: &str = "kernel::service::SessionService::CoHandleMessageRevoke";
const REFRESH: &str = "kernel::service::SessionService::CoHandleRevokedMessageOutOfDate";

pub const FEATURE: Feature = Feature {
    id: "revoke",
    name: "防撤回",
    description: "保留对方撤回的消息",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

struct Message {
    local: i64,
    server: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Slot {
    base: Register,
    offset: i64,
}

impl Slot {
    fn from(instruction: &Instruction) -> Result<Self> {
        if instruction.memory_index() != Register::None {
            return Err("消息字段使用了索引寻址".into());
        }
        Ok(Self {
            base: instruction.memory_base(),
            offset: instruction.memory_displacement64() as i64,
        })
    }

    fn add(self, offset: i64) -> Self {
        Self {
            offset: self.offset + offset,
            ..self
        }
    }

    fn entered(self, stack: i64) -> Self {
        self.add(if self.base == Register::RSP {
            stack + 8
        } else {
            0
        })
    }

    fn memory(self) -> Result<AsmMemoryOperand> {
        Ok(ptr(register(self.base)? + self.offset))
    }
}

fn register(value: Register) -> Result<AsmRegister64> {
    Ok(match value {
        Register::RAX => rax,
        Register::RCX => rcx,
        Register::RDX => rdx,
        Register::RBX => rbx,
        Register::RSP => rsp,
        Register::RBP => rbp,
        Register::RSI => rsi,
        Register::RDI => rdi,
        Register::R8 => r8,
        Register::R9 => r9,
        Register::R10 => r10,
        Register::R11 => r11,
        Register::R12 => r12,
        Register::R13 => r13,
        Register::R14 => r14,
        Register::R15 => r15,
        _ => return Err(format!("需要 64 位通用寄存器：{value:?}").into()),
    })
}

fn unique<T>(values: Vec<T>, description: &str) -> Result<T> {
    let [value]: [T; 1] = values
        .try_into()
        .map_err(|_| format!("无法唯一定位{description}"))?;
    Ok(value)
}

fn calls(instructions: &[Instruction]) -> impl DoubleEndedIterator<Item = &Instruction> {
    instructions
        .iter()
        .filter(|instruction| instruction.code() == Code::Call_rel32_64)
}

fn wrapper(image: &Image<'_>, instructions: &[Instruction], target: u64) -> Result<u64> {
    let mut found = BTreeSet::new();
    for address in calls(instructions)
        .map(Instruction::near_branch_target)
        .collect::<BTreeSet<_>>()
    {
        if let Some(function) = image.function(address)?
            && calls(&image.instructions(&function)?)
                .any(|call| call.near_branch_target() == target)
        {
            found.insert(address);
        }
    }
    unique(found.into_iter().collect(), "原生调用包装函数")
}

fn patch(image: &Image<'_>, range: Range<u64>, assembler: &mut CodeAssembler) -> Result<Edit> {
    let mut bytes = assembler.assemble(range.start)?;
    let size = usize::try_from(range.end - range.start)?;
    if bytes.len() > size {
        return Err(format!("RVA {:#x} 的指令空间不足", range.start - image.base()).into());
    }
    bytes.resize(size, 0x90);
    let offset = image.offset(range.start)?;
    Ok(Edit {
        range: offset..offset + size,
        bytes,
    })
}

fn call_patch(image: &Image<'_>, instruction: &Instruction, target: u64) -> Result<Edit> {
    let mut assembler = CodeAssembler::new(64)?;
    assembler.call(target)?;
    patch(
        image,
        instruction.ip()..instruction.next_ip(),
        &mut assembler,
    )
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    xlog::find(
        image,
        &[
            REVOKE, DELETE, SORT, ADD, UNREAD, SESSION, VIEW, GROUP, SUMMARY, REFRESH,
        ],
        progress,
    )
}

fn scan(
    image: &Image<'_>,
    symbols: &Symbols,
    references: &References,
    progress: &Progress,
) -> Result<Vec<Edit>> {
    let step = progress.activity("定位消息处理");
    let mut found = BTreeMap::new();
    for name in [
        REVOKE, DELETE, SORT, ADD, UNREAD, SESSION, VIEW, SUMMARY, REFRESH,
    ] {
        progress.check()?;
        let function = unique(
            functions(name, symbols, references).into_values().collect(),
            name,
        )?;
        step.detail(format!("{name}\nRVA {:#x}", function.start - image.base()));
        found.insert(name, function);
    }
    let root = image.instructions(&found[REVOKE])?;
    let deletion = wrapper(image, &root, found[DELETE].start)?;
    let delete_sites: Vec<_> = root
        .iter()
        .enumerate()
        .filter(|(_, instruction)| {
            instruction.code() == Code::Call_rel32_64
                && instruction.near_branch_target() == deletion
        })
        .map(|(index, _)| index)
        .collect();
    let mut original = None;
    let mut manager = None;
    let mut ordinary = None;
    for &index in &delete_sites {
        let receiver = &root[index - 3];
        if receiver.code() != Code::Mov_r64_rm64
            || receiver.op0_register() != Register::RCX
            || receiver.op1_kind() != OpKind::Memory
        {
            return Err("无法识别撤回删除调用的管理器参数".into());
        }
        let slot = Slot::from(receiver)?;
        if manager
            .replace(slot)
            .is_some_and(|previous| previous != slot)
        {
            return Err("撤回分支的管理器位置不一致".into());
        }
        let argument = &root[index - 2];
        if argument.mnemonic() != Mnemonic::Lea || argument.op0_register() != Register::RDX {
            return Err("无法识别撤回删除调用的消息参数".into());
        }
        let slot = Slot::from(argument)?;
        if original
            .replace(slot)
            .is_some_and(|previous| previous != slot)
        {
            return Err("撤回分支的原消息位置不一致".into());
        }
        if root[index - 1].mnemonic() == Mnemonic::Xor
            && root[index - 1].op0_register() == Register::R8D
            && root[index - 1].op1_register() == Register::R8D
        {
            ordinary = Some(index);
        }
    }
    let original = original.ok_or("找不到撤回删除调用")?;
    let manager = manager.ok_or("找不到撤回消息管理器")?;
    let ordinary = ordinary.ok_or("找不到普通消息删除分支")?;
    let add_index = root
        .windows(3)
        .enumerate()
        .skip(ordinary + 1)
        .find(|(_, window)| {
            window[0].mnemonic() == Mnemonic::Lea
                && window[0].op0_register() == Register::RDX
                && window[1].mnemonic() == Mnemonic::Lea
                && window[1].op0_register() == Register::R8
                && window[2].code() == Code::Call_rel32_64
        })
        .map(|(index, _)| index + 2)
        .ok_or("找不到撤回提示入库调用")?;
    let tip = Slot::from(&root[add_index - 1])?;
    let added_function = image
        .function(root[add_index].near_branch_target())?
        .ok_or("找不到提示入库函数")?;
    let added = image.instructions(&added_function)?;
    let add_bridge = wrapper(image, &added, found[ADD].start)?;
    let shown = image.instructions(&found[VIEW])?;
    let compared = comparisons(&shown);
    let first = compared.first().ok_or("找不到撤回提示的排序比较")?;
    let cast = calls(&shown[..first.argument])
        .next_back()
        .ok_or("找不到视图项类型转换")?;
    let view_type = shown
        .iter()
        .rev()
        .find(|instruction| {
            instruction.ip() < cast.ip()
                && instruction.mnemonic() == Mnemonic::Lea
                && instruction.op0_register() == Register::R9
                && instruction.is_ip_rel_memory_operand()
        })
        .ok_or("找不到消息视图类型")?
        .ip_rel_memory_address();
    let callers = references
        .get(add_bridge)
        .ok_or("找不到入库包装函数的引用")?;
    if !callers.eq([&added_function]) {
        return Err("入库包装函数还有其他引用".into());
    }
    let bridge = image
        .function(add_bridge)?
        .ok_or("找不到入库包装函数范围")?;
    let success = root
        .iter()
        .enumerate()
        .skip(add_index + 1)
        .find(|(_, instruction)| {
            matches!(
                instruction.code(),
                Code::Cmp_rm32_imm8 | Code::Cmp_rm32_imm32
            ) && instruction.memory_base() == tip.base
                && instruction.immediate32() == 0
        })
        .map(|(index, _)| index)
        .ok_or("找不到提示入库结果判断")?;
    let local = Slot::from(&root[success])?.offset - tip.offset;

    let own = message_check(image, &image.instructions(&found[SORT])?)?;
    let unread = image.instructions(&found[UNREAD])?;
    let session_call = unique(
        unread
            .iter()
            .enumerate()
            .filter(|(_, instruction)| {
                instruction.code() == Code::Call_rel32_64
                    && instruction.near_branch_target() == found[SESSION].start
            })
            .map(|(index, _)| index)
            .collect(),
        "撤回会话更新调用",
    )?;
    let server = unread[..session_call]
        .iter()
        .rev()
        .find(|instruction| {
            instruction.code() == Code::Mov_r64_rm64
                && instruction.op0_register() == Register::R9
                && instruction.op1_kind() == OpKind::Memory
        })
        .ok_or("找不到撤回目标编号参数")?
        .memory_displacement64() as i64;
    let empty = empty_result(image, &root, add_index, success, tip)?;
    let message = Message { local, server };
    let (mut edits, cleanup) = summary(
        image,
        &found[SUMMARY],
        &message,
        found[UNREAD].start,
        found[REFRESH].start,
        references,
        progress,
    )?;
    step.finish(format!(
        "{REVOKE}；RVA 0x{:08X}\n发送者判定；RVA 0x{:08X}",
        found[REVOKE].start - image.base(),
        own - image.base(),
    ));

    let step = progress.activity("准备消息保留");
    let mut assembler = CodeAssembler::new(64)?;
    let mut keep = assembler.create_label();
    let mut done = assembler.create_label();
    assembler.push(rsi)?;
    assembler.sub(rsp, 0x30)?;
    assembler.mov(esi, r8d)?;
    assembler.mov(rcx, rdx)?;
    assembler.call(own)?;
    assembler.test(al, al)?;
    assembler.je(keep)?;
    assembler.mov(rcx, qword_ptr(manager.entered(0x38).memory()?))?;
    assembler.lea(rdx, original.entered(0x38).memory()?)?;
    assembler.mov(r8d, esi)?;
    assembler.add(rsp, 0x30)?;
    assembler.pop(rsi)?;
    assembler.jmp(deletion)?;
    assembler.set_label(&mut keep)?;
    assembler.test(sil, sil)?;
    assembler.jne(done)?;
    assembler.xor(eax, eax)?;
    assembler.mov(dword_ptr(tip.add(local).entered(0x38).memory()?), eax)?;
    assembler.inc(qword_ptr(tip.add(server).entered(0x38).memory()?))?;
    assembler.set_label(&mut done)?;
    assembler.add(rsp, 0x30)?;
    assembler.pop(rsi)?;
    assembler.ret()?;

    let group_condition = group_condition(&root, ordinary, &symbols[GROUP])?;
    let mut group = CodeAssembler::new(64)?;
    let mut finish = group.create_label();
    group.sub(rsp, 0x28)?;
    group.xor(eax, eax)?;
    group.cmp(
        qword_ptr(Slot::from(&root[group_condition])?.entered(0x28).memory()?),
        0,
    )?;
    group.je(finish)?;
    group.lea(rcx, original.entered(0x28).memory()?)?;
    group.call(own)?;
    group.set_label(&mut finish)?;
    group.add(rsp, 0x28)?;
    group.ret()?;
    edits.extend(image.replace_function(
        &bridge,
        &mut assembler,
        &[1, 5, 2, 0, 5, 0x52, 1, 0x60],
    )?);
    edits.extend(image.replace_function(&cleanup, &mut group, &[1, 4, 1, 0, 4, 0x42, 0, 0])?);
    for index in delete_sites {
        edits.push(call_patch(image, &root[index], bridge.start)?);
        step.record(format!(
            "RVA 0x{:08X}；call 0x{:08X} → call 0x{:08X}",
            root[index].ip() - image.base(),
            deletion - image.base(),
            bridge.start - image.base(),
        ));
    }
    let mut group = CodeAssembler::new(64)?;
    group.call(cleanup.start)?;
    group.test(al, al)?;
    group.je(root[group_condition + 1].near_branch_target())?;
    edits.push(patch(
        image,
        root[group_condition].ip()..root[group_condition + 1].next_ip(),
        &mut group,
    )?);
    edits.push(add_arguments(
        image,
        &added,
        add_bridge,
        found[ADD].start,
        local,
    )?);
    edits.push(empty);
    edits.push(unread_count(image, &unread, session_call)?);
    step.finish(format!(
        "发送者判定：AL ≠ 0 → jmp 0x{:08X}；AL = 0 → ret\n\
         提示字段：localId [+{local:#x}] → 0；svrId [+{server:#x}] += 1\n\
         {ADD}：新增记录参数 = (localId == 0)\n\
         图片组继承条件：call 0x{:08X}；test al,al；je 跳过继承\n\
         {UNREAD}：保留未读计数参数 → 1\n\
         {SUMMARY}：call {REFRESH}；RVA 0x{:08X}",
        deletion - image.base(),
        cleanup.start - image.base(),
        found[REFRESH].start - image.base(),
    ));

    let step = progress.activity("准备消息显示");
    edits.extend(view(
        image,
        &shown,
        references
            .get(view_type)
            .ok_or("找不到消息视图类型的引用")?,
        &step,
    )?);
    step.finish(format!(
        "{VIEW}；RVA 0x{:08X}；sortSeq 相等 → 比较 localId",
        found[VIEW].start - image.base(),
    ));
    Ok(edits)
}

fn message_check(image: &Image<'_>, instructions: &[Instruction]) -> Result<u64> {
    let mut found = BTreeSet::new();
    for address in calls(instructions).map(Instruction::near_branch_target) {
        let Some(function) = image.function(address)? else {
            continue;
        };
        let instructions = image.instructions(&function)?;
        if instructions.windows(2).any(|window| {
            window[0].code() == Code::Cmp_rm32_imm32
                && window[0].memory_base() == Register::RCX
                && window[0].immediate32() == 10000
                && window[1].mnemonic() == Mnemonic::Je
        }) {
            found.insert(address);
        }
    }
    unique(found.into_iter().collect(), "原生发送者判定")
}

fn group_condition(
    instructions: &[Instruction],
    deletion: usize,
    messages: &[u64],
) -> Result<usize> {
    let mut candidates = Vec::new();
    for (index, window) in instructions.windows(2).enumerate().take(deletion) {
        if window[0].code() != Code::Cmp_rm64_imm8
            || window[0].op0_kind() != OpKind::Memory
            || window[0].immediate8() != 0
            || !matches!(window[1].code(), Code::Je_rel8_64 | Code::Je_rel32_64)
        {
            continue;
        }
        let target = window[1].near_branch_target();
        if target <= window[1].ip() || target >= instructions[deletion].ip() {
            continue;
        }
        if instructions.iter().any(|instruction| {
            instruction.ip() > window[1].ip()
                && instruction.ip() < target
                && instruction.is_ip_rel_memory_operand()
                && messages.contains(&instruction.ip_rel_memory_address())
        }) {
            candidates.push(index);
        }
    }
    unique(candidates, "图片组信息继承条件")
}

fn add_arguments(
    image: &Image<'_>,
    instructions: &[Instruction],
    bridge: u64,
    target: u64,
    local: i64,
) -> Result<Edit> {
    let call = unique(
        calls(instructions)
            .filter(|instruction| instruction.near_branch_target() == bridge)
            .copied()
            .collect(),
        "提示入库参数包装调用",
    )?;
    let getter = calls(instructions)
        .rfind(|instruction| instruction.ip() < call.ip())
        .ok_or("找不到提示的会话名访问函数")?;
    let message = instructions
        .iter()
        .find(|instruction| {
            instruction.ip() < getter.ip()
                && instruction.mnemonic() == Mnemonic::Mov
                && instruction.op1_kind() == OpKind::Register
                && instruction.op1_register() == Register::R8
                && instruction.op0_register() != Register::RCX
        })
        .ok_or("找不到入库消息寄存器")?
        .op0_register();
    let arguments: Vec<_> = instructions
        .iter()
        .filter(|instruction| instruction.ip() >= getter.next_ip() && instruction.ip() < call.ip())
        .collect();
    let receiver = arguments
        .iter()
        .rev()
        .find(|instruction| {
            instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_register() == Register::RCX
                && instruction.op1_kind() == OpKind::Register
        })
        .ok_or("找不到入库存储对象")?;
    let result = arguments
        .iter()
        .rev()
        .find(|instruction| {
            instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_register() == Register::R8
                && instruction.op1_kind() == OpKind::Register
        })
        .ok_or("找不到入库结果寄存器")?
        .op1_register();
    let result_address = arguments
        .iter()
        .rev()
        .find(|instruction| {
            instruction.mnemonic() == Mnemonic::Lea && instruction.op0_register() == result
        })
        .ok_or("找不到入库结果空间")?;
    let mut assembler = CodeAssembler::new(64)?;
    assembler.cmp(dword_ptr(register(message)? + local), 0)?;
    assembler.sete(byte_ptr(rsp + 0x20))?;
    assembler.mov(byte_ptr(rsp + 0x28), 1)?;
    for instruction in &arguments {
        if instruction.mnemonic() == Mnemonic::Movsd {
            assembler.add_instruction(**instruction)?;
        }
    }
    assembler.mov(r9, rax)?;
    assembler.mov(r8, register(message)?)?;
    assembler.add_instruction(**result_address)?;
    assembler.mov(rdx, register(result)?)?;
    assembler.add_instruction(**receiver)?;
    let size = assembler.assemble(getter.next_ip())?.len();
    let available = usize::try_from(call.ip() - getter.next_ip())?;
    if size > available {
        return Err("提示入库参数的指令空间不足".into());
    }
    for _ in size..available {
        assembler.nop()?;
    }
    assembler.call(target)?;
    patch(image, getter.next_ip()..call.next_ip(), &mut assembler)
}

fn empty_result(
    image: &Image<'_>,
    instructions: &[Instruction],
    added: usize,
    success: usize,
    tip: Slot,
) -> Result<Edit> {
    let first_call = calls(instructions).next().ok_or("撤回函数缺少调用")?.ip();
    let output = unique(
        instructions
            .iter()
            .filter(|instruction| {
                instruction.ip() < first_call
                    && instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.op1_register() == Register::RDX
            })
            .map(Instruction::op0_register)
            .collect(),
        "撤回输出寄存器",
    )?;
    let (flag, cleanup) = unique(
        instructions[added..]
            .windows(2)
            .filter(|window| {
                matches!(window[0].code(), Code::Mov_rm8_r8 | Code::Mov_rm8_imm8)
                    && window[0].memory_base() == output
                    && window[1].mnemonic() == Mnemonic::Lea
                    && window[1].op0_register() == Register::RCX
                    && window[1].memory_base() == tip.base
                    && window[1].memory_displacement64() as i64 == tip.offset
            })
            .map(|window| (window[0], window[1].ip()))
            .collect(),
        "撤回提示的结果清理",
    )?;
    let branch = instructions[success + 1];
    if !matches!(branch.code(), Code::Je_rel8_64 | Code::Je_rel32_64) {
        return Err("提示入库结果分支与预期不同".into());
    }
    let start = branch.near_branch_target();
    let mut assembler = CodeAssembler::new(64)?;
    assembler.mov(byte_ptr(Slot::from(&flag)?.memory()?), 0)?;
    assembler.jmp(cleanup)?;
    let size = assembler.assemble(start)?.len() as u64;
    let end = instructions
        .iter()
        .find(|instruction| instruction.ip() >= start && instruction.next_ip() >= start + size)
        .ok_or("找不到结果处理指令范围")?
        .next_ip();
    let cleanup_index = instructions
        .iter()
        .position(|instruction| instruction.ip() == cleanup)
        .ok_or("找不到提示析构位置")?;
    let destroy = instructions[cleanup_index + 1];
    if destroy.code() != Code::Call_rel32_64 {
        return Err("无法识别消息析构调用".into());
    }
    patch(image, start..end, &mut assembler)
}

fn unread_count(image: &Image<'_>, instructions: &[Instruction], call: usize) -> Result<Edit> {
    let start = instructions[..call]
        .iter()
        .rposition(|instruction| {
            instruction.code() == Code::Mov_rm8_r8 && instruction.memory_base() == Register::RSP
        })
        .ok_or("找不到撤回未读处理参数")?;
    let mut assembler = CodeAssembler::new(64)?;
    assembler.mov(byte_ptr(Slot::from(&instructions[start])?.memory()?), 1)?;
    for instruction in &instructions[start + 1..=call] {
        assembler.add_instruction(*instruction)?;
    }
    let end = match instructions.get(call + 1) {
        Some(instruction) if instruction.mnemonic() == Mnemonic::Nop => instruction.next_ip(),
        _ => instructions[call].next_ip(),
    };
    patch(image, instructions[start].ip()..end, &mut assembler)
}

fn summary(
    image: &Image<'_>,
    function: &Range<u64>,
    message: &Message,
    update: u64,
    refresh: u64,
    references: &References,
    progress: &Progress,
) -> Result<(Vec<Edit>, Range<u64>)> {
    let instructions = image.instructions(function)?;
    let compare = unique(
        instructions
            .windows(3)
            .filter(|window| {
                window[0].code() == Code::Mov_r32_rm32
                    && window[0].op0_register() == Register::EAX
                    && window[1].code() == Code::Cmp_r32_rm32
                    && window[1].op0_register() == Register::EAX
                    && window[1].op1_kind() == OpKind::Memory
                    && window[1].memory_displacement64() as i64 == message.local
                    && matches!(window[2].code(), Code::Ja_rel8_64 | Code::Ja_rel32_64)
            })
            .collect(),
        "撤回摘要的消息编号比较",
    )?;
    let notify = unique(
        calls(&instructions)
            .filter(|call| call.near_branch_target() == update)
            .collect(),
        "撤回摘要的会话更新调用",
    )?;
    let session = instructions
        .iter()
        .rev()
        .find(|instruction| {
            instruction.ip() < notify.ip()
                && instruction.mnemonic() == Mnemonic::Lea
                && instruction.op0_register() == Register::RDX
        })
        .ok_or("找不到摘要所属会话")?;
    let session = Slot::from(session)?;
    let source = compare[1].memory_base();
    let receiver = instructions
        .iter()
        .take_while(|instruction| instruction.code() != Code::Call_rel32_64)
        .find(|instruction| {
            instruction.code() == Code::Mov_rm64_r64
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_register() == Register::RCX
        })
        .ok_or("找不到会话服务对象")?
        .op0_register();
    let continuation = unique(
        instructions
            .iter()
            .filter(|instruction| {
                instruction.ip() > notify.ip()
                    && instruction.code() == Code::Mov_r64_rm64
                    && instruction.op0_register() == receiver
                    && instruction.op1_kind() == OpKind::Memory
                    && instruction.memory_base() == source
                    && instruction.memory_displacement64() as i64 == message.server
            })
            .collect(),
        "撤回群信息更新入口",
    )?;
    let removed = compare[2].next_ip()..compare[2].near_branch_target();
    let (mut edits, cleanup, address) = cleanup(image, function, &removed, references, progress)?;
    let mut branch = CodeAssembler::new(64)?;
    branch.jmp(removed.end)?;
    edits.push(patch(image, compare[0].ip()..removed.start, &mut branch)?);
    let mut code = CodeAssembler::new(64)?;
    code.mov(rax, qword_ptr(register(source)? + message.server))?;
    // The summary flag occupies the tail of this slot and is finished here.
    code.mov(qword_ptr(session.add(0x20).memory()?), rax)?;
    code.mov(rcx, register(receiver)?)?;
    code.lea(rdx, session.memory()?)?;
    code.call(refresh)?;
    code.add_instruction(*continuation)?;
    code.jmp(continuation.next_ip())?;
    let size = code.assemble(address)?.len() as u64;
    let end = instructions
        .iter()
        .find(|instruction| instruction.ip() >= address && instruction.next_ip() >= address + size)
        .ok_or("找不到摘要刷新指令范围")?
        .next_ip();
    if end > removed.end {
        return Err("摘要刷新的指令空间不足".into());
    }
    edits.push(patch(image, address..end, &mut code)?);
    let mut branch = CodeAssembler::new(64)?;
    branch.jmp(address)?;
    edits.push(patch(
        image,
        continuation.ip()..continuation.next_ip(),
        &mut branch,
    )?);
    Ok((edits, cleanup))
}

fn cleanup(
    image: &Image<'_>,
    function: &Range<u64>,
    removed: &Range<u64>,
    references: &References,
    progress: &Progress,
) -> Result<(Vec<Edit>, Range<u64>, u64)> {
    let unwind = image.unwind_info(function.start)?;
    let header = image.data(unwind, 4)?;
    if !matches!(header[0] >> 3, 1..=3) {
        return Err("无法识别摘要的异常处理信息".into());
    }
    let handler = unwind + (4 + u64::from(header[2]) * 2).next_multiple_of(4);
    let info = image.base() + u32::from_le_bytes(image.data(handler + 4, 4)?.try_into()?) as u64;
    let fields: Vec<_> = image
        .data(info, 40)?
        .as_chunks::<4>()
        .0
        .iter()
        .map(|field| u32::from_le_bytes(*field))
        .collect();
    if fields[0] & 0x1fff_ffff != 0x1993_0522 {
        return Err("无法识别摘要的 C++ 清理表".into());
    }
    let actions: Vec<_> = image
        .data(image.base() + fields[2] as u64, fields[1] as usize * 8)?
        .as_chunks::<8>()
        .0
        .iter()
        .map(|entry| {
            (
                i32::from_le_bytes(entry[..4].try_into().expect("unwind state")),
                u32::from_le_bytes(entry[4..].try_into().expect("cleanup RVA")),
            )
        })
        .collect();
    let map = image.base() + fields[6] as u64;
    let states: Vec<_> = image
        .data(map, fields[5] as usize * 8)?
        .as_chunks::<8>()
        .0
        .iter()
        .map(|entry| {
            (
                image.base()
                    + u32::from_le_bytes(entry[..4].try_into().expect("instruction RVA")) as u64,
                i32::from_le_bytes(entry[4..].try_into().expect("instruction state")),
            )
        })
        .collect();
    let mut used = BTreeSet::new();
    for (index, &(address, mut state)) in states.iter().enumerate() {
        let end = states.get(index + 1).map_or(function.end, |entry| entry.0);
        if address >= removed.start && end <= removed.end {
            continue;
        }
        while state >= 0 && used.insert(state) {
            state = actions.get(state as usize).ok_or("清理状态超出范围")?.0;
        }
    }
    let sections = image.sections()?;
    let (_, data) = sections
        .iter()
        .find(|(address, data)| *address <= info && info < *address + data.len() as u64)
        .ok_or("找不到异常处理数据节")?;
    let (state, action) = actions
        .iter()
        .enumerate()
        .find(|(state, action)| {
            !used.contains(&(*state as i32))
                && action.1 != 0
                && memchr::memmem::find_iter(data, &action.1.to_le_bytes()).count() == 1
        })
        .ok_or("找不到独立的摘要清理函数")?;
    let cleanup = image
        .function(image.base() + action.1 as u64)?
        .ok_or("找不到摘要清理函数范围")?;
    progress.check()?;
    if references.get(cleanup.start).is_some() {
        return Err("摘要清理函数还有其他调用".into());
    }
    let mut parent = state as i32;
    while parent >= 0 && !used.contains(&parent) {
        parent = actions.get(parent as usize).ok_or("清理状态超出范围")?.0;
    }
    let address = states
        .iter()
        .find(|entry| removed.contains(&entry.0) && entry.1 == parent)
        .ok_or("找不到摘要对象的有效清理状态")?
        .0;
    let mut edits = Vec::new();
    for (index, &(address, state)) in states.iter().enumerate() {
        if !removed.contains(&address) || state < 0 || used.contains(&state) {
            continue;
        }
        let mut parent = state;
        while parent >= 0 && !used.contains(&parent) {
            parent = actions.get(parent as usize).ok_or("清理状态超出范围")?.0;
        }
        let offset = image.offset(map + (index * 8 + 4) as u64)?;
        edits.push(Edit {
            range: offset..offset + 4,
            bytes: parent.to_le_bytes().to_vec(),
        });
    }
    Ok((edits, cleanup, address))
}

struct Comparison {
    argument: usize,
    load: usize,
    compare: usize,
    equal: usize,
    order: usize,
}

fn comparisons(instructions: &[Instruction]) -> Vec<Comparison> {
    let mut found = Vec::new();
    for (index, instruction) in instructions.iter().enumerate().skip(1) {
        if !matches!(instruction.code(), Code::Je_rel8_64 | Code::Je_rel32_64) {
            continue;
        }
        let compare = &instructions[index - 1];
        if compare.code() != Code::Cmp_r64_rm64
            || compare.op0_register() != Register::RAX
            || compare.op1_kind() != OpKind::Memory
        {
            continue;
        }
        let tail: Vec<_> = instructions
            .iter()
            .enumerate()
            .skip(index + 1)
            .filter(|(_, instruction)| instruction.mnemonic() != Mnemonic::Nop)
            .take(5)
            .collect();
        let [
            (argument, receiver),
            (_, call),
            (_, load),
            (_, second),
            (order, branch),
        ] = tail.as_slice()
        else {
            continue;
        };
        if receiver.mnemonic() != Mnemonic::Mov
            || receiver.op0_register() != Register::RCX
            || receiver.op1_kind() != OpKind::Register
            || call.code() != Code::Call_rel32_64
            || load.code() != Code::Mov_r64_rm64
            || load.op0_register() != Register::RAX
            || load.memory_base() != Register::RAX
            || load.memory_displacement64() != compare.memory_displacement64()
            || second.code() != compare.code()
            || second.op0_register() != compare.op0_register()
            || second.memory_base() != compare.memory_base()
            || second.memory_displacement64() != compare.memory_displacement64()
            || !matches!(
                branch.code(),
                Code::Jbe_rel8_64 | Code::Jbe_rel32_64 | Code::Ja_rel8_64 | Code::Ja_rel32_64
            )
        {
            continue;
        }
        let getter = call.near_branch_target();
        let Some(first) = instructions[..index - 1].iter().rposition(|instruction| {
            instruction.code() == Code::Call_rel32_64 && instruction.near_branch_target() == getter
        }) else {
            continue;
        };
        let Some(load) =
            (first + 1..index - 1).find(|&i| instructions[i].mnemonic() != Mnemonic::Nop)
        else {
            continue;
        };
        if first == 0
            || instructions[first - 1].op0_register() != Register::RCX
            || instructions[first - 1].op1_register() != receiver.op1_register()
            || instructions[load].code() != Code::Mov_r64_rm64
            || instructions[load].memory_base() != Register::RAX
            || instructions[load].memory_displacement64() != compare.memory_displacement64()
            || *argument <= index
        {
            continue;
        }
        found.push(Comparison {
            argument: first - 1,
            load,
            compare: index - 1,
            equal: index,
            order: *order,
        });
    }
    found
}

fn view<'a>(
    image: &Image<'_>,
    instructions: &[Instruction],
    types: impl Iterator<Item = &'a Range<u64>>,
    step: &Step,
) -> Result<Vec<Edit>> {
    let comparisons = comparisons(instructions);
    if comparisons.is_empty() {
        return Err("找不到撤回提示的排序比较".into());
    }
    let incoming = instructions[comparisons[0].compare].memory_base();
    let local = unique(
        instructions
            .windows(2)
            .filter(|window| {
                window[0].code() == Code::Mov_r32_rm32
                    && window[0].memory_base() == Register::RAX
                    && window[1].code() == Code::Cmp_r32_rm32
                    && window[1].memory_base() == incoming
                    && window[0].op0_register() == window[1].op0_register()
                    && window[0].memory_displacement64() == window[1].memory_displacement64()
            })
            .map(|window| window[0].memory_displacement64() as i64)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        "界面消息本地编号",
    )?;
    let first_call = calls(instructions)
        .next()
        .ok_or("消息视图函数缺少调用")?
        .ip();
    let receiver = unique(
        instructions
            .iter()
            .filter(|instruction| {
                instruction.ip() < first_call
                    && instruction.mnemonic() == Mnemonic::Mov
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.op1_register() == Register::RCX
            })
            .map(Instruction::op0_register)
            .collect(),
        "消息视图对象寄存器",
    )?;
    let cast = calls(&instructions[..comparisons[0].argument])
        .next_back()
        .ok_or("找不到视图项类型转换")?
        .near_branch_target();
    let mut accessors = BTreeSet::new();
    for function in types {
        let code = image.instructions(function)?;
        let filters: Vec<_> = code
            .iter()
            .filter(|instruction| instruction.code() == Code::Bt_rm64_r64)
            .collect();
        let [first, last] = filters.as_slice() else {
            continue;
        };
        if calls(&code).any(|call| call.near_branch_target() == cast)
            && first.op0_register() == last.op0_register()
            && first.op1_register() == last.op1_register()
        {
            accessors.insert(function.start);
        }
    }
    let accessor = unique(accessors.into_iter().collect(), "图片组消息访问函数")?;
    step.record(format!(
        "视图访问：call 0x{:08X} → call 0x{:08X}",
        cast - image.base(),
        accessor - image.base(),
    ));
    let mut edits = Vec::new();
    for comparison in comparisons {
        edits.push(view_item(
            image,
            instructions,
            &comparison,
            receiver,
            accessor,
        )?);
        let mut assembler = CodeAssembler::new(64)?;
        let mut ordered = assembler.create_label();
        for instruction in &instructions[comparison.argument..comparison.load] {
            assembler.add_instruction(*instruction)?;
        }
        let mut load = instructions[comparison.load];
        load.set_op0_register(Register::RDX);
        assembler.add_instruction(load)?;
        for instruction in &instructions[comparison.load + 1..comparison.compare] {
            assembler.add_instruction(*instruction)?;
        }
        let mut compare = instructions[comparison.compare];
        compare.set_op0_register(Register::RDX);
        assembler.add_instruction(compare)?;
        assembler.jne(ordered)?;
        assembler.mov(edx, dword_ptr(rax + local))?;
        assembler.cmp(edx, dword_ptr(register(incoming)? + local))?;
        assembler.je(instructions[comparison.equal].near_branch_target())?;
        assembler.set_label(&mut ordered)?;
        assembler.add_instruction(instructions[comparison.order])?;
        edits.push(patch(
            image,
            instructions[comparison.argument].ip()..instructions[comparison.order].next_ip(),
            &mut assembler,
        )?);
    }
    Ok(edits)
}

fn view_item(
    image: &Image<'_>,
    instructions: &[Instruction],
    comparison: &Comparison,
    receiver: Register,
    accessor: u64,
) -> Result<Edit> {
    let cast = instructions[..comparison.argument]
        .iter()
        .rposition(|instruction| instruction.code() == Code::Call_rel32_64)
        .ok_or("找不到视图项类型转换")?;
    let start = instructions[..cast]
        .iter()
        .rposition(|instruction| {
            instruction.code() == Code::Mov_r64_rm64
                && instruction.op0_register() == Register::RCX
                && instruction.op1_kind() == OpKind::Memory
        })
        .ok_or("找不到待比较的视图项")?;
    let object = instructions[..start]
        .iter()
        .rev()
        .find(|instruction| {
            instruction.mnemonic() == Mnemonic::Movaps && instruction.op0_kind() == OpKind::Memory
        })
        .ok_or("找不到消息视图的共享对象")?;
    let object = Slot::from(object)?;
    let end = instructions[cast + 1..comparison.argument]
        .iter()
        .find(|instruction| {
            instruction.mnemonic() == Mnemonic::Movaps
                && instruction.op0_kind() == OpKind::Memory
                && Slot::from(instruction).is_ok_and(|slot| slot != object)
        })
        .ok_or("找不到消息视图的引用复制")?
        .ip();
    let absent = instructions[cast + 1..comparison.argument]
        .iter()
        .find(|instruction| matches!(instruction.code(), Code::Je_rel8_64 | Code::Je_rel32_64))
        .ok_or("找不到空视图项分支")?
        .near_branch_target();
    let result = register(instructions[comparison.argument].op1_register())?;
    let mut pair = instructions[start];
    pair.set_code(Code::Lea_r64_m);
    pair.set_op0_register(Register::R8);
    let mut assembler = CodeAssembler::new(64)?;
    assembler.lea(rdx, object.memory()?)?;
    assembler.add_instruction(pair)?;
    assembler.mov(rcx, register(receiver)?)?;
    assembler.xor(r9d, r9d)?;
    assembler.call(accessor)?;
    assembler.mov(result, qword_ptr(object.memory()?))?;
    assembler.mov(rax, qword_ptr(object.add(8).memory()?))?;
    assembler.test(result, result)?;
    assembler.je(absent)?;
    patch(image, instructions[start].ip()..end, &mut assembler)
}
