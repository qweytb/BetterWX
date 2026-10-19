use std::{collections::BTreeMap, ops::Range};

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Instruction, MemoryOperand, Mnemonic, OpKind, Register,
    code_asm::CodeAssembler,
};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, functions},
    progress::Progress,
    xlog,
};

const IMAGE: &str = "kernel::manager::ImageMessageHandler::HandlePredownloadOnAddMessage";
const VIDEO: &str = "virtual kernel::manager::VideoMessageHandler::CoHandleReceiveAddMessage";
const DOWNLOAD: &str = "kernel::manager::MessageManager::DownloadMessageResource";
const ALL: &str = "kernel::manager::MessageManager::DownloadMessageAllResource";
const SAVE: &str =
    "virtual kernel::manager::MessagePreloadCallback::NotifyRestorePreloadTasksBeforeLogout";
const LOAD: &str =
    "kernel::manager::PreDownloadManager::LoadLocalPreloadTasks()::(lambda)::operator()";
const RESUME: &str = "virtual kernel::manager::MessageResourceDownloadTask::CoResume";
const NOTIFY: &str =
    "kernel::manager::MessageResourceDownloadTask::NotifyUpdateMessageTransferStatus";
const TRANSFERS: &[&str] = &[
    "virtual kernel::manager::MessageImageResourceDownloadTask::ResumeDownloadTask",
    "virtual kernel::manager::MessageVideoResourceDownloadTask::ResumeDownloadTask",
    "virtual kernel::manager::MessageFileResourceDownloadTask::ResumeDownloadTask",
];

pub const FEATURE: Feature = Feature {
    id: "resources",
    name: "防止文件过期",
    description: "更积极地自动下载和保留各类资源",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

struct Scan {
    symbols: Symbols,
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let mut names = vec![IMAGE, VIDEO, DOWNLOAD, ALL, SAVE, LOAD, RESUME, NOTIFY];
    names.extend_from_slice(TRANSFERS);
    xlog::find(image, &names, progress)
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan { symbols })
}

fn unique<T>(values: Vec<T>, description: &str) -> Result<T> {
    let [value]: [T; 1] = values
        .try_into()
        .map_err(|_| format!("无法唯一定位{description}"))?;
    Ok(value)
}

fn calls(body: &[Instruction], target: u64) -> Vec<usize> {
    body.iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (instruction.code() == Code::Call_rel32_64
                && instruction.near_branch_target() == target)
                .then_some(index)
        })
        .collect()
}

fn getters(image: &Image<'_>, body: &[Instruction]) -> Result<Vec<usize>> {
    let mut found = Vec::new();
    for (index, instruction) in body.iter().enumerate() {
        if instruction.code() != Code::Call_rel32_64 {
            continue;
        }
        let target = instruction.near_branch_target();
        let bytes = image.data(target, 8)?;
        let mut decoder = Decoder::with_ip(64, bytes, target, DecoderOptions::NONE);
        let value = decoder.decode();
        if value.code() == Code::Mov_r32_rm32
            && value.op0_register() == Register::EAX
            && value.op1_kind() == OpKind::Memory
            && value.memory_base() == Register::RCX
            && value.memory_index() == Register::None
            && decoder.decode().code() == Code::Retnq
        {
            found.push(index);
        }
    }
    Ok(found)
}

fn patch(image: &Image<'_>, range: Range<u64>, bytes: &[u8]) -> Result<Edit> {
    let size = usize::try_from(range.end - range.start)?;
    if bytes.len() > size {
        return Err("原指令空间不足".into());
    }
    image.data(range.start, size)?;
    let offset = image.offset(range.start)?;
    let mut bytes = bytes.to_vec();
    bytes.resize(size, 0x90);
    Ok(Edit {
        range: offset..offset + size,
        bytes,
    })
}

fn replace(image: &Image<'_>, original: &Instruction, instruction: Instruction) -> Result<Edit> {
    let mut encoder = Encoder::new(64);
    encoder.encode(&instruction, original.ip())?;
    patch(
        image,
        original.ip()..original.next_ip(),
        &encoder.take_buffer(),
    )
}

fn redirect(image: &Image<'_>, call: &Instruction, target: u64) -> Result<Edit> {
    replace(
        image,
        call,
        Instruction::with_branch(Code::Call_rel32_64, target)?,
    )
}

fn assign(original: &mut Instruction, mut instruction: Instruction) {
    instruction.set_ip(original.ip());
    *original = instruction;
}

fn insert(
    image: &Image<'_>,
    body: &mut Vec<Instruction>,
    index: usize,
    mut instructions: Vec<Instruction>,
) {
    let address = image.end();
    for (offset, instruction) in instructions.iter_mut().enumerate() {
        instruction.set_ip(address + offset as u64);
    }
    body.splice(index..index, instructions);
}

fn reencode(
    image: &Image<'_>,
    function: &Range<u64>,
    body: &mut [Instruction],
) -> Result<Vec<Edit>> {
    let header = image.data(image.unwind_info(function.start)?, 4)?;
    let prologue = function.start + u64::from(header[1]);
    for instruction in body.iter_mut() {
        if instruction.ip() >= prologue && instruction.mnemonic() == Mnemonic::Nop {
            assign(instruction, Instruction::with(Code::Zero_bytes));
        }
    }
    image.reencode(function, body)
}

fn receive(image: &Image<'_>, body: &[Instruction], download: u64, all: u64) -> Result<Vec<Edit>> {
    let downloads = calls(body, download);
    let first = *downloads.first().ok_or("找不到收件资源下载调用")?;
    let fields = getters(image, &body[..first])?;
    let expected = if downloads.len() == 2 { 4 } else { 2 };
    if fields.len() != expected {
        return Err("无法识别收件预下载条件".into());
    }
    let start = (1..fields[0])
        .rev()
        .find(|&index| {
            body[index].mnemonic() == Mnemonic::Je && body[index - 1].mnemonic() == Mnemonic::Test
        })
        .ok_or("找不到收件预下载的消息来源检查")?
        - 1;
    let last = *fields.last().expect("fields");
    let next = body[last + 1..]
        .iter()
        .position(|instruction| instruction.code() == Code::Call_rel32_64)
        .map(|index| last + 1 + index)
        .ok_or("找不到收件下载的管理器入口")?;
    let end = (last + 1..next)
        .rev()
        .find(|&index| matches!(body[index].mnemonic(), Mnemonic::Jne | Mnemonic::Jle))
        .ok_or("找不到收件预下载的条件分支")?;
    let priority = body[end + 1..first]
        .iter()
        .rev()
        .find(|instruction| {
            instruction.code() == Code::Mov_rm32_r32
                && instruction.op0_kind() == OpKind::Memory
                && instruction.memory_base() == Register::RSP
                && instruction.memory_displacement64() == 32
        })
        .ok_or("找不到收件下载的优先级参数")?
        .op1_register();
    let mut code = CodeAssembler::new(64)?;
    code.add_instruction(Instruction::with2(Code::Mov_r32_imm32, priority, 300u32)?)?;
    if downloads.len() == 2 {
        let value = body[last + 1..end]
            .iter()
            .find(|instruction| instruction.mnemonic() != Mnemonic::Nop)
            .ok_or("找不到原图预下载条件")?;
        if value.mnemonic() != Mnemonic::Mov || value.op1_register() != Register::EAX {
            return Err("无法识别原图预下载条件".into());
        }
        let register = value.op0_register();
        code.add_instruction(Instruction::with2(Code::Xor_r32_rm32, register, register)?)?;
    }
    let resource = &body[first - 1];
    if resource.code() != Code::Mov_r32_imm32 || resource.op0_register() != Register::R9D {
        return Err("无法识别收件下载的资源类型参数".into());
    }
    Ok(vec![
        patch(
            image,
            body[start].ip()..body[end].next_ip(),
            &code.assemble(body[start].ip())?,
        )?,
        replace(
            image,
            resource,
            Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 0u32)?,
        )?,
        redirect(image, &body[first], all)?,
    ])
}

fn download_all(
    image: &Image<'_>,
    function: &Range<u64>,
    download: u64,
    coroutine: u64,
) -> Result<Vec<Edit>> {
    let mut body = image.instructions(function)?;
    let call = unique(calls(&body, download), "完整资源下载调用")?;
    let await_call = (call + 1..body.len())
        .find(|&index| body[index].code() == Code::Call_rel32_64)
        .ok_or("找不到资源下载结果读取")?;
    let arguments = body[call + 1..await_call]
        .iter()
        .enumerate()
        .filter(|(_, instruction)| instruction.mnemonic() != Mnemonic::Nop)
        .map(|(index, instruction)| (call + 1 + index, *instruction))
        .collect::<Vec<_>>();
    let [(receiver, _), (result, output), (future, input)] = arguments[..] else {
        return Err("无法识别资源下载结果参数".into());
    };
    if output.mnemonic() != Mnemonic::Mov
        || output.op0_register() != Register::RDX
        || output.op1_kind() != OpKind::Register
        || input.mnemonic() != Mnemonic::Mov
        || input.op0_register() != Register::R8
        || input.op1_kind() != OpKind::Register
    {
        return Err("无法识别资源下载结果存储".into());
    }
    let destination = (0..call)
        .rev()
        .find(|&index| body[index].op0_register() == Register::RDX)
        .ok_or("找不到资源下载输出参数")?;
    if body[destination].mnemonic() != Mnemonic::Mov {
        return Err("无法识别资源下载输出参数".into());
    }
    body[destination].set_op1_register(output.op1_register());
    body[call].set_near_branch64(coroutine);
    assign(
        &mut body[receiver],
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)?,
    );
    for (index, displacement) in [(result, 0), (future, 8)] {
        assign(
            &mut body[index],
            Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_displ(input.op1_register(), displacement),
                Register::RAX,
            )?,
        );
    }
    assign(&mut body[await_call], Instruction::with(Code::Zero_bytes));
    let check = unique(
        body.windows(3)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].code() == Code::Mov_r32_rm32
                    && window[0].op1_kind() == OpKind::Memory
                    && window[0].memory_displacement64() == 4
                    && window[1].code() == Code::Or_r32_rm32
                    && window[1].memory_base() == window[0].memory_base()
                    && window[1].memory_displacement64() == 0
                    && window[2].mnemonic() == Mnemonic::Jne)
                    .then_some(index)
            })
            .collect(),
        "完整资源下载的完成条件",
    )?;
    let failure = body[check + 2].near_branch_target();
    let next = body[check + 2].next_ip();
    let pointer = body[check + 1].memory_base();
    body[check + 2].set_code(Code::Je_rel32_64);
    body[check + 2].set_near_branch64(next);
    // The native coroutine reports queued work as (5500, 9).
    insert(
        image,
        &mut body,
        check + 3,
        vec![
            Instruction::with2(
                Code::Cmp_rm32_imm32,
                MemoryOperand::with_base(pointer),
                5500u32,
            )?,
            Instruction::with_branch(Code::Jne_rel32_64, failure)?,
            Instruction::with2(
                Code::Cmp_rm32_imm8,
                MemoryOperand::with_base_displ(pointer, 4),
                9u32,
            )?,
            Instruction::with_branch(Code::Jne_rel32_64, failure)?,
        ],
    );
    reencode(image, function, &mut body)
}

fn save(image: &Image<'_>, function: &Range<u64>) -> Result<Vec<Edit>> {
    let body = image.instructions(function)?;
    let query = unique(
        body.windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].code() == Code::Mov_r32_imm32
                    && window[0].op0_register() == Register::R8D
                    && window[0].immediate32() == 400
                    && window[1].code() == Code::Call_rel32_64)
                    .then_some(index)
            })
            .collect(),
        "待下载任务查询",
    )?;
    let mut edits = vec![replace(
        image,
        &body[query],
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 0u32)?,
    )?];
    let size = unique(
        body.windows(2)
            .filter_map(|window| {
                (window[0].code() == Code::Cmp_rm32_imm8
                    && window[0].op0_kind() == OpKind::Memory
                    && window[0].memory_base() != Register::RBP
                    && window[0].memory_base() != Register::RSP
                    && window[0].immediate8() == 0
                    && window[1].mnemonic() == Mnemonic::Jle
                    && window[1].near_branch_target() < window[0].ip())
                .then_some(window[1])
            })
            .collect(),
        "待下载任务大小条件",
    )?;
    edits.push(patch(image, size.ip()..size.next_ip(), &[])?);
    let field = unique(getters(image, &body)?, "消息预下载优先级读取")?;
    let check = body[field + 1..]
        .iter()
        .find(|instruction| {
            instruction.op0_kind() == OpKind::NearBranch64
                && !matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
        })
        .ok_or("找不到消息预下载优先级条件")?;
    if check.mnemonic() != Mnemonic::Jle {
        return Err("无法识别消息预下载优先级条件".into());
    }
    edits.push(patch(image, check.ip()..check.next_ip(), &[])?);
    let target = body[query + 1].near_branch_target();
    let function = image.function(target)?.ok_or("找不到任务查询函数")?;
    let mut body = image.instructions(&function)?;
    let condition = unique(
        body.windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].code() == Code::Cmp_rm32_r32
                    && window[0].op0_kind() == OpKind::Memory
                    && window[0].memory_displacement64() == 0x1c0
                    && window[1].mnemonic() == Mnemonic::Jne)
                    .then_some(index)
            })
            .collect(),
        "任务查询的优先级条件",
    )?;
    let priority = body[condition].op1_register();
    let include = body[condition + 1].next_ip();
    let compare = body[condition];
    assign(
        &mut body[condition],
        Instruction::with2(Code::Test_rm32_r32, priority, priority)?,
    );
    insert(
        image,
        &mut body,
        condition + 1,
        vec![
            Instruction::with_branch(Code::Je_rel32_64, include)?,
            compare,
        ],
    );
    edits.extend(reencode(image, &function, &mut body)?);
    Ok(edits)
}

fn local(image: &Image<'_>, function: &Range<u64>) -> Result<Vec<Edit>> {
    let body = image.instructions(function)?;
    let check = unique(
        body.windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].code() == Code::Cmp_rm32_imm32
                    && window[0].op0_kind() == OpKind::Register
                    && window[0].immediate32() == 400
                    && window[1].mnemonic() == Mnemonic::Jne)
                    .then_some(index)
            })
            .collect(),
        "后台下载的本地文件检查",
    )?;
    let mut compare = body[check];
    compare.set_immediate32(300);
    let mut branch = body[check + 1];
    branch.set_code(Code::Jb_rel32_64);
    let priority = unique(
        body.iter()
            .filter(|instruction| {
                instruction.code() == Code::Mov_r32_imm32
                    && instruction.op0_register() == compare.op0_register()
                    && instruction.immediate32() == 400
                    && instruction.ip() > branch.ip()
                    && instruction.ip() < branch.near_branch_target()
            })
            .copied()
            .collect(),
        "后台下载优先级赋值",
    )?;
    Ok(vec![
        replace(image, &body[check], compare)?,
        replace(image, &body[check + 1], branch)?,
        patch(image, priority.ip()..priority.next_ip(), &[])?,
    ])
}

fn restore(image: &Image<'_>, found: &BTreeMap<&str, Range<u64>>) -> Result<Vec<Edit>> {
    let function = &found[RESUME];
    let mut body = image.instructions(function)?;
    let mut methods = BTreeMap::new();
    for offset in [0x68, 0x70] {
        let index = unique(
            body.iter()
                .enumerate()
                .filter_map(|(index, instruction)| {
                    (instruction.code() == Code::Call_rm64
                        && instruction.memory_base() == Register::RAX
                        && instruction.memory_displacement64() == offset)
                        .then_some(index)
                })
                .collect(),
            "下载任务虚方法调用",
        )?;
        methods.insert(offset, index);
    }
    let check = methods[&0x68];
    let transfer = methods[&0x70];
    let receiver = body[check - 2];
    let table = body[check - 3];
    let output = body[transfer - 3];
    if receiver.mnemonic() != Mnemonic::Mov
        || receiver.op0_register() != Register::RCX
        || receiver.op1_kind() != OpKind::Register
        || table.code() != Code::Mov_r64_rm64
        || table.op0_register() != Register::RAX
        || table.memory_base() != receiver.op1_register()
        || table.memory_displacement64() != 0
        || output.code() != Code::Lea_r64_m
        || body[transfer - 1].op0_register() != Register::RDX
        || body[transfer - 1].op1_register() != output.op0_register()
    {
        return Err("无法识别下载任务调用参数".into());
    }
    let task = receiver.op1_register();
    let slot = output.op0_register();
    let info = body
        .iter()
        .take_while(|instruction| instruction.mnemonic() != Mnemonic::Call)
        .find(|instruction| {
            instruction.code() == Code::Mov_r64_rm64
                && instruction.op0_register() == Register::RCX
                && instruction.memory_base() == task
        })
        .ok_or("找不到下载任务资源信息")?;
    let result = image
        .instructions(&found[ALL])?
        .iter()
        .find(|instruction| instruction.code() == Code::Call_rel32_64)
        .ok_or("找不到下载结果构造函数")?
        .near_branch_target();
    let prefix = vec![
        receiver,
        table,
        Instruction::with1(
            Code::Call_rm64,
            MemoryOperand::with_base_displ(Register::RAX, 0x78),
        )?,
        Instruction::with2(Code::Test_rm8_r8, Register::AL, Register::AL)?,
        Instruction::with_branch(Code::Je_rel32_64, table.ip())?,
        output,
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)?,
        Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base(slot),
            Register::RAX,
        )?,
        Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ(slot, 8),
            Register::RAX,
        )?,
        Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ(slot, 16),
            Register::RAX,
        )?,
        Instruction::with2(
            Code::Mov_rm64_imm32,
            MemoryOperand::with_base_displ(slot, 24),
            15i32,
        )?,
        Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ(Register::RSP, 32),
            slot,
        )?,
        receiver,
        Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RDX,
            MemoryOperand::with_base_displ(task, info.memory_displacement64() as i64),
        )?,
        Instruction::with2(Code::Mov_r32_imm32, Register::R8D, 2u32)?,
        Instruction::with2(Code::Mov_r32_imm32, Register::R9D, 1u32)?,
        Instruction::with_branch(Code::Call_rel32_64, found[NOTIFY].start)?,
        Instruction::with2(Code::Mov_r64_rm64, Register::RCX, slot)?,
        Instruction::with2(Code::Xor_r32_rm32, Register::EDX, Register::EDX)?,
        Instruction::with2(Code::Xor_r32_rm32, Register::R8D, Register::R8D)?,
        Instruction::with_branch(Code::Call_rel32_64, result)?,
        Instruction::with_branch(Code::Jmp_rel32_64, body[transfer].next_ip())?,
    ];
    insert(image, &mut body, check - 3, prefix);
    let mut edits = reencode(image, function, &mut body)?;
    for name in TRANSFERS {
        let body = image.instructions(&found[name])?;
        let call = unique(
            body.iter()
                .enumerate()
                .filter_map(|(index, instruction)| {
                    (instruction.code() == Code::Call_rm64
                        && instruction.memory_base() == Register::RAX
                        && instruction.memory_displacement64() == 0x78)
                        .then_some(index)
                })
                .collect(),
            "下载任务的本地复用调用",
        )?;
        let branch = body[call + 1..]
            .iter()
            .find(|instruction| instruction.mnemonic() == Mnemonic::Je)
            .ok_or("找不到本地复用失败分支")?;
        let mut code = CodeAssembler::new(64)?;
        code.jmp(branch.near_branch_target())?;
        edits.push(patch(
            image,
            body[call].ip()..branch.next_ip(),
            &code.assemble(body[call].ip())?,
        )?);
    }
    Ok(edits)
}

impl Analysis for Scan {
    fn visit(
        &mut self,
        _image: &Image<'_>,
        _function: &Range<u64>,
        _references: &References,
        _progress: &Progress,
    ) -> Result<Vec<Edit>> {
        Ok(Vec::new())
    }

    fn finish(
        self: Box<Self>,
        image: &Image<'_>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Mode>> {
        let found: BTreeMap<_, _> = self
            .symbols
            .keys()
            .map(|name| {
                Ok((
                    name.as_str(),
                    unique(
                        functions(name, &self.symbols, references)
                            .into_values()
                            .collect(),
                        name,
                    )?,
                ))
            })
            .collect::<Result<_>>()?;
        let step = progress.activity("准备资源补丁");
        let received = image.instructions(&found[IMAGE])?;
        let download = unique(
            received
                .windows(2)
                .filter_map(|window| {
                    (window[0].code() == Code::Mov_r32_imm32
                        && window[0].op0_register() == Register::R9D
                        && window[0].immediate32() == 2
                        && window[1].code() == Code::Call_rel32_64)
                        .then_some(window[1].near_branch_target())
                })
                .collect(),
            "收件下载协程",
        )?;
        let mut edits = receive(image, &received, download, found[ALL].start)?;
        let video = image.instructions(&found[VIDEO])?;
        let mut helpers = BTreeMap::new();
        for call in video.iter().filter(|instruction| {
            instruction.code() == Code::Call_rel32_64
                && instruction.near_branch_target() != download
        }) {
            let target = call.near_branch_target();
            if let Some(function) = image.function(target)?
                && function.start == target
            {
                let body = image.instructions(&function)?;
                if calls(&body, download).len() == 1 && getters(image, &body)?.len() == 2 {
                    helpers.insert(target, body);
                }
            }
        }
        let video = unique(helpers.into_values().collect(), "视频收件预下载函数")?;
        edits.extend(receive(image, &video, download, found[ALL].start)?);
        edits.extend(download_all(
            image,
            &found[ALL],
            found[DOWNLOAD].start,
            download,
        )?);
        edits.extend(local(image, &found[DOWNLOAD])?);
        edits.extend(save(image, &found[SAVE])?);
        let load = image.instructions(&found[LOAD])?;
        let priority = unique(
            load.iter()
                .filter(|instruction| {
                    instruction.code() == Code::Mov_rm32_imm32
                        && instruction.op0_kind() == OpKind::Memory
                        && instruction.memory_base() == Register::RSP
                        && instruction.memory_displacement64() == 32
                        && instruction.immediate32() == 400
                })
                .copied()
                .collect(),
            "下载恢复优先级",
        )?;
        let mut background = priority;
        background.set_immediate32(300);
        edits.push(replace(image, &priority, background)?);
        edits.extend(restore(image, &found)?);
        step.finish(format!("{} 处修改", edits.len()));
        Ok(vec![Mode::enabled(edits)])
    }
}
