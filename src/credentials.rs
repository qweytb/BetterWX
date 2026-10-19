use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use iced_x86::{
    Code, Mnemonic, OpKind, Register,
    code_asm::{
        CodeAssembler, byte_ptr, dword_ptr, eax, ptr, qword_ptr, r8d, rax, rbx, rcx, rdx, rsp,
    },
};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, functions},
    login,
    progress::Progress,
    xlog,
};

const CLEAR: &str = "kernel::KernelPrivate::ClearAutoLoginInfo";
const GET: &str = "kernel::KernelPrivate::GetAutoLoginInfo";
const REQUEST: &str = "kernel::manager::LoginManager::PushLoginURL";
const INIT: &str = "mmui::LoginViewModel::Init()::(lambda)::operator()";
const CANCEL: &str = "mmui::LoginViewModel::OnCancelButtonClick";
const BACK: &str = "mmui::LoginViewModel::OnBackButtonClick";
const MENU: &str = "mmui::LoginViewModel::OnMenuLoginButtonClick";
const AUTO: &str = "OnAutoLoginButtonClick";
const DELAY: &str = "mmui::LoginViewModel::DelayCheckQrCode";
const FILE: &str = "login_service.cc";
const FUNCTIONS: &[&str] = &[CLEAR, GET, REQUEST, INIT, CANCEL, BACK, MENU, AUTO, DELAY];
const SERVER_BUSY: i32 = -446;

pub const FEATURE: Feature = Feature {
    id: "keep-login",
    name: "保留登录信息",
    description: "登录失败时不要清理登录信息，除非登录信息真的失效",
    targets: &[Target {
        file: None,
        find,
        scan,
    }],
};

struct Scan {
    symbols: Symbols,
    emitted: bool,
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let mut names = FUNCTIONS.to_vec();
    names.push(FILE);
    xlog::find(image, &names, progress)
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan {
        symbols,
        emitted: false,
    })
}

impl Analysis for Scan {
    fn visit(
        &mut self,
        image: &Image<'_>,
        _function: &Range<u64>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Edit>> {
        let mut found = BTreeMap::new();
        for &name in FUNCTIONS {
            let matches = functions(name, &self.symbols, references);
            if matches.len() > 1 {
                return Err(format!("无法唯一定位{name}").into());
            }
            if let Some(function) = matches.into_values().next() {
                found.insert(name, function);
            }
        }
        if found.len() != FUNCTIONS.len() {
            return Ok(Vec::new());
        }
        let sources = functions(FILE, &self.symbols, references);
        let callers: Vec<_> = references
            .get(found[CLEAR].start)
            .into_iter()
            .flatten()
            .filter(|function| sources.contains_key(&function.start))
            .collect();
        if callers.len() > 1 {
            return Err("无法唯一定位登录信息清理请求".into());
        }
        let Some(function) = callers.first() else {
            return Ok(Vec::new());
        };
        if self.emitted {
            return Ok(Vec::new());
        }
        let edits = prepare(image, &found, function, progress)?;
        self.emitted = true;
        Ok(edits)
    }

    fn finish(
        self: Box<Self>,
        _image: &Image<'_>,
        _references: &References,
        _progress: &Progress,
    ) -> Result<Vec<Mode>> {
        if !self.emitted {
            return Err("找不到登录信息恢复流程".into());
        }
        Ok(vec![Mode::enabled(Vec::new())])
    }
}

fn prepare(
    image: &Image<'_>,
    found: &BTreeMap<&str, Range<u64>>,
    worker: &Range<u64>,
    progress: &Progress,
) -> Result<Vec<Edit>> {
    let step = progress.activity("定位登录信息");
    let instructions = image.instructions(worker)?;
    let calls: Vec<_> = instructions
        .windows(3)
        .filter(|part| {
            part[0].code() == Code::Call_rel32_64
                && matches!(part[1].code(), Code::Mov_r64_rm64 | Code::Mov_rm64_r64)
                && part[1].op0_register() == Register::RCX
                && part[1].op1_kind() == OpKind::Register
                && part[1].op1_register() == Register::RAX
                && part[2].code() == Code::Call_rel32_64
                && part[2].near_branch_target() == found[CLEAR].start
        })
        .collect();
    let [calls] = calls[..] else {
        return Err("无法定位登录信息清理调用".into());
    };
    let root = calls[0].near_branch_target();
    let mut callbacks = BTreeMap::new();
    for instruction in image.instructions(&found[AUTO])? {
        if instruction.code() != Code::Lea_r64_m || !instruction.is_ip_rel_memory_operand() {
            continue;
        }
        let Ok(bytes) = image.data(instruction.ip_rel_memory_address() + 16, 8) else {
            continue;
        };
        let address = u64::from_le_bytes(bytes.try_into()?);
        let Some(function) = image.function(address)? else {
            continue;
        };
        if function.start != address {
            continue;
        }
        let body = image.instructions(&function)?;
        if [CANCEL, DELAY].iter().all(|name| {
            body.iter().any(|instruction| {
                instruction.code() == Code::Call_rel32_64
                    && instruction.near_branch_target() == found[name].start
            })
        }) {
            callbacks.insert(address, (function, body));
        }
    }
    let callbacks: Vec<_> = callbacks.into_values().collect();
    let [(callback, body)] = &callbacks[..] else {
        return Err("无法定位登录请求的响应回调".into());
    };
    let captures: BTreeSet<_> = body
        .iter()
        .filter(|instruction| {
            instruction.code() == Code::Mov_r64_rm64
                && instruction.op0_register() == Register::RCX
                && instruction.op1_kind() == OpKind::Memory
                && !matches!(
                    instruction.memory_base(),
                    Register::RSP | Register::RBP | Register::RIP
                )
                && instruction.memory_index() == Register::None
        })
        .map(|instruction| instruction.memory_displacement64())
        .collect();
    let [capture] = captures.into_iter().collect::<Vec<_>>()[..] else {
        return Err("无法定位登录回调的界面对象".into());
    };
    let initialized = image.instructions(&found[INIT])?;
    let drops: Vec<_> = initialized
        .windows(3)
        .filter(|part| {
            part[0].code() == Code::Lea_r64_m
                && part[0].op0_register() == Register::RCX
                && part[0].memory_index() == Register::None
                && part[1].code() == Code::Call_rel32_64
                && part[2].code() == Code::Mov_rm8_imm8
                && part[2].immediate8() == 0
                && part[2].memory_base() == part[0].memory_base()
                && part[2].memory_displacement64() > part[0].memory_displacement64()
        })
        .collect();
    let [drop] = drops[..] else {
        return Err("无法定位账号信息对象".into());
    };
    let register = drop[0].memory_base();
    let cached = i32::try_from(drop[2].memory_displacement64())?;
    let present = i32::try_from(drop[2].memory_displacement64() - drop[0].memory_displacement64())?;
    let states: Vec<_> = initialized
        .windows(2)
        .filter(|part| {
            part[0].code() == Code::Mov_rm64_imm32
                && part[1].code() == Code::Mov_rm32_imm32
                && part.iter().all(|instruction| {
                    instruction.memory_base() == register
                        && instruction.memory_index() == Register::None
                })
                && part[1].memory_displacement64() == part[0].memory_displacement64() + 8
        })
        .collect();
    let [state] = states[..] else {
        return Err("无法定位账号登录状态".into());
    };
    let receivers: Vec<_> = initialized
        .windows(2)
        .filter(|part| part[0].op1_register() == register)
        .map(|part| part[1].ip())
        .collect();
    let initialized = login::calls(&initialized);
    let menu = login::calls(&image.instructions(&found[MENU])?);
    let targets: Vec<_> = initialized
        .iter()
        .filter(|(target, sites)| {
            menu.contains_key(target) && sites.iter().any(|site| receivers.contains(site))
        })
        .map(|(target, _)| *target)
        .collect();
    let [notify] = targets[..] else {
        return Err("无法定位登录界面刷新".into());
    };
    let request = image.instructions(&found[REQUEST])?;
    let comparisons: Vec<_> = request
        .iter()
        .enumerate()
        .filter(|(_, instruction)| {
            instruction.code() == Code::Cmp_EAX_imm32 && instruction.immediate32() as i32 == -2017
        })
        .collect();
    let [(index, comparison)] = comparisons[..] else {
        return Err("无法定位登录信息失效判定".into());
    };
    let branch = request
        .get(index + 1)
        .filter(|instruction| instruction.mnemonic() == Mnemonic::Jne)
        .ok_or("无法定位登录信息清理分支")?;
    let result = request[..index]
        .iter()
        .rfind(|instruction| {
            instruction.code() == Code::Mov_r32_rm32
                && instruction.op0_register() == Register::EAX
                && instruction.op1_kind() == OpKind::Memory
                && !instruction.is_ip_rel_memory_operand()
                && instruction.memory_displacement64() == 4
        })
        .ok_or("无法定位登录请求错误码")?;
    let continuation = request
        .iter()
        .find(|instruction| {
            instruction.ip() > result.ip()
                && instruction.ip() < comparison.ip()
                && instruction.mnemonic() == Mnemonic::Je
                && instruction.near_branch_target() > instruction.ip()
                && instruction.near_branch_target() <= comparison.ip()
        })
        .ok_or("无法定位登录结果判定范围")?
        .near_branch_target();
    step.finish(format!(
        "{GET}；RVA 0x{:08X}\n登录响应回调；RVA 0x{:08X}\n{REQUEST}；RVA 0x{:08X}",
        found[GET].start - image.base(),
        callback.start - image.base(),
        found[REQUEST].start - image.base(),
    ));

    let step = progress.activity("准备登录信息补丁");
    let mut code = CodeAssembler::new(64)?;
    code.add_instruction(*result)?;
    code.cmp(eax, SERVER_BUSY)?;
    code.je(branch.near_branch_target())?;
    let mut kind = *result;
    kind.set_ip(0);
    kind.set_memory_displacement64(0);
    code.add_instruction(kind)?;
    code.jmp(comparison.ip())?;
    let bytes = code.assemble(result.ip())?;
    if result.ip() + bytes.len() as u64 > continuation {
        return Err("登录结果判定的指令空间不足".into());
    }
    let offset = image.offset(result.ip())?;
    let mut edits = vec![Edit {
        range: offset..offset + bytes.len(),
        bytes,
    }];
    let mut comparison = *comparison;
    comparison.set_immediate32(0);
    let mut code = CodeAssembler::new(64)?;
    code.add_instruction(comparison)?;
    let bytes = code.assemble(comparison.ip())?;
    let offset = image.offset(comparison.ip())?;
    edits.push(Edit {
        range: offset..offset + bytes.len(),
        bytes,
    });
    step.record(format!(
        "RVA 0x{:08X}；读取错误码和错误类型 → 原清理分支",
        result.ip() - image.base(),
    ));

    let mut code = CodeAssembler::new(64)?;
    let mut back = code.create_label();
    let mut success = code.create_label();
    let frame = 32 + (present as u32 + 1).next_multiple_of(16);
    code.push(rbx)?;
    code.sub(rsp, i32::try_from(frame)?)?;
    let prologue = u8::try_from(code.assemble(callback.start)?.len())?;
    code.mov(rbx, qword_ptr(rcx + i32::try_from(capture)?))?;
    code.test(byte_ptr(rdx), 1)?;
    code.jnz(success)?;
    code.cmp(byte_ptr(rbx + cached), 1)?;
    code.jne(back)?;
    code.call(root)?;
    code.mov(rcx, rax)?;
    code.lea(rdx, ptr(rsp + 32))?;
    code.xor(r8d, r8d)?;
    code.call(found[GET].start)?;
    code.cmp(byte_ptr(rsp + 32 + present), 1)?;
    code.jne(back)?;
    code.lea(rcx, ptr(rsp + 32))?;
    code.call(drop[1].near_branch_target())?;
    code.mov(
        qword_ptr(rbx + i32::try_from(state[0].memory_displacement64())?),
        state[0].immediate32() as i32,
    )?;
    code.mov(
        dword_ptr(rbx + i32::try_from(state[1].memory_displacement64())?),
        state[1].immediate32() as i32,
    )?;
    code.mov(rcx, rbx)?;
    code.add(rsp, i32::try_from(frame)?)?;
    code.pop(rbx)?;
    code.jmp(notify)?;
    code.set_label(&mut back)?;
    code.mov(rcx, rbx)?;
    code.add(rsp, i32::try_from(frame)?)?;
    code.pop(rbx)?;
    code.jmp(found[BACK].start)?;
    code.set_label(&mut success)?;
    code.mov(rcx, rbx)?;
    code.add(rsp, i32::try_from(frame)?)?;
    code.pop(rbx)?;
    code.jmp(found[DELAY].start)?;
    let allocation = u16::try_from(frame / 8)?.to_le_bytes();
    let unwind = [
        1,
        prologue,
        3,
        0,
        prologue,
        1,
        allocation[0],
        allocation[1],
        1,
        0x30,
        0,
        0,
    ];
    edits.extend(image.replace_function(callback, &mut code, &unwind)?);
    step.finish(format!(
        "登录响应回调；RVA 0x{:08X}；读取账号信息 → 恢复登录状态",
        callback.start - image.base(),
    ));
    Ok(edits)
}
