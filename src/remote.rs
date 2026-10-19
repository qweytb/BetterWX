use std::{collections::BTreeMap, ops::Range};

use iced_x86::{Code, Instruction, MemoryOperand, Mnemonic, OpKind, Register};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, argument, calls, functions},
    progress::Progress,
    xlog,
};

const FILTER: &str = "virtual mmui::WeChatNativeEventFilter::nativeEventFilter";

pub const FEATURE: Feature = Feature {
    id: "remote",
    name: "模拟输入兼容",
    description: "修正模拟输入导致自动退出登录的问题",
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
    xlog::find(image, &[FILTER, "wechat_application.cc"], progress)
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan { symbols })
}

fn assign(original: &mut Instruction, mut instruction: Instruction) {
    instruction.set_ip(original.ip());
    *original = instruction;
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
        let filters = functions(FILTER, &self.symbols, references);
        let mut handlers = BTreeMap::new();
        for filter in filters.values() {
            for (_, target) in calls(&image.instructions(filter)?) {
                let Some(bridge) = image.function(target)? else {
                    continue;
                };
                for instruction in image.instructions(&bridge)? {
                    if !matches!(
                        instruction.code(),
                        Code::Call_rel32_64 | Code::Jmp_rel32_64 | Code::Jmp_rel8_64
                    ) {
                        continue;
                    }
                    if let Some(function) = image.function(instruction.near_branch_target())? {
                        handlers.insert(function.start, function);
                    }
                }
            }
        }
        let mut found = Vec::new();
        for function in handlers.values() {
            progress.check()?;
            let body = image.instructions(function)?;
            for (index, window) in body.windows(4).enumerate() {
                let [call, test, branch, origin] = window else {
                    unreachable!();
                };
                if call.code() != Code::Call_rm64
                    || call.op0_kind() != OpKind::Register
                    || test.code() != Code::Test_rm32_r32
                    || test.op0_register() != Register::EAX
                    || test.op1_register() != Register::EAX
                    || !matches!(branch.code(), Code::Je_rel8_64 | Code::Je_rel32_64)
                    || origin.code() != Code::Mov_r32_rm32
                    || origin.op1_kind() != OpKind::Memory
                {
                    continue;
                }
                let Ok(buffer) = argument(&body, index, Register::RCX) else {
                    continue;
                };
                if buffer.code() == Code::Lea_r64_m
                    && buffer.memory_base() == Register::RSP
                    && origin.memory_base() == buffer.memory_base()
                    && origin.memory_index() == buffer.memory_index()
                    && origin.memory_index_scale() == buffer.memory_index_scale()
                    && origin.memory_displacement64() == buffer.memory_displacement64() + 4
                {
                    found.push((function.clone(), origin.ip()));
                }
            }
        }
        let [(function, address)] = &found[..] else {
            return Err("无法唯一定位输入来源检查".into());
        };
        let step = progress.activity("准备远控兼容补丁");
        let mut body = image.instructions(function)?;
        let origin = *body
            .iter()
            .find(|instruction| instruction.ip() == *address)
            .ok_or("找不到输入来源读取指令")?;
        let register = origin.op0_register();
        let memory = MemoryOperand::new(
            origin.memory_base(),
            origin.memory_index(),
            origin.memory_index_scale(),
            origin.memory_displacement64() as i64,
            origin.memory_displ_size(),
            false,
            origin.segment_prefix(),
        );
        let mut buffer = memory;
        buffer.displacement -= 4;
        let packets = body
            .windows(8)
            .enumerate()
            .filter_map(|(index, block)| {
                (block[2].mnemonic() == Mnemonic::Cmp
                    && block[3].code() == Code::Setne_rm8
                    && block[3].op0_kind() == OpKind::Register
                    && block[4].mnemonic() == Mnemonic::Cmp
                    && block[4].op0_kind() == OpKind::Register
                    && matches!(
                        block[4].op1_kind(),
                        OpKind::Immediate8to32
                            | OpKind::Immediate8to64
                            | OpKind::Immediate32
                            | OpKind::Immediate32to64
                    )
                    && block[4].op0_register().full_register()
                        != block[3].op0_register().full_register()
                    && block[5].code() == Code::Setne_rm8
                    && block[5].op0_kind() == OpKind::Register
                    && block[5].op0_register() != block[3].op0_register()
                    && block[6].code() == Code::Or_rm8_r8
                    && block[6].op0_register() == block[5].op0_register()
                    && block[6].op1_register() == block[3].op0_register()
                    && matches!(block[7].code(), Code::Je_rel8_64 | Code::Je_rel32_64))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let [packet] = packets[..] else {
            return Err("无法唯一定位文本输入判断".into());
        };
        let next = body[packet + 7].next_ip();
        assign(
            &mut body[packet + 3],
            Instruction::with_branch(Code::Jne_rel8_64, next)?,
        );
        assign(&mut body[packet + 5], Instruction::with(Code::Zero_bytes));
        assign(&mut body[packet + 6], Instruction::with(Code::Zero_bytes));

        let checks = body
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (instruction.code() == Code::Cmp_rm32_imm8
                    && instruction.op0_register() == register
                    && instruction.immediate8to32() == 2)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        let common = checks
            .iter()
            .copied()
            .filter(|index| {
                body.get(index + 1).is_some_and(|instruction| {
                    matches!(instruction.code(), Code::Jbe_rel8_64 | Code::Jbe_rel32_64)
                })
            })
            .collect::<Vec<_>>();
        let [common] = common[..] else {
            return Err("无法唯一定位输入来源分支".into());
        };
        let target = body[common].ip();
        let branch = body[common + 1];
        for index in checks {
            if !body.get(index + 1).is_some_and(|instruction| {
                matches!(instruction.code(), Code::Ja_rel8_64 | Code::Ja_rel32_64)
                    && instruction.near_branch_target() == branch.next_ip()
            }) {
                continue;
            }
            assign(
                &mut body[index],
                Instruction::with_branch(Code::Jmp_rel8_64, target)?,
            );
            assign(&mut body[index + 1], Instruction::with(Code::Zero_bytes));
            if body.get(index + 2).is_some_and(|instruction| {
                matches!(instruction.code(), Code::Jmp_rel8_64 | Code::Jmp_rel32_64)
                    && instruction.near_branch_target() == branch.near_branch_target()
            }) {
                assign(&mut body[index + 2], Instruction::with(Code::Zero_bytes));
            }
        }

        let clears = body
            .windows(2)
            .enumerate()
            .filter_map(|(index, window)| {
                (window[0].code() == Code::Mov_rm64_imm32
                    && window[0].op0_kind() == OpKind::Memory
                    && window[0].memory_base() == buffer.base
                    && window[0].memory_index() == buffer.index
                    && window[0].memory_displacement64() == buffer.displacement as u64
                    && window[0].immediate32() == 0
                    && window[1].op0_kind() == OpKind::Register
                    && window[1].op0_register() == Register::RAX
                    && window[1].code() == Code::Mov_r64_rm64)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        let [clear] = clears[..] else {
            return Err("无法唯一定位输入来源初始化".into());
        };
        assign(
            &mut body[clear],
            Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EAX)?,
        );
        let mut store = Instruction::with2(Code::Mov_rm64_r64, buffer, Register::RAX)?;
        store.set_ip(image.end() + 4);
        body.insert(clear + 1, store);

        let index = body
            .iter()
            .position(|instruction| instruction.ip() == *address)
            .ok_or("找不到输入来源读取指令")?;
        let mut added = [
            Instruction::with2(Code::Cmp_rm32_imm8, register, 2)?,
            Instruction::with_branch(Code::Jne_rel8_64, body[index + 1].ip())?,
            Instruction::with1(Code::Dec_rm32, register)?,
            Instruction::with2(Code::Mov_rm32_r32, memory, register)?,
        ];
        for (offset, instruction) in added.iter_mut().enumerate() {
            instruction.set_ip(image.end() + offset as u64);
        }
        body.splice(index + 1..index + 1, added);
        let edits = image.reencode(function, &body)?;
        step.finish(format!(
            "输入来源；RVA 0x{:08X}；2 → 1",
            address - image.base(),
        ));
        Ok(vec![Mode::enabled(edits)])
    }
}
