use std::{collections::BTreeMap, ops::Range};

use iced_x86::{Code, Instruction, Mnemonic, OpKind};

use crate::{
    Result,
    feature::{Analysis, Edit, Mode},
    image::{Image, References, Symbols, calls, functions},
    progress::Progress,
};

const HEX: &str = "0123456789ABCDEF";
const QUERY: &str = "NtQuerySystemInformation";
const INPUT: &str = "Keyboard::InjectInput";

struct Scan {
    symbols: Symbols,
}

pub fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let values = [HEX, QUERY, INPUT].map(|name| {
        let text = format!("{name}\0");
        let bytes = if name == INPUT {
            text.encode_utf16().flat_map(u16::to_le_bytes).collect()
        } else {
            text.into_bytes()
        };
        (name, bytes)
    });
    let symbols = image.find_many(values, progress)?;
    for name in [HEX, QUERY, INPUT] {
        if symbols[name].is_empty() {
            return Err(format!("找不到探针符号：{name}").into());
        }
    }
    Ok(symbols)
}

pub fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan { symbols })
}

fn branch(image: &Image<'_>, instruction: &Instruction) -> Result<Edit> {
    let bytes = match instruction.code() {
        Code::Je_rel8_64 | Code::Jle_rel8_64 => vec![0xeb],
        Code::Je_rel32_64 | Code::Jle_rel32_64 => vec![0x90, 0xe9],
        _ => return Err("无法识别检测结果分支".into()),
    };
    let offset = image.offset(instruction.ip())?;
    Ok(Edit {
        range: offset..offset + bytes.len(),
        bytes,
    })
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
        let mut candidates = BTreeMap::new();
        for function in functions(HEX, &self.symbols, references).values() {
            for (_, target) in calls(&image.instructions(function)?) {
                if let Some(function) = image.function(target)? {
                    candidates.insert(function.start, function);
                }
            }
        }
        let mut windows = BTreeMap::new();
        for function in candidates.values() {
            progress.check()?;
            let body = image.instructions(function)?;
            let mut found = Vec::new();
            for block in body.windows(5) {
                let [branch, flag, matched, jump, empty] = block else {
                    unreachable!();
                };
                if matches!(branch.code(), Code::Je_rel8_64 | Code::Je_rel32_64)
                    && flag.code() == Code::Mov_r8_imm8
                    && flag.immediate8() == 1
                    && matched.code() == Code::Mov_rm32_imm32
                    && matched.op0_kind() == OpKind::Memory
                    && matched.immediate32() == 1
                    && matches!(jump.code(), Code::Jmp_rel8_64 | Code::Jmp_rel32_64)
                    && empty.code() == Code::Mov_rm32_imm32
                    && empty.op0_kind() == OpKind::Memory
                    && empty.immediate32() == 2
                    && matched.memory_base() == empty.memory_base()
                    && matched.memory_index() == empty.memory_index()
                    && matched.memory_index_scale() == empty.memory_index_scale()
                    && matched.memory_displacement64() == empty.memory_displacement64()
                    && branch.near_branch_target() == empty.ip()
                    && jump.near_branch_target() == empty.next_ip()
                {
                    found.push(*branch);
                }
            }
            if !found.is_empty() {
                windows.insert(function.start, found);
            }
        }
        let [windows] = windows.values().collect::<Vec<_>>()[..] else {
            return Err("无法唯一定位远控窗口检测结果".into());
        };
        let mut edits = Vec::new();
        let step = progress.activity("准备窗口特征补丁");
        for instruction in windows {
            edits.push(branch(image, instruction)?);
            step.record(format!(
                "窗口匹配；RVA 0x{:08X}；未命中",
                instruction.ip() - image.base(),
            ));
        }
        step.finish("窗口检测结果");

        let queries = functions(QUERY, &self.symbols, references);
        let mut pipes = BTreeMap::new();
        for query in queries.values() {
            for function in references.get(query.start).into_iter().flatten() {
                progress.check()?;
                let body = image.instructions(function)?;
                for block in body.windows(5) {
                    let [call, first, last, compare, branch] = block else {
                        unreachable!();
                    };
                    if call.code() == Code::Call_rel32_64
                        && call.near_branch_target() == query.start
                        && first.code() == Code::Mov_r64_rm64
                        && first.op1_kind() == OpKind::Memory
                        && last.code() == Code::Mov_r64_rm64
                        && last.op1_kind() == OpKind::Memory
                        && first.memory_base() == last.memory_base()
                        && first.memory_index() == last.memory_index()
                        && last.memory_displacement64() == first.memory_displacement64() + 8
                        && compare.mnemonic() == Mnemonic::Cmp
                        && compare.op0_register() == first.op0_register()
                        && compare.op1_register() == last.op0_register()
                        && matches!(branch.code(), Code::Je_rel8_64 | Code::Je_rel32_64)
                        && body.iter().any(|instruction| {
                            instruction.ip() == branch.near_branch_target()
                                && instruction.code() == Code::Test_rm64_r64
                                && instruction.op0_register() == first.op0_register()
                                && instruction.op1_register() == first.op0_register()
                        })
                    {
                        pipes.insert(branch.ip(), *branch);
                    }
                }
            }
        }
        let [pipe] = pipes.values().collect::<Vec<_>>()[..] else {
            return Err("无法唯一定位UIA管道筛选".into());
        };
        let step = progress.activity("准备UIA探测补丁");
        edits.push(branch(image, pipe)?);
        step.finish(format!(
            "管道筛选；RVA 0x{:08X}；空结果",
            pipe.ip() - image.base(),
        ));

        let mut input = BTreeMap::new();
        for function in functions(INPUT, &self.symbols, references).values() {
            progress.check()?;
            let body = image.instructions(function)?;
            for block in body.windows(3) {
                let [compare, branch, interval] = block else {
                    unreachable!();
                };
                if compare.mnemonic() == Mnemonic::Cmp
                    && compare.op0_kind() == OpKind::Memory
                    && matches!(branch.code(), Code::Jle_rel8_64 | Code::Jle_rel32_64)
                    && interval.code() == Code::Imul_r64_rm64_imm32
                    && interval.op1_kind() == OpKind::Memory
                    && interval.immediate32() == 1_000_000_000
                    && body.iter().any(|instruction| {
                        instruction.ip() > branch.ip()
                            && instruction.ip() < branch.near_branch_target()
                            && matches!(instruction.code(), Code::Jge_rel8_64 | Code::Jge_rel32_64)
                            && instruction.near_branch_target() == branch.near_branch_target()
                    })
                {
                    input.insert(branch.ip(), *branch);
                }
            }
        }
        let [input] = input.values().collect::<Vec<_>>()[..] else {
            return Err("无法唯一定位输入活动通知条件".into());
        };
        let step = progress.activity("准备输入活动补丁");
        edits.push(branch(image, input)?);
        step.finish(format!(
            "输入活动；RVA 0x{:08X}；未命中",
            input.ip() - image.base(),
        ));
        Ok(vec![Mode::enabled(edits)])
    }
}
