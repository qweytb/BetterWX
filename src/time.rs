use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use iced_x86::{Encoder, Instruction, Mnemonic, OpKind, Register};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, argument, assembly, calls, functions},
    progress::{Progress, Step},
    xlog,
};

const VIEW: &str = "mmui::ChatTimeItemView::RefershTimeLabel";
const MODEL: &str = "virtual mmui::ChatTimeItemView::OnViewModelChanged";
const SHORT: &str = "hh:mm\0";
const SPACE: &str = " hh:mm\0";
const SECONDS: &str = " hh:mm:ss\0";

pub const FEATURE: Feature = Feature {
    id: "time-format",
    name: "时间格式",
    description: "可以精确到秒，也可以始终显示完整的日期时间",
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
    let mut symbols = xlog::find(image, &[VIEW, MODEL], progress)?;
    for text in [SHORT, SPACE, SECONDS] {
        symbols.insert(
            text.to_owned(),
            image.find(text, text.as_bytes(), progress)?,
        );
    }
    Ok(symbols)
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan { symbols })
}

fn encode(image: &Image<'_>, instruction: Instruction, step: &Step) -> Result<Edit> {
    let mut encoder = Encoder::new(64);
    encoder.encode(&instruction, instruction.ip())?;
    let bytes = encoder.take_buffer();
    if bytes.len() != instruction.len() {
        return Err("无法原位修改时间格式".into());
    }
    let original = image.data(instruction.ip(), instruction.len())?;
    if original != bytes {
        step.record(format!(
            "RVA 0x{:08X}；{} → {}",
            instruction.ip() - image.base(),
            assembly(original, instruction.ip()),
            assembly(&bytes, instruction.ip()),
        ));
    }
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
        let found: Vec<_> = functions(VIEW, &self.symbols, references)
            .into_values()
            .collect();
        let [view] = &found[..] else {
            return Err("无法唯一定位聊天时间显示函数".into());
        };
        let body = image.instructions(view)?;
        let short = functions(SHORT, &self.symbols, references);
        let found: Vec<_> = calls(&body)
            .filter(|(_, target)| short.contains_key(target))
            .collect();
        let [(index, short)] = found[..] else {
            return Err("无法唯一定位原样式时间格式调用".into());
        };
        let output = argument(&body, index, Register::RCX)?;
        if output.mnemonic() != Mnemonic::Lea
            || !matches!(output.memory_base(), Register::RBP | Register::RSP)
        {
            return Err("无法识别时间格式输出位置".into());
        }
        let timestamp = argument(&body, index, Register::RDX)?;
        let found: Vec<_> = calls(&body)
            .filter(|(_, target)| *target != short)
            .filter(|(index, _)| {
                argument(&body, *index, Register::RCX).is_ok_and(|argument| argument == output)
                    && argument(&body, *index, Register::RDX)
                        .is_ok_and(|argument| argument == timestamp)
            })
            .collect();
        let [(_, full)] = found[..] else {
            return Err("无法唯一定位完整时间格式调用".into());
        };
        let mut targets = BTreeSet::from([short, full]);
        for target in [short, full] {
            let function = image.function(target)?.ok_or("找不到时间格式函数")?;
            let body = image.instructions(&function)?;
            targets.extend(calls(&body).map(|(_, target)| target));
        }
        let mut replacements = BTreeMap::new();
        let seconds = self.symbols[SECONDS][0];
        for target in targets {
            progress.check()?;
            let Some(function) = image.function(target)? else {
                continue;
            };
            let body = image.instructions(&function)?;
            for (index, _) in calls(&body) {
                for (pointer, length) in [
                    (Register::RCX, Register::RDX),
                    (Register::RDX, Register::R8),
                ] {
                    let Ok(mut pointer) = argument(&body, index, pointer) else {
                        continue;
                    };
                    if pointer.mnemonic() != Mnemonic::Lea || !pointer.is_ip_rel_memory_operand() {
                        continue;
                    }
                    let address = pointer.ip_rel_memory_address();
                    let (size, replacement) = if self.symbols[SHORT].contains(&address) {
                        (5, seconds + 1)
                    } else if self.symbols[SPACE].contains(&address) {
                        (6, seconds)
                    } else {
                        continue;
                    };
                    let mut length = argument(&body, index, length)?;
                    if length.mnemonic() != Mnemonic::Mov
                        || length.op1_kind() != OpKind::Immediate32
                        || length.immediate32() != size
                    {
                        return Err("无法识别时间格式字符串长度".into());
                    }
                    pointer.set_memory_displacement64(replacement);
                    length.set_immediate32(size + 3);
                    replacements.insert(pointer.ip(), pointer);
                    replacements.insert(length.ip(), length);
                }
            }
        }
        if replacements.is_empty() {
            return Err("找不到时间格式字符串参数".into());
        }
        let step = progress.activity("准备时间格式");
        let edits = replacements
            .into_values()
            .map(|instruction| encode(image, instruction, &step))
            .collect::<Result<Vec<_>>>()?;
        let mut modes = Vec::new();
        for (id, name, target) in [("seconds", "精确到秒", short), ("full", "完整时间", full)]
        {
            let mut edits = edits.clone();
            let mut call = body[index];
            call.set_near_branch64(target);
            edits.push(encode(image, call, &step)?);
            modes.push(Mode { id, name, edits });
        }
        step.finish("精确到秒、完整时间");
        Ok(modes)
    }
}
