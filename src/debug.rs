use std::ops::Range;

use iced_x86::{Code, Mnemonic, Register};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, assembly, functions},
    progress::Progress,
};

const ITEMS: &[&str] = &["插件调试命令\0", "附件预下载调试\0"];

pub const FEATURE: Feature = Feature {
    id: "debug",
    name: "开放调试功能",
    description: "开放原生调试面板的隐藏功能，快捷键 Ctrl+Shift+I",
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
    ITEMS
        .iter()
        .map(|name| {
            Ok((
                (*name).to_owned(),
                image.find(name, name.as_bytes(), progress)?,
            ))
        })
        .collect()
}

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan { symbols })
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
        let mut matches = functions(ITEMS[0], &self.symbols, references);
        for name in &ITEMS[1..] {
            let other = functions(name, &self.symbols, references);
            matches.retain(|address, _| other.contains_key(address));
        }
        let [function]: [_; 1] = matches
            .into_values()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "无法唯一定位调试面板")?;
        let body = image.instructions(&function)?;
        let mut edits = Vec::new();
        for name in ITEMS {
            let labels = body
                .iter()
                .filter(|instruction| {
                    instruction.is_ip_rel_memory_operand()
                        && self.symbols[*name].contains(&instruction.ip_rel_memory_address())
                })
                .map(|instruction| instruction.ip())
                .collect::<Vec<_>>();
            let title = name.trim_end_matches('\0');
            let [label] = labels[..] else {
                return Err(format!("无法唯一定位{title}").into());
            };
            let branches = body
                .windows(2)
                .filter_map(|window| {
                    let test = &window[0];
                    let branch = &window[1];
                    (test.code() == Code::Test_rm8_r8
                        && test.op0_register() == Register::AL
                        && test.op1_register() == Register::AL
                        && branch.mnemonic() == Mnemonic::Je
                        && branch.next_ip() <= label
                        && label < branch.near_branch_target())
                    .then_some(*branch)
                })
                .collect::<Vec<_>>();
            let [branch] = branches[..] else {
                return Err(format!("无法唯一定位{title}的显示条件").into());
            };
            let step = progress.activity("准备调试补丁");
            let offset = image.offset(branch.ip())?;
            let bytes = image.data(branch.ip(), branch.len())?;
            edits.push(Edit {
                range: offset..offset + bytes.len(),
                bytes: vec![0x90; bytes.len()],
            });
            step.finish(format!(
                "{title}；RVA 0x{:08X}；{} → nop",
                branch.ip() - image.base(),
                assembly(bytes, branch.ip()),
            ));
        }
        Ok(vec![Mode::enabled(edits)])
    }
}
