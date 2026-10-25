use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use iced_x86::{Code, Encoder, Mnemonic, OpKind};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, assembly, calls, functions},
    progress::Progress,
    xlog,
};

const FUNCTIONS: &[&str] = &[
    "mmui::ChatMessageViewModel::OnMessageLoaded",
    "mmui::ChatMessageViewModel::OnOlderPageMessageLoaded",
    "mmui::ChatMessageViewModel::OnNewerPageMessageLoaded",
    "mmui::ChatMessageViewModel::AddNormalMessage",
    "mmui::ChatMessageViewModel::TryAddFriendMessage",
];

pub const FEATURE: Feature = Feature {
    id: "timestamps",
    name: "逐条显示时间",
    description: "每条消息都显示时间",
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
    xlog::find(image, FUNCTIONS, progress)
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
        let mut comparisons = BTreeMap::new();
        for &name in FUNCTIONS {
            let found: Vec<_> = functions(name, &self.symbols, references)
                .into_values()
                .collect();
            let [function] = &found[..] else {
                return Err(format!("无法唯一定位{name}").into());
            };
            let body = image.instructions(function)?;
            let mut targets: BTreeSet<_> = calls(&body).map(|(_, target)| target).collect();
            targets.insert(function.start);
            let mut candidates = BTreeMap::new();
            for target in targets {
                progress.check()?;
                let Some(function) = image.function(target)? else {
                    continue;
                };
                let body = image.instructions(&function)?;
                for window in body.windows(3) {
                    let comparison = window[1];
                    if window[0].mnemonic() == Mnemonic::Cmova
                        && comparison.code() == Code::Cmp_rm32_imm32
                        && comparison.op0_kind() == OpKind::Register
                        && comparison.immediate32() == 301
                        && window[0].op0_register().full_register()
                            == comparison.op0_register().full_register()
                        && matches!(window[2].mnemonic(), Mnemonic::Setae | Mnemonic::Jb)
                    {
                        candidates.insert(comparison.ip(), comparison);
                    }
                }
            }
            let found: Vec<_> = candidates.into_values().collect();
            let [comparison] = found[..] else {
                return Err(format!("无法唯一定位{name}的时间间隔判断").into());
            };
            comparisons.insert(comparison.ip(), comparison);
        }
        let step = progress.activity("准备时间显示");
        let mut edits = Vec::new();
        for original in comparisons.into_values() {
            let mut comparison = original;
            comparison.set_immediate32(0);
            let mut encoder = Encoder::new(64);
            encoder.encode(&comparison, original.ip())?;
            let bytes = encoder.take_buffer();
            if bytes.len() != original.len() {
                return Err("无法原位替换时间间隔判断".into());
            }
            let offset = image.offset(original.ip())?;
            step.record(format!(
                "RVA 0x{:08X}；{} → {}",
                original.ip() - image.base(),
                assembly(image.data(original.ip(), original.len())?, original.ip()),
                assembly(&bytes, original.ip()),
            ));
            edits.push(Edit {
                range: offset..offset + bytes.len(),
                bytes,
            });
        }
        step.finish(format!("{} 处时间间隔判断；301 秒 → 0 秒", edits.len()));
        Ok(vec![Mode::enabled(edits)])
    }
}
