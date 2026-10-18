use std::{collections::BTreeSet, ops::Range};

use iced_x86::Code;

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, functions},
    progress::Progress,
    xlog,
};

const CHANGE: &str = "ChangeIconFlashVisible";
const STOP: &str = "mmui::MessageNotificationUIService::StopFlashAndRecoverIcon";

pub const FEATURE: Feature = Feature {
    id: "tray-flash",
    name: "关闭托盘闪动",
    description: "收到新消息时使用静止的托盘图标",
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
    xlog::find(image, &[CHANGE, STOP], progress)
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
        let named = |name: &str| -> Result<Range<u64>> {
            let found = functions(name, &self.symbols, references)
                .into_values()
                .collect::<Vec<_>>();
            let [function]: [_; 1] = found
                .try_into()
                .map_err(|_| format!("无法唯一定位{name}"))?;
            Ok(function)
        };
        let change = named(CHANGE)?;
        let stop = named(STOP)?;
        let callers = references
            .get(stop.start)
            .into_iter()
            .flatten()
            .map(|function| function.start)
            .collect::<BTreeSet<_>>();
        let found = references
            .get(change.start)
            .into_iter()
            .flatten()
            .filter(|function| callers.contains(&function.start))
            .collect::<Vec<_>>();
        let [function] = &found[..] else {
            return Err("无法唯一定位托盘闪动回调".into());
        };
        let jumps = image
            .instructions(function)?
            .into_iter()
            .filter(|instruction| {
                matches!(instruction.code(), Code::Jmp_rel8_64 | Code::Jmp_rel32_64)
                    && instruction.near_branch_target() == change.start
            })
            .collect::<Vec<_>>();
        let [jump] = jumps[..] else {
            return Err("无法唯一定位图标显隐调用".into());
        };
        let step = progress.activity("准备托盘补丁");
        let offset = image.offset(jump.ip())?;
        step.finish(format!(
            "{CHANGE}；RVA 0x{:08X}；{:02X} → C3",
            jump.ip() - image.base(),
            image.data(jump.ip(), 1)?[0],
        ));
        Ok(vec![Mode::enabled(vec![Edit {
            range: offset..offset + 1,
            bytes: vec![0xc3],
        }])])
    }
}
