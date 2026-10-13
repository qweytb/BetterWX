use std::collections::BTreeSet;

use crate::{
    Result,
    feature::{Edit, Feature, Target},
    image::{Image, References, Symbols, assembly},
    progress::Progress,
    xlog,
};

const KEY: &str = "update.data\0";

pub const FEATURE: Feature = Feature {
    id: "no-updates",
    name: "关闭更新",
    description: "关闭微信内置版本更新",
    targets: &[
        Target {
            file: None,
            find,
            scan,
        },
        Target {
            file: Some("../Weixin.exe"),
            find: find_launcher,
            scan: scan_launcher,
        },
    ],
};

const FUNCTIONS: &[(&str, &[u8])] = &[
    // CheckUpdate returns 2 when no update is available.
    (
        "kernel::manager::UpdateManager::CheckUpdate",
        &[0xb8, 2, 0, 0, 0, 0xc3],
    ),
    (
        "kernel::manager::UpdateManager::OnXPluginUpdateNotify",
        &[0xc3],
    ),
    ("kernel::manager::UpdateManager::TryDownloadUpdate", &[0xc3]),
    (
        "kernel::manager::UpdateManager::LaunchUpdateExe",
        &[0x31, 0xc0, 0xc3],
    ),
    (
        "kernel::manager::UpdateManager::NeedShowRestartAlert",
        &[0x31, 0xc0, 0xc3],
    ),
    (
        "kernel::manager::UpdateManager::NeedShowUpdateTip",
        &[0x31, 0xc0, 0xc3],
    ),
];

fn edit(image: &Image<'_>, address: u64, bytes: &[u8]) -> Result<Edit> {
    image.data(address, bytes.len())?;
    let offset = image.offset(address)?;
    Ok(Edit {
        range: offset..offset + bytes.len(),
        bytes: bytes.to_vec(),
    })
}

fn find(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    let names: Vec<_> = FUNCTIONS.iter().map(|(name, ..)| *name).collect();
    xlog::find(image, &names, progress)
}

fn scan(
    image: &Image<'_>,
    symbols: &Symbols,
    references: &References,
    progress: &Progress,
) -> Result<Vec<Edit>> {
    let step = progress.start("准备更新补丁", FUNCTIONS.len() as u64, "个函数");
    let mut edits = Vec::new();
    for (index, (name, bytes)) in FUNCTIONS.iter().enumerate() {
        progress.check()?;
        let functions: BTreeSet<_> = symbols[*name]
            .iter()
            .filter_map(|address| references.get(*address))
            .flatten()
            .map(|function| function.start)
            .collect();
        let [address] = functions.into_iter().collect::<Vec<_>>()[..] else {
            return Err(format!("无法唯一定位 {name}").into());
        };
        step.record(format!(
            "{name}；RVA 0x{:08X}；入口 → {}",
            address - image.base(),
            assembly(bytes, address),
        ));
        edits.push(edit(image, address, bytes)?);
        step.set(index as u64 + 1);
    }
    step.finish(format!(
        "{} 入口；{} 字节",
        edits.len(),
        edits.iter().map(|edit| edit.bytes.len()).sum::<usize>()
    ));
    Ok(edits)
}

fn find_launcher(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    Ok(Symbols::from([(
        KEY.to_owned(),
        image.find(KEY.as_bytes(), progress)?,
    )]))
}

fn scan_launcher(
    image: &Image<'_>,
    symbols: &Symbols,
    references: &References,
    progress: &Progress,
) -> Result<Vec<Edit>> {
    let functions: BTreeSet<_> = symbols[KEY]
        .iter()
        .filter_map(|address| references.get(*address))
        .flatten()
        .map(|function| function.start)
        .collect();
    let [address] = functions.into_iter().collect::<Vec<_>>()[..] else {
        return Err("无法唯一定位启动器的版本更新入口".into());
    };
    let step = progress.activity("准备启动器补丁");
    let loader = edit(image, address, &[0x31, 0xc0, 0xc3])?;
    step.finish(format!(
        "Weixin.exe；RVA 0x{:08X}；入口 → {}",
        address - image.base(),
        assembly(&loader.bytes, address)
    ));
    Ok(vec![loader])
}
