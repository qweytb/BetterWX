use std::collections::BTreeSet;

use crate::{
    Result,
    feature::{Edit, Edits, Feature},
    image::Image,
    progress::Progress,
    store::Store,
    xlog,
};

const LAUNCHER: &str = "../Weixin.exe";

pub const FEATURE: Feature = Feature {
    id: "no-updates",
    name: "关闭更新",
    description: "关闭微信内置版本更新",
    files: &[LAUNCHER],
    scan,
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

fn scan(store: &mut Store, progress: &Progress) -> Result<Edits> {
    let target = store.target.clone();
    let launcher = target.parent().ok_or("目标文件缺少父目录")?.join(LAUNCHER);
    let launcher = store
        .load(&launcher, progress)
        .map_err(|error| format!("无法读取 {}：{error}", launcher.display()))?
        .target
        .clone();
    let image = Image::parse(&store.files[&target].original, progress)?;
    let names: Vec<_> = FUNCTIONS.iter().map(|(name, _)| *name).collect();
    let symbols = xlog::find(&image, &names, progress)?;
    let addresses: Vec<_> = symbols.iter().flatten().copied().collect();
    let references = image.references(&addresses, progress)?;
    let step = progress.start("定位版本更新函数", FUNCTIONS.len() as u64, "个函数");
    let mut edits = Vec::new();
    for (index, ((name, bytes), symbols)) in FUNCTIONS.iter().zip(symbols).enumerate() {
        progress.check()?;
        let functions: BTreeSet<_> = symbols
            .iter()
            .filter_map(|address| references.get(address))
            .flatten()
            .map(|function| function.start)
            .collect();
        let [address] = functions.into_iter().collect::<Vec<_>>()[..] else {
            return Err(format!("无法唯一定位 {name}").into());
        };
        step.detail(format!("{name}\nRVA {:#x}", address - image.base()));
        edits.push(edit(&image, address, bytes)?);
        step.set(index as u64 + 1);
    }
    step.finish(format!("取得 {} 个函数入口", edits.len()));

    let image = Image::parse(&store.files[&launcher].original, progress)?;
    let addresses = image.find(b"update.data\0", progress)?;
    let references = image.references(&addresses, progress)?;
    let functions: BTreeSet<_> = references
        .values()
        .flatten()
        .map(|function| function.start)
        .collect();
    let [address] = functions.into_iter().collect::<Vec<_>>()[..] else {
        return Err("无法唯一定位启动器的版本更新入口".into());
    };
    let step = progress.activity("准备启动器补丁");
    let loader = edit(&image, address, &[0x31, 0xc0, 0xc3])?;
    step.finish(format!("更新入口 RVA {:#x}", address - image.base()));
    Ok(Edits::from([(target, edits), (launcher, vec![loader])]))
}
