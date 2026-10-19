use std::{collections::BTreeSet, ops::Range};

use crate::{
    Result,
    feature::{Analysis, Edit, Feature, Mode, Target},
    image::{Image, References, Symbols, assembly, functions},
    progress::Progress,
    xlog,
};

const KEY: &str = "update.data\0";

pub const FEATURE: Feature = Feature {
    id: "no-updates",
    name: "不要更新",
    description: "不要下载安装更新",
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

struct Scan {
    symbols: Symbols,
    functions: &'static [(&'static str, &'static [u8])],
    found: BTreeSet<&'static str>,
}

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

fn scan(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan {
        symbols,
        functions: FUNCTIONS,
        found: BTreeSet::new(),
    })
}

fn find_launcher(image: &Image<'_>, progress: &Progress) -> Result<Symbols> {
    Ok(Symbols::from([(
        KEY.to_owned(),
        image.find(KEY, KEY.as_bytes(), progress)?,
    )]))
}

fn scan_launcher(symbols: Symbols) -> Box<dyn Analysis> {
    Box::new(Scan {
        symbols,
        functions: &[(KEY, &[0x31, 0xc0, 0xc3])],
        found: BTreeSet::new(),
    })
}

impl Analysis for Scan {
    fn visit(
        &mut self,
        image: &Image<'_>,
        function: &Range<u64>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Edit>> {
        let mut edits = Vec::new();
        for &(name, bytes) in self.functions {
            let matches = functions(name, &self.symbols, references);
            if !matches.contains_key(&function.start) {
                continue;
            }
            if matches.len() != 1 {
                return Err(format!("无法唯一定位 {}", name.trim_end_matches('\0')).into());
            }
            if self.found.insert(name) {
                let step = progress.activity("准备更新补丁");
                let address = function.start;
                edits.push(edit(image, address, bytes)?);
                step.finish(format!(
                    "{}；RVA 0x{:08X}；入口 → {}",
                    name.trim_end_matches('\0'),
                    address - image.base(),
                    assembly(bytes, address),
                ));
            }
        }
        Ok(edits)
    }

    fn finish(
        self: Box<Self>,
        _image: &Image<'_>,
        _references: &References,
        _progress: &Progress,
    ) -> Result<Vec<Mode>> {
        for &(name, _) in self.functions {
            if !self.found.contains(name) {
                return Err(format!("找不到 {}", name.trim_end_matches('\0')).into());
            }
        }
        Ok(vec![Mode::enabled(Vec::new())])
    }
}
