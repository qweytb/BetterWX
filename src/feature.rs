use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Path, PathBuf},
};

use crate::{
    Result,
    progress::Progress,
    store::{Content, Store},
    uia,
};

pub type Edits = BTreeMap<PathBuf, Vec<Edit>>;

pub struct Feature {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub files: &'static [&'static str],
    pub scan: fn(&mut Store, &Progress) -> Result<Edits>,
}

pub struct Edit {
    pub range: Range<usize>,
    pub bytes: Vec<u8>,
}

pub struct Prepared {
    pub feature: &'static Feature,
    pub edits: std::result::Result<Edits, String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disabled,
    Enabled,
    Partial,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "关闭",
            Self::Enabled => "开启",
            Self::Partial => "部分开启",
        }
    }
}

impl Prepared {
    pub fn issue<'a>(&'a self, store: &'a Store) -> Option<&'a String> {
        match &self.edits {
            Err(error) => Some(error),
            Ok(edits) => edits
                .keys()
                .find_map(|target| store.files[target].issue.as_ref()),
        }
    }

    pub fn state(&self, store: &Store) -> State {
        let Ok(edits) = &self.edits else {
            return State::Disabled;
        };
        let enabled = edits
            .keys()
            .filter(|target| store.files[*target].enabled.contains(self.feature.id))
            .count();
        if enabled == 0 {
            State::Disabled
        } else if enabled == edits.len() {
            State::Enabled
        } else {
            State::Partial
        }
    }

    pub fn targets(&self, store: &Store, enable: bool) -> Result<Vec<PathBuf>> {
        Ok(self
            .edits
            .as_ref()
            .map_err(|error| error.clone())?
            .keys()
            .filter(|target| store.files[*target].enabled.contains(self.feature.id) != enable)
            .cloned()
            .collect())
    }
}

pub const FEATURES: &[Feature] = &[uia::FEATURE];

pub fn targets(target: &Path) -> Result<Vec<PathBuf>> {
    let directory = target.parent().ok_or("目标文件缺少父目录")?;
    Ok(FEATURES
        .iter()
        .flat_map(|feature| feature.files)
        .map(|file| directory.join(file))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

pub fn find(id: &str) -> Result<&'static Feature> {
    FEATURES
        .iter()
        .find(|feature| feature.id == id)
        .ok_or_else(|| format!("未知功能：{id}").into())
}

pub fn scan(store: &mut Store, progress: &Progress) -> Result<Vec<Prepared>> {
    let mut prepared = Vec::new();
    for feature in FEATURES {
        progress.check()?;
        let edits = (feature.scan)(store, progress).map_err(|error| error.to_string());
        progress.check()?;
        prepared.push(Prepared { feature, edits });
    }
    Ok(prepared)
}

pub fn inspect(store: &mut Store, prepared: &[Prepared], progress: &Progress) -> Result<()> {
    for (target, file) in &mut store.files {
        let step = progress.activity("识别当前补丁");
        step.detail(target.display().to_string());
        let mut enabled = BTreeSet::new();
        for patch in prepared {
            progress.check()?;
            let Some(edits) = patch
                .edits
                .as_ref()
                .ok()
                .and_then(|edits| edits.get(target))
            else {
                continue;
            };
            let applied = !edits.is_empty()
                && edits.iter().all(|edit| {
                    file.current
                        .get(edit.range.start..edit.range.start + edit.bytes.len())
                        == Some(edit.bytes.as_slice())
                });
            if applied {
                enabled.insert(patch.feature.id.to_owned());
            }
        }
        let expected = generate(&file.original, &enabled, prepared, target)?;
        let difference = expected
            .iter()
            .zip(file.current.iter())
            .position(|(left, right)| left != right)
            .or_else(|| {
                (expected.len() != file.current.len())
                    .then_some(expected.len().min(file.current.len()))
            });
        file.issue = difference
            .map(|offset| format!("{} 的位置 {offset:#x} 存在未识别的改动", target.display()));
        step.finish(if let Some(issue) = &file.issue {
            issue.clone()
        } else if enabled.is_empty() {
            "原始状态".to_owned()
        } else {
            enabled.iter().cloned().collect::<Vec<_>>().join("、")
        });
        file.enabled = enabled;
    }
    Ok(())
}

pub fn change(
    store: &Store,
    patch: &Prepared,
    enable: bool,
    prepared: &[Prepared],
) -> Result<BTreeMap<PathBuf, Content>> {
    if let Some(issue) = patch.issue(store) {
        return Err(issue.clone().into());
    }
    let mut contents = BTreeMap::new();
    for target in patch.targets(store, enable)? {
        let file = &store.files[&target];
        let mut enabled = file.enabled.clone();
        if enable {
            enabled.insert(patch.feature.id.to_owned());
        } else {
            enabled.remove(patch.feature.id);
        }
        let data = generate(&file.original, &enabled, prepared, &target)?;
        contents.insert(target, Content { data, enabled });
    }
    Ok(contents)
}

fn generate(
    original: &[u8],
    enabled: &BTreeSet<String>,
    prepared: &[Prepared],
    target: &Path,
) -> Result<Vec<u8>> {
    let mut edits = Vec::new();
    for id in enabled {
        let patch = prepared
            .iter()
            .find(|patch| patch.feature.id == id)
            .ok_or_else(|| format!("未知功能：{id}"))?;
        let changes = patch
            .edits
            .as_ref()
            .map_err(|error| format!("{}：{error}", patch.feature.name))?;
        if let Some(changes) = changes.get(target) {
            edits.extend(changes);
        }
    }
    edits.sort_by_key(|edit| edit.range.start);
    for pair in edits.windows(2) {
        if pair[0].range.end > pair[1].range.start {
            return Err("所选功能的修改位置重叠".into());
        }
    }
    let mut output = original.to_vec();
    for edit in edits.into_iter().rev() {
        output.splice(edit.range.clone(), edit.bytes.iter().copied());
    }
    Ok(output)
}
