use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::{Path, PathBuf},
};

use crate::{
    Result, appex, browser, coexist, credentials, emoticon, icon,
    image::{Image, References, Symbols},
    login, notify,
    progress::Progress,
    remote, resources, revoke, sound,
    store::{self, Content, Store},
    tray, uia, updates,
};

pub type Edits = BTreeMap<PathBuf, Vec<Edit>>;
pub type Resources = BTreeMap<String, Range<usize>>;

pub struct Feature {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub targets: &'static [Target],
}

pub struct Target {
    pub file: Option<&'static str>,
    pub find: fn(&Image<'_>, &Progress) -> Result<Symbols>,
    pub scan: fn(Symbols) -> Box<dyn Analysis>,
}

pub trait Analysis {
    fn resources(&self) -> Resources {
        Resources::new()
    }

    fn visit(
        &mut self,
        image: &Image<'_>,
        function: &Range<u64>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Edit>>;

    fn finish(
        self: Box<Self>,
        image: &Image<'_>,
        references: &References,
        progress: &Progress,
    ) -> Result<Vec<Mode>>;
}

impl Target {
    fn path(&self, primary: &Path) -> Result<PathBuf> {
        match self.file {
            Some(file) => Ok(primary.parent().ok_or("目标文件缺少父目录")?.join(file)),
            None => Ok(primary.to_owned()),
        }
    }
}

#[derive(Clone)]
pub struct Edit {
    pub range: Range<usize>,
    pub bytes: Vec<u8>,
}

pub struct Mode<T = Vec<Edit>> {
    pub id: &'static str,
    pub name: &'static str,
    pub edits: T,
}

impl<T> Mode<T> {
    pub fn enabled(edits: T) -> Self {
        Self {
            id: "enabled",
            name: "开启",
            edits,
        }
    }
}

pub struct Prepared {
    pub feature: &'static Feature,
    pub edits: std::result::Result<Vec<Mode<Edits>>, String>,
    pub resources: BTreeMap<PathBuf, Resources>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disabled,
    Enabled(usize),
    Partial,
}

impl State {
    pub fn enabled(self) -> bool {
        matches!(self, Self::Enabled(_))
    }
}

impl Prepared {
    pub fn issue<'a>(&'a self, store: &'a Store) -> Option<&'a String> {
        match &self.edits {
            Err(error) => Some(error),
            Ok(modes) => modes
                .iter()
                .flat_map(|mode| mode.edits.keys())
                .find_map(|target| store.files[target].issue.as_ref()),
        }
    }

    pub fn state(&self, store: &Store) -> State {
        let Ok(modes) = &self.edits else {
            return State::Disabled;
        };
        let states: BTreeSet<_> = modes
            .iter()
            .flat_map(|mode| mode.edits.keys())
            .map(|target| store.files[target].enabled.get(self.feature.id).copied())
            .collect();
        match states.into_iter().collect::<Vec<_>>().as_slice() {
            [] | [None] => State::Disabled,
            [Some(mode)] => State::Enabled(*mode),
            _ => State::Partial,
        }
    }

    pub fn label(&self, state: State) -> &'static str {
        match state {
            State::Disabled => "关闭",
            State::Enabled(mode) => self.edits.as_ref().expect("mode not prepared")[mode].name,
            State::Partial => "部分开启",
        }
    }

    pub fn next(&self, store: &Store) -> Option<usize> {
        match self.state(store) {
            State::Enabled(mode) if mode + 1 == self.edits.as_ref().expect("modes").len() => None,
            State::Enabled(mode) => Some(mode + 1),
            _ => Some(0),
        }
    }

    pub fn targets(&self, store: &Store, mode: Option<usize>) -> Result<Vec<PathBuf>> {
        Ok(self
            .edits
            .as_ref()
            .map_err(|error| error.clone())?
            .iter()
            .flat_map(|mode| mode.edits.keys())
            .filter(|target| store.files[*target].enabled.get(self.feature.id).copied() != mode)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }
}

pub const FEATURES: &[Feature] = &[
    login::FEATURE,
    credentials::FEATURE,
    revoke::FEATURE,
    resources::FEATURE,
    emoticon::FEATURE,
    browser::FEATURE,
    appex::FEATURE,
    notify::FEATURE,
    tray::FEATURE,
    remote::FEATURE,
    uia::FEATURE,
    updates::FEATURE,
    icon::FEATURE,
    sound::FEATURE,
    coexist::FEATURE,
];

pub fn targets(target: &Path) -> Result<Vec<PathBuf>> {
    Ok(FEATURES
        .iter()
        .flat_map(|feature| feature.targets)
        .filter(|target| target.file.is_some())
        .map(|entry| entry.path(target))
        .collect::<Result<BTreeSet<_>>>()?
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
    analyze(store, FEATURES, progress)
}

pub fn analyze(
    store: &mut Store,
    features: &'static [Feature],
    progress: &Progress,
) -> Result<Vec<Prepared>> {
    let mut prepared: Vec<_> = features
        .iter()
        .map(|feature| Prepared {
            feature,
            edits: Ok(Vec::new()),
            resources: BTreeMap::new(),
        })
        .collect();
    let mut files: BTreeMap<PathBuf, Vec<(usize, &Target)>> = BTreeMap::new();
    for (index, feature) in features.iter().enumerate() {
        for target in feature.targets {
            progress.check()?;
            let path = target.path(&store.target)?;
            match store.load(&path, progress) {
                Ok(file) => files
                    .entry(file.target.clone())
                    .or_default()
                    .push((index, target)),
                Err(error) => {
                    prepared[index].edits =
                        Err(format!("无法读取 {}：{error}", store::display(&path)))
                }
            }
        }
    }
    for (path, targets) in files {
        progress.check()?;
        let image = match Image::parse(&store.files[&path].original) {
            Ok(image) => image,
            Err(error) => {
                for (index, _) in targets {
                    prepared[index].edits = Err(format!("{}：{error}", store::display(&path)));
                }
                continue;
            }
        };
        let mut found = Vec::new();
        for (index, target) in targets {
            if prepared[index].edits.is_err() {
                continue;
            }
            progress.check()?;
            match (target.find)(&image, progress) {
                Ok(symbols) => {
                    let analysis = (target.scan)(symbols.clone());
                    found.push((index, symbols, analysis, Vec::new()));
                }
                Err(error) => {
                    let error = error.to_string();
                    progress.fail(&error);
                    prepared[index].edits = Err(error);
                }
            }
        }
        if found.is_empty() {
            continue;
        }
        let labels = found
            .iter()
            .flat_map(|(_, symbols, _, _)| symbols)
            .flat_map(|(name, addresses)| {
                addresses
                    .iter()
                    .map(move |address| (*address, name.trim_end_matches('\0').to_owned()))
            })
            .collect();
        let mut listeners: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (index, (_, symbols, _, _)) in found.iter().enumerate() {
            for address in symbols.values().flatten() {
                listeners.entry(*address).or_default().push(index);
            }
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let references =
            match image.references(&name, labels, progress, |references, function, changed| {
                let listeners: BTreeSet<_> = changed
                    .iter()
                    .flat_map(|address| &listeners[address])
                    .copied()
                    .collect();
                for listener in listeners {
                    progress.check()?;
                    let (index, _, analysis, common) = &mut found[listener];
                    if prepared[*index].edits.is_err() {
                        continue;
                    }
                    let progress = progress.group(features[*index].name);
                    match analysis.visit(&image, function, references, &progress) {
                        Ok(edits) => common.extend(edits),
                        Err(error) => {
                            let error = error.to_string();
                            progress.fail(&error);
                            prepared[*index].edits = Err(error);
                        }
                    }
                }
                Ok(())
            }) {
                Ok(references) => references,
                Err(error) => {
                    progress.fail(&error.to_string());
                    for (index, _, _, _) in found {
                        prepared[index].edits = Err(error.to_string());
                    }
                    continue;
                }
            };
        for (index, _, analysis, common) in found {
            progress.check()?;
            if prepared[index].edits.is_err() {
                continue;
            }
            let progress = progress.group(features[index].name);
            let resources = analysis.resources();
            match analysis.finish(&image, &references, &progress) {
                Ok(modes) => {
                    if let Ok(choices) = &mut prepared[index].edits {
                        for mode in modes {
                            let choice =
                                match choices.iter().position(|choice| choice.id == mode.id) {
                                    Some(index) => &mut choices[index],
                                    None => {
                                        choices.push(Mode {
                                            id: mode.id,
                                            name: mode.name,
                                            edits: Edits::new(),
                                        });
                                        choices.last_mut().expect("mode")
                                    }
                                };
                            let edits = choice.edits.entry(path.clone()).or_default();
                            edits.extend(common.iter().cloned());
                            edits.extend(mode.edits);
                        }
                    }
                    if !resources.is_empty() {
                        prepared[index].resources.insert(path.clone(), resources);
                    }
                }
                Err(error) => {
                    let error = error.to_string();
                    progress.fail(&error);
                    prepared[index].edits = Err(error);
                }
            }
        }
    }
    Ok(prepared)
}

pub fn inspect(store: &mut Store, prepared: &[Prepared], progress: &Progress) -> Result<()> {
    for (target, file) in &mut store.files {
        let name = target.file_name().unwrap_or_default().to_string_lossy();
        let step = progress.start("识别当前补丁", file.current.len() as u64, "字节");
        step.detail(name.as_ref());
        let mut enabled = BTreeMap::new();
        for patch in prepared {
            progress.check()?;
            let Ok(modes) = &patch.edits else {
                continue;
            };
            for (mode, choice) in modes.iter().enumerate() {
                let Some(edits) = choice.edits.get(target) else {
                    continue;
                };
                let applied = !edits.is_empty()
                    && edits.iter().all(|edit| {
                        file.current
                            .get(edit.range.start..edit.range.start + edit.bytes.len())
                            == Some(edit.bytes.as_slice())
                    });
                if applied {
                    enabled.insert(patch.feature.id.to_owned(), mode);
                    break;
                }
            }
        }
        let expected = generate(&file.original, &enabled, prepared, target)?;
        let mut offset = 0;
        let difference = expected
            .chunks(1024 * 1024)
            .zip(file.current.chunks(1024 * 1024))
            .find_map(|(expected, current)| {
                let difference = expected
                    .iter()
                    .zip(current)
                    .position(|(left, right)| left != right);
                let start = offset;
                offset += current.len();
                step.set(offset as u64);
                if step.sample() {
                    step.detail(format!(
                        "{name}；offset 0x{start:08X}；{} 字节",
                        current.len()
                    ));
                }
                difference.map(|index| start + index)
            })
            .or_else(|| {
                (expected.len() != file.current.len())
                    .then_some(expected.len().min(file.current.len()))
            });
        file.issue = difference.map(|offset| {
            format!(
                "{} 的位置 {offset:#x} 存在未识别的改动",
                store::display(target)
            )
        });
        let state = if let Some(issue) = &file.issue {
            issue.clone()
        } else if enabled.is_empty() {
            "原始状态".to_owned()
        } else {
            prepared
                .iter()
                .filter_map(|patch| {
                    enabled.get(patch.feature.id).map(|mode| {
                        if patch.edits.as_ref().expect("modes").len() == 1 {
                            patch.feature.name.to_owned()
                        } else {
                            format!(
                                "{}：{}",
                                patch.feature.name,
                                patch.label(State::Enabled(*mode))
                            )
                        }
                    })
                })
                .collect::<Vec<_>>()
                .join("、")
        };
        step.finish(format!("{name}；{state}"));
        file.enabled = enabled;
    }
    Ok(())
}

pub fn change(
    store: &Store,
    patch: &Prepared,
    mode: Option<usize>,
    prepared: &[Prepared],
    progress: &Progress,
) -> Result<BTreeMap<PathBuf, Content>> {
    if let Some(issue) = patch.issue(store) {
        return Err(issue.clone().into());
    }
    if mode.is_some() && patch.feature.id == sound::FEATURE.id {
        sound::initialize(store, patch, progress)?;
    }
    if mode.is_some() && patch.feature.id == icon::FEATURE.id {
        icon::initialize(store, patch, progress)?;
    }
    if mode.is_some() && patch.feature.id == notify::FEATURE.id {
        notify::initialize(progress)?;
    }
    let mut contents = BTreeMap::new();
    for target in patch.targets(store, mode)? {
        let file = &store.files[&target];
        let mut enabled = file.enabled.clone();
        if let Some(mode) = mode {
            enabled.insert(patch.feature.id.to_owned(), mode);
        } else {
            enabled.remove(patch.feature.id);
        }
        let data = generate(&file.original, &enabled, prepared, &target)?;
        contents.insert(target, Content { data, enabled });
    }
    Ok(contents)
}

pub fn describe(
    store: &Store,
    contents: &BTreeMap<PathBuf, Content>,
    prepared: &[Prepared],
    progress: &Progress,
) -> Result<()> {
    for (target, content) in contents {
        let file = &store.files[target];
        let name = target.file_name().unwrap_or_default().to_string_lossy();
        for patch in prepared {
            let Ok(modes) = &patch.edits else {
                continue;
            };
            let previous = file.enabled.get(patch.feature.id).copied();
            let current = content.enabled.get(patch.feature.id).copied();
            if previous == current {
                continue;
            }
            let Some(mode) = current.or(previous) else {
                continue;
            };
            let Some(edits) = modes[mode].edits.get(target) else {
                continue;
            };
            let image = Image::parse(&file.original)?;
            let step = progress.group(patch.feature.name).activity("生成文件内容");
            let mut size = 0;
            for edit in edits {
                progress.check()?;
                let before = &file.current[edit.range.start.min(file.current.len())
                    ..edit.range.end.min(file.current.len())];
                let after = &content.data[edit.range.start.min(content.data.len())
                    ..edit.range.end.min(content.data.len())];
                if before != after {
                    step.record(format!(
                        "{name}；{}",
                        image.difference(&edit.range, &file.current, &content.data)?
                    ));
                    size += before
                        .iter()
                        .zip(after)
                        .filter(|(left, right)| left != right)
                        .count()
                        + before.len().abs_diff(after.len());
                }
            }
            step.finish(format!(
                "{name}；{}；差异 {size} 字节",
                patch.label(current.map_or(State::Disabled, State::Enabled)),
            ));
        }
    }
    Ok(())
}

fn generate(
    original: &[u8],
    enabled: &BTreeMap<String, usize>,
    prepared: &[Prepared],
    target: &Path,
) -> Result<Vec<u8>> {
    let mut edits = Vec::new();
    for (id, mode) in enabled {
        let patch = prepared
            .iter()
            .find(|patch| patch.feature.id == id)
            .ok_or_else(|| format!("未知功能：{id}"))?;
        let modes = patch
            .edits
            .as_ref()
            .map_err(|error| format!("{}：{error}", patch.feature.name))?;
        let mode = modes.get(*mode).ok_or("找不到所选功能模式")?;
        if let Some(changes) = mode.edits.get(target) {
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
