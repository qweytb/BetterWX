use std::{
    collections::BTreeMap,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use crate::{
    Result, feature, icon, install,
    progress::Progress,
    sound,
    store::{self, Content, Store},
};

pub struct Source {
    target: PathBuf,
    pub modes: BTreeMap<&'static str, &'static str>,
    pub detail: String,
}

pub fn find(store: &Store, progress: &Progress) -> Result<Option<Source>> {
    let file = &store.files[&store.target];
    if file.backed_up()? || file.source_issue.is_some() {
        return Ok(None);
    }
    let Some(target) = install::previous(&store.target)? else {
        return Ok(None);
    };
    let progress = progress.group("读取旧版设置");
    let mut previous = Store::open(&target, &progress)?;
    let primary = previous.target.clone();
    let prepared = feature::prepare(&mut previous, feature::FEATURES, &progress, |path| {
        path == primary
    })?;
    feature::inspect(&mut previous, &prepared, &progress)?;
    let mut modes = BTreeMap::new();
    let mut descriptions = Vec::new();
    for patch in &prepared {
        let feature::State::Enabled(mode) = patch.state(&previous) else {
            continue;
        };
        let choices = patch.edits.as_ref().expect("mode not prepared");
        modes.insert(patch.feature.id, choices[mode].id);
        descriptions.push(if choices.len() == 1 {
            patch.feature.name.to_owned()
        } else {
            format!("{}：{}", patch.feature.name, choices[mode].name)
        });
    }
    if modes.is_empty() {
        return Ok(None);
    }
    let version = target
        .parent()
        .and_then(Path::file_name)
        .ok_or("旧版本目录缺少名称")?
        .to_string_lossy();
    let detail = format!("继承 {version} 的设置：\n{}", descriptions.join("\n"));
    progress.record("可继承设置", &detail);
    Ok(Some(Source {
        target,
        modes,
        detail,
    }))
}

impl Source {
    pub fn copy(
        &self,
        store: &Store,
        contents: &BTreeMap<PathBuf, Content>,
        progress: &Progress,
    ) -> Result<()> {
        let enabled = |id| {
            contents
                .values()
                .any(|content| content.enabled.contains_key(id))
        };
        if enabled(sound::FEATURE.id) {
            for sound in sound::SOUNDS {
                progress.check()?;
                copy(
                    &sound.path(&self.target)?,
                    &sound.path(&store.target)?,
                    sound::validate,
                    progress,
                )?;
            }
        }
        if enabled(icon::FEATURE.id) {
            copy(
                &icon::path(&self.target)?,
                &icon::path(&store.target)?,
                |data| icon::validate(data, progress),
                progress,
            )?;
        }
        Ok(())
    }
}

fn copy(
    source: &Path,
    target: &Path,
    validate: impl FnOnce(&[u8]) -> Result<()>,
    progress: &Progress,
) -> Result<()> {
    if target.try_exists()? {
        return Ok(());
    }
    let data = match fs::read(source) {
        Ok(data) => data,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    validate(&data)?;
    fs::create_dir_all(target.parent().ok_or("资源文件缺少父目录")?)?;
    store::write(target, &data, progress)
}
