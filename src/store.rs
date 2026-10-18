use std::{
    collections::{BTreeMap, btree_map::Entry},
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf, Prefix},
    sync::Arc,
};

use tempfile::NamedTempFile;

use crate::{Result, install, progress::Progress};

pub struct Store {
    pub target: PathBuf,
    pub files: BTreeMap<PathBuf, File>,
}

pub struct File {
    pub target: PathBuf,
    backup: PathBuf,
    pub current: Arc<Vec<u8>>,
    pub original: Arc<Vec<u8>>,
    pub enabled: BTreeMap<String, usize>,
    pub issue: Option<String>,
}

pub struct Content {
    pub data: Vec<u8>,
    pub enabled: BTreeMap<String, usize>,
}

pub fn display(path: &Path) -> String {
    let text = path.to_string_lossy();
    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::VerbatimDisk(_) => text[4..].to_owned(),
            Prefix::VerbatimUNC(..) => format!(r"\\{}", &text[8..]),
            _ => text.into_owned(),
        },
        _ => text.into_owned(),
    }
}

fn read(path: &Path, progress: &Progress, name: &str) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let total = file.metadata()?.len();
    let mut data = Vec::with_capacity(total as usize);
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        progress.check()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..count]);
    }
    progress.record(
        name,
        &path.file_name().unwrap_or_default().to_string_lossy(),
    );
    Ok(data)
}

pub fn write(path: &Path, data: &[u8], progress: &Progress) -> Result<()> {
    let parent = path.parent().ok_or("目标文件缺少父目录")?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let step = progress.start("写入文件", data.len() as u64, "字节");
    step.detail(name.as_ref());
    let mut completed = 0;
    for chunk in data.chunks(1024 * 1024) {
        progress.check()?;
        temporary.write_all(chunk)?;
        completed += chunk.len();
        step.set(completed as u64);
    }
    temporary.as_file().sync_all()?;
    progress.check()?;
    temporary.persist(path)?;
    step.finish(format!("{name}；{} 字节", data.len()));
    Ok(())
}

impl Store {
    pub fn open(target: &Path, progress: &Progress) -> Result<Self> {
        let target = fs::canonicalize(target)?;
        let mut store = Self {
            target: target.clone(),
            files: BTreeMap::new(),
        };
        store.load(&target, progress)?;
        Ok(store)
    }

    pub fn load(&mut self, target: &Path, progress: &Progress) -> Result<&File> {
        let target = fs::canonicalize(target)?;
        let backup = self.backup(&target)?;
        Ok(match self.files.entry(target) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let file = File::open(entry.key(), backup, progress)?;
                entry.insert(file)
            }
        })
    }

    fn backup(&self, target: &Path) -> Result<PathBuf> {
        let directory = target.parent().ok_or("目标文件缺少父目录")?;
        if Some(directory) == self.target.parent() {
            return Ok(target.with_added_extension("bak"));
        }
        let name = target.file_name().ok_or("目标文件缺少名称")?;
        Ok(directory
            .join(install::version(target)?)
            .join(name)
            .with_added_extension("bak"))
    }

    pub fn write_error(&self, targets: &[PathBuf]) -> Option<String> {
        targets.iter().find_map(|target| {
            OpenOptions::new()
                .write(true)
                .open(target)
                .err()
                .map(|error| format!("无法写入 {}：{error}", display(target)))
        })
    }

    pub fn load_backups(&mut self, targets: &[PathBuf], progress: &Progress) -> Result<()> {
        for target in targets {
            if target.try_exists()? && self.backup(target)?.try_exists()? {
                self.load(target, progress)?;
            }
        }
        Ok(())
    }

    pub fn changed(&self) -> Vec<PathBuf> {
        self.files
            .iter()
            .filter(|(_, file)| file.current != file.original)
            .map(|(target, _)| target.clone())
            .collect()
    }

    pub fn originals(&self) -> BTreeMap<PathBuf, Content> {
        self.changed()
            .into_iter()
            .map(|target| {
                let data = self.files[&target].original.as_ref().clone();
                (
                    target,
                    Content {
                        data,
                        enabled: BTreeMap::new(),
                    },
                )
            })
            .collect()
    }

    pub fn save(
        &mut self,
        contents: BTreeMap<PathBuf, Content>,
        progress: &Progress,
    ) -> Result<()> {
        for (target, content) in contents {
            progress.check()?;
            self.files
                .get_mut(&target)
                .expect("file not loaded")
                .save(content, progress)?;
        }
        Ok(())
    }
}

impl File {
    fn open(target: &Path, backup: PathBuf, progress: &Progress) -> Result<Self> {
        let current = Arc::new(read(target, progress, "载入文件")?);
        let original = if backup.try_exists()? {
            Arc::new(read(&backup, progress, "载入文件")?)
        } else {
            current.clone()
        };
        Ok(Self {
            target: target.to_owned(),
            backup,
            current,
            original,
            enabled: BTreeMap::new(),
            issue: None,
        })
    }

    fn save(&mut self, content: Content, progress: &Progress) -> Result<()> {
        if self.current.as_slice() == content.data {
            return Ok(());
        }
        if read(&self.target, progress, "读取当前文件")?.as_slice() != self.current.as_slice()
        {
            return Err(format!("读取后目标文件发生了变化：{}", display(&self.target)).into());
        }
        if !self.backup.try_exists()? {
            fs::create_dir_all(self.backup.parent().ok_or("备份文件缺少父目录")?)?;
            write(&self.backup, &self.original, progress)?;
        }
        write(&self.target, &content.data, progress)?;
        self.current = Arc::new(content.data);
        self.enabled = content.enabled;
        self.issue = None;
        Ok(())
    }
}
