use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use tempfile::NamedTempFile;

use crate::{Result, progress::Progress};

pub struct Store {
    target: PathBuf,
    backup: PathBuf,
    pub current: Arc<Vec<u8>>,
    pub original: Arc<Vec<u8>>,
    pub enabled: BTreeSet<String>,
}

fn read(path: &Path, progress: &Progress, name: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let total = file.metadata()?.len();
    let step = progress.start(name, total, "字节");
    step.detail(path.display().to_string());
    let mut data = Vec::with_capacity(total as usize);
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        progress.check()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..count]);
        step.set(data.len() as u64);
    }
    step.finish(format!(
        "{} 已载入",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    Ok(data)
}

fn write(path: &Path, data: &[u8], progress: &Progress) -> Result<()> {
    let parent = path.parent().ok_or("目标文件缺少父目录")?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let step = progress.start(format!("写入 {name}"), data.len() as u64, "字节");
    step.detail(path.display().to_string());
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
    step.finish(format!("{name} 已写入"));
    Ok(())
}

impl Store {
    pub fn open(target: &Path, progress: &Progress) -> Result<Self> {
        let target = fs::canonicalize(target)?;
        let current = Arc::new(read(&target, progress, "载入文件")?);
        let backup = target.with_added_extension("bak");
        let original = if backup.try_exists()? {
            Arc::new(read(&backup, progress, "载入原始副本")?)
        } else {
            current.clone()
        };
        Ok(Self {
            target,
            backup,
            current,
            original,
            enabled: BTreeSet::new(),
        })
    }

    pub fn write_error(&self) -> Option<String> {
        OpenOptions::new()
            .write(true)
            .open(&self.target)
            .err()
            .map(|error| format!("无法写入文件：{error}"))
    }

    pub fn save(
        &mut self,
        output: Vec<u8>,
        enabled: BTreeSet<String>,
        progress: &Progress,
    ) -> Result<()> {
        if read(&self.target, progress, "读取当前文件")?.as_slice() != self.current.as_slice()
        {
            return Err(format!("读取后目标文件发生了变化：{}", self.target.display()).into());
        }
        if !self.backup.try_exists()? {
            write(&self.backup, &self.original, progress)?;
        }
        write(&self.target, &output, progress)?;
        self.current = Arc::new(output);
        self.enabled = enabled;
        Ok(())
    }
}
