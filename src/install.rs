use std::{fs, io::ErrorKind, path::PathBuf};

use crate::Result;

#[cfg(windows)]
fn directory() -> Result<Option<PathBuf>> {
    use winreg::{RegKey, enums::HKEY_CURRENT_USER};

    let key = match RegKey::predef(HKEY_CURRENT_USER).open_subkey("Software\\Tencent\\Weixin") {
        Ok(key) => key,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(Some(PathBuf::from(
        key.get_value::<String, _>("InstallPath")?,
    )))
}

#[cfg(not(windows))]
fn directory() -> Result<Option<PathBuf>> {
    Ok(None)
}

pub fn scan() -> Result<Vec<PathBuf>> {
    let mut versions = Vec::new();
    let Some(directory) = directory()? else {
        return Ok(Vec::new());
    };
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(version) = name
            .split('.')
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
        else {
            continue;
        };
        let file = entry.path().join("Weixin.dll");
        if version.len() == 4 && file.is_file() {
            versions.push((version, file));
        }
    }
    versions.sort_by(|left, right| right.0.cmp(&left.0));
    Ok(versions.into_iter().map(|(_, file)| file).collect())
}

#[cfg(windows)]
pub fn pick() -> Result<Option<PathBuf>> {
    Ok(native_dialog::DialogBuilder::file()
        .set_title("选择文件")
        .add_filter("动态库", ["dll"])
        .open_single_file()
        .show()?)
}

#[cfg(not(windows))]
pub fn pick() -> Result<Option<PathBuf>> {
    Err("系统文件选择器需要 Windows".into())
}
