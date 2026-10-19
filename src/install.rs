use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

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
pub fn version(path: &Path) -> Result<String> {
    use std::{io, os::windows::ffi::OsStrExt, ptr::null_mut};

    use windows_sys::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
    };

    let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), null_mut()) };
    if size == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut data = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, data.as_mut_ptr().cast()) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut value = null_mut();
    let mut length = 0;
    if unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            [u16::from(b'\\'), 0].as_ptr(),
            &mut value,
            &mut length,
        )
    } == 0
        || value.is_null()
        || (length as usize) < size_of::<VS_FIXEDFILEINFO>()
    {
        return Err("无法读取文件版本".into());
    }
    let version = unsafe { value.cast::<VS_FIXEDFILEINFO>().read_unaligned() };
    Ok(format!(
        "{}.{}.{}.{}",
        version.dwFileVersionMS >> 16,
        version.dwFileVersionMS & 0xffff,
        version.dwFileVersionLS >> 16,
        version.dwFileVersionLS & 0xffff,
    ))
}

#[cfg(not(windows))]
pub fn version(_path: &Path) -> Result<String> {
    Err("读取系统文件版本需要 Windows".into())
}

#[cfg(windows)]
pub fn pick() -> Result<Option<PathBuf>> {
    Ok(native_dialog::DialogBuilder::file()
        .set_title("手动选择")
        .add_filter("动态库", ["dll"])
        .open_single_file()
        .show()?)
}

#[cfg(not(windows))]
pub fn pick() -> Result<Option<PathBuf>> {
    Err("系统文件选择器需要 Windows".into())
}
