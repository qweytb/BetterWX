use std::path::PathBuf;

use crate::Result;

#[cfg(windows)]
pub fn pick(title: &str, filters: Vec<(&str, &str)>) -> Result<Option<PathBuf>> {
    use std::sync::Once;

    use windows_sys::Win32::UI::WindowsAndMessaging::SetProcessDPIAware;

    static INIT: Once = Once::new();
    INIT.call_once(|| unsafe {
        SetProcessDPIAware();
    });
    let result = wfd::open_dialog(wfd::DialogParams {
        title,
        file_types: filters,
        options: wfd::FOS_PATHMUSTEXIST | wfd::FOS_FILEMUSTEXIST | wfd::FOS_STRICTFILETYPES,
        ..Default::default()
    });
    let error = match result {
        Ok(result) => return Ok(Some(result.selected_file_path)),
        Err(wfd::DialogError::UserCancelled) => return Ok(None),
        Err(wfd::DialogError::HResultFailed { error_method, .. }) => error_method,
        Err(wfd::DialogError::UnsupportedFilepath) => "Unsupported filepath".to_owned(),
    };
    Err(format!("other errors reported by implementation: {error}").into())
}

#[cfg(not(windows))]
pub fn pick(_title: &str, _filters: Vec<(&str, &str)>) -> Result<Option<PathBuf>> {
    Err("系统文件选择器需要 Windows".into())
}
