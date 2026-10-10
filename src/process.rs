use std::{
    ffi::OsString,
    io,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::PathBuf,
    ptr::{null, null_mut},
};

use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, FILETIME, WAIT_FAILED, WAIT_OBJECT_0},
    System::{
        RestartManager::{
            CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
            RmStartSession,
        },
        Threading::{
            GetProcessTimes, INFINITE, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
        },
    },
};

use crate::{Result, progress::Progress};

struct Session(u32);

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { RmEndSession(self.0) };
    }
}

pub struct Process {
    handle: OwnedHandle,
    pub id: u32,
    pub name: String,
}

impl Process {
    pub fn description(&self) -> String {
        format!("{}（PID {}）", self.name, self.id)
    }

    pub fn terminate(&self, progress: &Progress) -> Result<()> {
        let handle = self.handle.as_raw_handle();
        if unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0 {
            return Ok(());
        }
        let step = progress.activity("结束占用进程");
        step.detail(self.description());
        if unsafe { TerminateProcess(handle, 0) } == 0 {
            return Err(format!(
                "无法结束 {}：{}",
                self.description(),
                io::Error::last_os_error()
            )
            .into());
        }
        if unsafe { WaitForSingleObject(handle, INFINITE) } == WAIT_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        step.finish(self.description());
        Ok(())
    }
}

pub fn using(paths: &[PathBuf]) -> Result<Vec<Process>> {
    let mut handle = 0;
    let mut key = [0; CCH_RM_SESSION_KEY as usize + 1];
    let error = unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32).into());
    }
    let session = Session(handle);
    let paths: Vec<Vec<u16>> = paths
        .iter()
        .map(|path| {
            Ok(path
                .canonicalize()?
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect())
        })
        .collect::<Result<_>>()?;
    let pointers: Vec<_> = paths.iter().map(|path| path.as_ptr()).collect();
    let error = unsafe {
        RmRegisterResources(
            session.0,
            pointers.len() as u32,
            pointers.as_ptr(),
            0,
            null(),
            0,
            null(),
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32).into());
    }
    let mut entries: Vec<RM_PROCESS_INFO> = Vec::new();
    loop {
        let mut needed = 0;
        let mut count = entries.len() as u32;
        let mut reasons = 0;
        let buffer = if entries.is_empty() {
            null_mut()
        } else {
            entries.as_mut_ptr()
        };
        let error = unsafe { RmGetList(session.0, &mut needed, &mut count, buffer, &mut reasons) };
        if error == ERROR_MORE_DATA {
            entries.resize_with(needed as usize, || unsafe { std::mem::zeroed() });
            continue;
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32).into());
        }
        entries.truncate(count as usize);
        break;
    }
    let mut processes = Vec::new();
    for entry in entries {
        let id = entry.Process.dwProcessId;
        let name: Vec<u16> = entry
            .strAppName
            .into_iter()
            .take_while(|unit| *unit != 0)
            .collect();
        let name = OsString::from_wide(&name).to_string_lossy().into_owned();
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                0,
                id,
            )
        };
        if handle.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                continue;
            }
            return Err(format!("无法访问 {name}（PID {id}）：{error}").into());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut created: FILETIME = unsafe { std::mem::zeroed() };
        let mut exited = created;
        let mut kernel = created;
        let mut user = created;
        if unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if created.dwLowDateTime == entry.Process.ProcessStartTime.dwLowDateTime
            && created.dwHighDateTime == entry.Process.ProcessStartTime.dwHighDateTime
        {
            processes.push(Process { handle, id, name });
        }
    }
    Ok(processes)
}
