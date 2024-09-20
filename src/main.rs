use core::slice;
use std::{
    error::Error,
    ffi::{c_void, CStr, CString},
    mem,
};

use anyhow::anyhow;
use windows::{
    core::{s, PCSTR},
    Win32::{
        Foundation::{CloseHandle, BOOL, HWND, INVALID_HANDLE_VALUE, LPARAM},
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        UI::WindowsAndMessaging::{
            EnumThreadWindows, EnumWindows, FindWindowA, ShowWindow, HIDE_WINDOW, SHOW_WINDOW_CMD,
            SW_FORCEMINIMIZE, SW_HIDE, SW_MAXIMIZE, SW_SHOW, WNDENUMPROC,
        },
    },
};
use windows_hotkeys::{
    keys::{ModKey, VKey},
    singlethreaded::HotkeyManager,
    HotkeyManagerImpl,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_processes() {
        get_pid_of_exe("Telegram").unwrap();
    }
}

fn get_pid_of_exe(target_exe_name: &str) -> anyhow::Result<Vec<u32>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(anyhow!("invalid handle"));
    }

    let mut process_entry = PROCESSENTRY32::default();
    process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    unsafe { Process32First(snapshot, &mut process_entry) }?;

    let mut processes: Vec<u32> = vec![];

    loop {
        let string_parts: &[u8] =
            unsafe { slice::from_raw_parts(process_entry.szExeFile.as_ptr() as _, 260) };
        let exe_name = CStr::from_bytes_until_nul(&string_parts)?;

        if exe_name
            .to_str()?
            .to_lowercase()
            .contains(&target_exe_name.to_lowercase())
        {
            processes.push(process_entry.th32ProcessID);
        }

        process_entry = PROCESSENTRY32::default();
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

        match unsafe { Process32Next(snapshot, &mut process_entry) } {
            Ok(_) => {}
            Err(_) => {
                // No more processes.
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot) }?;

    println!(
        "Found process: {:?}, pid: {:?}",
        target_exe_name, &processes
    );

    Ok(processes)
}

fn enum_window_of_pid() -> anyhow::Result<()> {
    let handler = |handler: HWND| -> bool { false };

    enumerate_windows(handler);

    Ok(())
}

fn enumerate_windows<F>(mut callback: F)
where
    F: FnMut(HWND) -> bool,
{
    let mut trait_obj: &mut dyn FnMut(HWND) -> bool = &mut callback;
    let closure_pointer_pointer: *mut c_void = unsafe { mem::transmute(&mut trait_obj) };
    let result = unsafe {
        EnumWindows(
            Some(enumerate_callback),
            LPARAM(closure_pointer_pointer as _),
        )
    };
}

unsafe extern "system" fn enumerate_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let closure: &mut &mut dyn FnMut(HWND) -> bool = mem::transmute(lparam.0 as *mut c_void);
    if closure(hwnd) {
        BOOL(1)
    } else {
        BOOL(0)
    }
}

fn find_window(window_name: &str) -> anyhow::Result<()> {
    let window_name = format!("{}\0", window_name);
    let window_handle = unsafe { FindWindowA(PCSTR(window_name.as_ptr()), PCSTR::null()) }?;
    println!("Found Telegram window \n{:?}", window_handle);

    let result = unsafe { ShowWindow(window_handle, SW_HIDE) };
    println!("ShowWindow result: {:?}", result);

    Ok(())
}

fn start_event_loop() {
    let mut hkm = HotkeyManager::new();

    hkm.register(VKey::E, &[ModKey::Alt, ModKey::Ctrl], || {
        println!("Pressed Alt+Ctrl+E");
    })
    .expect("Failed to map");

    hkm.event_loop();
}

fn main() {
    let _ = find_window("Qt51515QWindowIcon");
}
