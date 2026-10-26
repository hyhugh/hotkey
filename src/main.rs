#![windows_subsystem = "windows"]

use core::slice;
use std::{
    env,
    ffi::{c_void, CStr},
    fs, mem,
    os::windows::ffi::OsStringExt,
    process::Command,
    sync::Arc,
};

use anyhow::anyhow;
use log::{debug, info};
use serde::Deserialize;
use simple_logger::SimpleLogger;
use windows::Win32::{
    Foundation::{CloseHandle, BOOL, HWND, INVALID_HANDLE_VALUE, LPARAM},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    },
    System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION},
    UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameA, GetForegroundWindow, GetParent, GetWindow,
        GetWindowModuleFileNameA, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsIconic,
        IsWindowVisible, SetForegroundWindow, SetWindowPlacement, ShowWindow, GW_OWNER,
        SW_FORCEMINIMIZE, SW_MINIMIZE, SW_RESTORE,
    },
};
use windows_hotkeys::{
    keys::{ModKey, VKey},
    singlethreaded::HotkeyManager,
    HotkeyManagerImpl,
};

fn get_pids_of_exe(target_exe_name: &str) -> anyhow::Result<Vec<u32>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(anyhow!("invalid handle"));
    }

    let mut process_entry = PROCESSENTRY32 {
        dwSize: mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    unsafe { Process32First(snapshot, &mut process_entry) }?;

    let mut processes: Vec<u32> = vec![];

    loop {
        let string_parts: &[u8] = unsafe {
            slice::from_raw_parts(
                process_entry.szExeFile.as_ptr() as _,
                process_entry.szExeFile.len(),
            )
        };
        let exe_name = CStr::from_bytes_until_nul(string_parts)?;

        if exe_name
            .to_str()?
            .to_lowercase()
            .contains(&target_exe_name.to_lowercase())
        {
            processes.push(process_entry.th32ProcessID);
        }

        process_entry = PROCESSENTRY32 {
            dwSize: mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        match unsafe { Process32Next(snapshot, &mut process_entry) } {
            Ok(_) => {}
            Err(_) => {
                // No more processes.
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot) }?;

    debug!(
        "Found process: {:?}, pid: {:?}",
        target_exe_name, &processes
    );

    Ok(processes)
}

fn get_class_name_of_window(hwnd: HWND) -> anyhow::Result<String> {
    let mut name_buffer: [u8; 256] = [0; 256];
    unsafe { GetClassNameA(hwnd, &mut name_buffer) };

    Ok(CStr::from_bytes_until_nul(&name_buffer)?.to_str()?.into())
}

fn has_parent(hwnd: HWND) -> bool {
    match unsafe { GetParent(hwnd) } {
        Ok(parent_hwnd) => {
            debug!("parent_hwnd: {:?}", parent_hwnd);
            parent_hwnd != hwnd
        }
        Err(err) => {
            debug!("GetParent error: {:?}", err);
            false
        }
    }
}

fn is_main_window(hwnd: HWND) -> bool {
    match unsafe { GetWindow(hwnd, GW_OWNER) } {
        Ok(owner_hwnd) => {
            debug!("owner_hwnd: {:?}", owner_hwnd);
            owner_hwnd != hwnd
        }
        Err(err) => {
            debug!("GetWindow error: {:?}", err);
            true
        }
    }
}

fn get_window_text(hwnd: HWND) -> anyhow::Result<String> {
    // Window titles are UTF-16. The ANSI API uses the system code page, which
    // cannot be decoded as UTF-8 when chat titles contain non-ASCII characters.
    let length = unsafe { GetWindowTextLengthW(hwnd) }.max(0) as usize;
    let mut text_buffer = vec![0u16; length + 1];
    let copied = unsafe { GetWindowTextW(hwnd, &mut text_buffer) } as usize;
    Ok(String::from_utf16_lossy(&text_buffer[..copied]))
}

fn get_window_module_file_name(hwnd: HWND) -> anyhow::Result<String> {
    let mut text_buffer: [u8; 256] = [0; 256];
    unsafe { GetWindowModuleFileNameA(hwnd, &mut text_buffer) };

    Ok(CStr::from_bytes_until_nul(&text_buffer)?.to_str()?.into())
}

fn toggle_window_visibility_of_pid(
    pid: u32,
    allowlisted_classes: &[String],
    excluded_window_texts: &[String],
) -> anyhow::Result<()> {
    let handler = move |hwnd: HWND| -> bool {
        let mut process_id: u32 = 0;

        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };

        if process_id == pid {
            debug!("Found window for pid \n{:?}", hwnd);

            let class_name = get_class_name_of_window(hwnd);
            let class_name = match class_name {
                Ok(name) => name,
                Err(_) => return true,
            };

            let window_text = get_window_text(hwnd);
            match window_text {
                Ok(text) => {
                    if excluded_window_texts.contains(&text) {
                        debug!("Excluded window text: {:?}", text);
                        return true;
                    }
                }
                Err(_) => {
                    // Ignore if failing to get text
                }
            };

            let window_module_file_name = get_window_module_file_name(hwnd);
            match window_module_file_name {
                Ok(file_name) => {
                    debug!("Found window module name: \n{:?}", file_name,);
                }
                Err(_) => {
                    // Ignore if failing to get module filename
                }
            }

            let has_parent = has_parent(hwnd);
            if has_parent {
                debug!("Has parent, skipping!");
                return true;
            }

            let is_main = is_main_window(hwnd);
            if !is_main {
                debug!("Not main window, skipping!");
                return true;
            }

            if !allowlisted_classes.contains(&class_name) {
                debug!("Not in allowlisted classes: {:?}", class_name);
                return true;
            }

            let is_visible = unsafe { IsWindowVisible(hwnd) };
            let is_minimised = unsafe { IsIconic(hwnd) };
            if !is_visible.as_bool() || is_minimised.as_bool() {
                // Closing a tray app can hide its window without minimizing it.
                // Restore both states before requesting foreground activation.
                let result = unsafe { ShowWindow(hwnd, SW_RESTORE) };
                debug!("ShowWindow(restore) result: {:?}", result);
                let result = unsafe { SetForegroundWindow(hwnd) };
                debug!("SetForegroundWindow(restore) result: {:?}", result);
            } else {
                let active_hwnd = unsafe { GetForegroundWindow() };
                let is_active = active_hwnd == hwnd;
                info!("Topmost: {:?}, {:?}, {:?}", is_active, active_hwnd, hwnd);

                if is_active {
                    debug!("Topmost window, minimizing!");
                    let result = unsafe { ShowWindow(hwnd, SW_MINIMIZE) };
                    debug!("ShowWindow(minimize) result: {:?}", result);
                } else {
                    let _ = unsafe { SetForegroundWindow(hwnd) };
                    info!("Not Topmost window, bringing to top!");
                }
            }
        }

        true
    };

    enumerate_windows(handler);

    Ok(())
}

// Single-instance tray apps need their own activation protocol to update their
// internal visibility state; showing their native HWND alone can leave it cloaked.
fn toggle_via_executable(
    pid: u32,
    allowlisted_classes: &[String],
    excluded_window_texts: &[String],
) -> anyhow::Result<()> {
    let hwnd = unsafe { GetForegroundWindow() };
    let mut foreground_pid = 0;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut foreground_pid)) };
    if foreground_pid == pid
        && allowlisted_classes.contains(&get_class_name_of_window(hwnd)?)
        && !excluded_window_texts.contains(&get_window_text(hwnd)?)
        && unsafe { IsWindowVisible(hwnd) }.as_bool()
        && !unsafe { IsIconic(hwnd) }.as_bool()
    {
        let _ = unsafe { ShowWindow(hwnd, SW_MINIMIZE) };
        return Ok(());
    }

    // Resolve the running executable, so portable app paths need no configuration.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }?;
    let mut path = vec![0u16; 32768];
    let mut length = path.len() as u32;
    let result = unsafe {
        QueryFullProcessImageNameW(
            process, PROCESS_NAME_WIN32, windows::core::PWSTR(path.as_mut_ptr()), &mut length,
        )
    };
    let close_result = unsafe { CloseHandle(process) };
    result?;
    close_result?;
    let path = std::ffi::OsString::from_wide(&path[..length as usize]);
    Command::new(path).spawn()?;
    Ok(())
}

fn enumerate_windows<F>(mut callback: F)
where
    F: FnMut(HWND) -> bool,
{
    let mut trait_obj: &mut dyn FnMut(HWND) -> bool = &mut callback;
    let closure_pointer_pointer: *mut c_void = unsafe { mem::transmute(&mut trait_obj) };
    let _ = unsafe {
        EnumWindows(
            Some(enumerate_callback),
            LPARAM(closure_pointer_pointer as _),
        )
    };
}

unsafe extern "system" fn enumerate_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    // Disable clippy here because it is too verbose to not use transmute.
    #[allow(clippy::transmute_ptr_to_ref)]
    let closure: &mut &mut dyn FnMut(HWND) -> bool = mem::transmute(lparam.0 as *mut c_void);
    if closure(hwnd) {
        BOOL(1)
    } else {
        BOOL(0)
    }
}

fn start_event_loop(config: &Config) {
    let mut hkm = HotkeyManager::new();

    for c in &(config.hotkeys) {
        let modifiers: Vec<ModKey> = c
            .modifiers
            .iter()
            .map(|k| {
                ModKey::from_keyname(k.to_uppercase().as_str())
                    .unwrap_or_else(|_| panic!("Unknown mod key {}", k))
            })
            .collect();
        let modifiers = Arc::new(modifiers);

        let trigger_key = VKey::from_char(c.trigger_key.chars().next().unwrap())
            .unwrap_or_else(|_| panic!("Unknown trigger key {}", c.trigger_key));

        let exe_name = c.exe_name.clone();
        let allowlisted_classes = c.allowlisted_classes.clone();
        let excluded_window_texts = c.excluded_window_texts.clone();
        let activate_via_exe = c.activate_via_exe;

        hkm.register(trigger_key, &modifiers.clone(), move || {
            debug!("Pressed {:?} + {:?}", modifiers, trigger_key);

            let pids = get_pids_of_exe(&exe_name).unwrap();
            for id in pids {
                let result = if activate_via_exe {
                    toggle_via_executable(id, &allowlisted_classes, &excluded_window_texts)
                } else {
                    toggle_window_visibility_of_pid(id, &allowlisted_classes, &excluded_window_texts)
                };
                if let Err(err) = result {
                    log::error!("Failed to toggle {} (pid {}): {}", exe_name, id, err);
                }
            }
        })
        .unwrap_or_else(|_| panic!("Failed to register hotkey {:?}", c));
    }

    hkm.event_loop();
}

#[derive(Deserialize, Debug)]
struct Config {
    hotkeys: Vec<Hotkey>,
}

#[derive(Deserialize, Debug)]
struct Hotkey {
    exe_name: String,
    trigger_key: String,
    modifiers: Vec<String>,
    allowlisted_classes: Vec<String>,
    excluded_window_texts: Vec<String>,
    #[serde(default)]
    activate_via_exe: bool,
}

fn main() {
    SimpleLogger::new().init().unwrap();

    // Collect the command-line arguments into a vector
    let args: Vec<String> = env::args().collect();

    // args[0] is the program name, so we check if there are additional arguments
    let config_path = if args.len() != 2 {
        "sample_config.toml"
    } else {
        debug!("Received argument: {}", args[1]);
        &args[1]
    };

    let config_str = fs::read_to_string(config_path).unwrap();
    let config: Config = toml::from_str(&config_str).unwrap();
    dbg!(&config);
    start_event_loop(&config);
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::{core::w, Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, SW_HIDE, WINDOW_EX_STYLE, WS_OVERLAPPEDWINDOW,
    }};

    #[test]
    fn restores_hidden_and_minimized_windows_without_bypassing_filters() {
        // Use a real, initially hidden Win32 window to exercise the tray state.
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(), w!("STATIC"), w!("Hotkey restore test 中文 — 📨"),
                WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, None, None, None, None,
            ).unwrap()
        };
        struct TestWindow(HWND);
        impl Drop for TestWindow {
            fn drop(&mut self) {
                let _ = unsafe { DestroyWindow(self.0) };
            }
        }
        let _window = TestWindow(hwnd);
        let title = "Hotkey restore test 中文 — 📨";
        assert_eq!(get_window_text(hwnd).unwrap(), title);
        let classes = vec![get_class_name_of_window(hwnd).unwrap()];
        let pid = std::process::id();
        assert!(!unsafe { IsWindowVisible(hwnd) }.as_bool());

        toggle_window_visibility_of_pid(pid, &[], &[]).unwrap();
        assert!(!unsafe { IsWindowVisible(hwnd) }.as_bool());
        toggle_window_visibility_of_pid(pid, &classes, &[title.into()]).unwrap();
        assert!(!unsafe { IsWindowVisible(hwnd) }.as_bool());

        toggle_window_visibility_of_pid(pid, &classes, &[]).unwrap();
        assert!(unsafe { IsWindowVisible(hwnd) }.as_bool());
        assert!(!unsafe { IsIconic(hwnd) }.as_bool());

        let _ = unsafe { ShowWindow(hwnd, SW_MINIMIZE) };
        assert!(unsafe { IsIconic(hwnd) }.as_bool());
        toggle_window_visibility_of_pid(pid, &classes, &[]).unwrap();
        assert!(!unsafe { IsIconic(hwnd) }.as_bool());
        let _ = unsafe { ShowWindow(hwnd, SW_HIDE) };
        toggle_window_visibility_of_pid(pid, &classes, &[]).unwrap();
        assert!(unsafe { IsWindowVisible(hwnd) }.as_bool());
    }
}
