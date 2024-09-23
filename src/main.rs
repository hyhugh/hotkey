#![windows_subsystem = "windows"]

use core::slice;
use std::{
    env,
    ffi::{c_void, CStr},
    fs, mem,
};

use anyhow::anyhow;
use log::debug;
use serde::Deserialize;
use simple_logger::SimpleLogger;
use windows::Win32::{
    Foundation::{CloseHandle, BOOL, HWND, INVALID_HANDLE_VALUE, LPARAM},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    },
    UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameA, GetParent, GetWindow, GetWindowModuleFileNameA, GetWindowTextA,
        GetWindowThreadProcessId, IsIconic, IsWindowVisible, ShowWindow, GW_OWNER, SW_MINIMIZE,
        SW_RESTORE,
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

    let mut process_entry = PROCESSENTRY32::default();
    process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    unsafe { Process32First(snapshot, &mut process_entry) }?;

    let mut processes: Vec<u32> = vec![];

    loop {
        let string_parts: &[u8] = unsafe {
            slice::from_raw_parts(
                process_entry.szExeFile.as_ptr() as _,
                process_entry.szExeFile.len(),
            )
        };
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
    let mut text_buffer: [u8; 256] = [0; 256];
    unsafe { GetWindowTextA(hwnd, &mut text_buffer) };

    Ok(CStr::from_bytes_until_nul(&text_buffer)?.to_str()?.into())
}

fn get_window_module_file_name(hwnd: HWND) -> anyhow::Result<String> {
    let mut text_buffer: [u8; 256] = [0; 256];
    unsafe { GetWindowModuleFileNameA(hwnd, &mut text_buffer) };

    Ok(CStr::from_bytes_until_nul(&text_buffer)?.to_str()?.into())
}

fn toggle_window_visibility_of_pid(
    pid: u32,
    allowlisted_classes: &Vec<String>,
    excluded_window_texts: &Vec<String>,
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
            if !is_visible.as_bool() {
                debug!("Not visible, skipping!");
                return true;
            }

            let is_minimised = unsafe { IsIconic(hwnd) };
            if !is_minimised.as_bool() {
                let result = unsafe { ShowWindow(hwnd, SW_MINIMIZE) };
                debug!("ShowWindow(hide) result: {:?}", result);
            } else {
                // Window is minimized.
                let result = unsafe { ShowWindow(hwnd, SW_RESTORE) };
                debug!("ShowWindow(restore) result: {:?}", result);
            }
        }

        true
    };

    enumerate_windows(handler);

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
                    .expect(format!("Unknown mod key {}", k).as_str())
            })
            .collect();
        let trigger_key = VKey::from_char(c.trigger_key.chars().next().unwrap())
            .expect(format!("Unknown trigger key {}", c.trigger_key).as_str());
        let exe_name = c.exe_name.clone();
        let allowlisted_classes = c.allowlisted_classes.clone();
        let excluded_window_texts = c.excluded_window_texts.clone();

        hkm.register(trigger_key, &(modifiers.clone()), move || {
            debug!("Pressed {:?} + {:?}", modifiers, trigger_key);

            let pids = get_pids_of_exe(&exe_name).unwrap();
            for id in pids {
                let _ = toggle_window_visibility_of_pid(
                    id,
                    &allowlisted_classes,
                    &excluded_window_texts,
                );
            }
        })
        .expect(format!("Failed to register hotkey {:?}", c).as_str());
    }

    hkm.event_loop();
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
}
