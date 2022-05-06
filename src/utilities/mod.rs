use winapi::um::winbase::{
    LookupPrivilegeValueW,
};

use winapi::um::processthreadsapi::{
    OpenProcessToken, 
    GetCurrentProcess,
};

use winapi::um::securitybaseapi::{
    AdjustTokenPrivileges, 
    GetTokenInformation,
};

use winapi::um::handleapi::CloseHandle;

use winapi::um::winnt::{
    TOKEN_ADJUST_PRIVILEGES, 
    SE_PRIVILEGE_ENABLED, 
    TOKEN_PRIVILEGES, 
    TOKEN_QUERY,
    HANDLE, 
    TOKEN_ELEVATION,
    TokenElevation,
};

use winapi::shared::minwindef::FALSE;

use crate::pivioting::scm::PSExec;

use std::io::Error;
use std::ptr::null_mut;
use anyhow::Result;

use std::io::{
    stdin,
    stdout,
    Write
};

const SE_DEBUG_NAME: [u16 ; 17] = [83u16, 101, 68, 101, 98, 117, 103, 80, 114, 105, 118, 105, 108, 101, 103, 101, 0];

pub struct Utils;

impl Utils {
    pub fn enable_debug_privilege() -> (bool, String) {
        unsafe {
            let mut token = null_mut();
            let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();

            privilege.PrivilegeCount = 1;
            privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            let result = LookupPrivilegeValueW(null_mut(), SE_DEBUG_NAME.as_ptr(), &mut privilege.Privileges[0].Luid);
            if result == FALSE {
                return (false, format!("[x] LookupPrivilege Error: {}", Error::last_os_error()));
            } else {
                let res = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token);
                if res == FALSE {
                    return (false, format!("[x] OpenProcessToken Error: {}", Error::last_os_error()));
                } else {
                    let token_adjust = AdjustTokenPrivileges(token, FALSE, &mut privilege, std::mem::size_of_val(&privilege) as u32, null_mut(), null_mut());
                    if token_adjust == FALSE {
                        return (false, format!("[x] AdjustTokenPrivileges Error: {}", Error::last_os_error()));
                    } else {
                        let close_handle = CloseHandle(token);
                        if close_handle == FALSE {
                            return (false, format!("[x] CloseHandle Error: {}", Error::last_os_error()));
                        } else {
                            return (true, format!("[!] Trying to enable debug privileges"));
                        }
                    }
                }
            }
        }
    }

    pub fn is_elevated() -> bool {
        let mut h_token: HANDLE = null_mut();
        let mut token_ele: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size: u32 = 0u32;
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h_token);
            GetTokenInformation(
                h_token,
                TokenElevation,
                &mut token_ele as *const _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            return token_ele.TokenIsElevated == 1;
        }
    }

    pub fn is_system() -> bool {
        if format!("{}", whoami::username()).to_lowercase() == "system" {
            return true;
        }
        return false;
    }

    pub fn get_user_input(addition: Option<String>) -> Vec<String> {
        let mut s = String::new();
        let mut result: Vec<String> = vec![];
        let perm = get_permission_status();
    
        match perm {
            0 => {
                //System: @
    
                if let Some(addition) = addition {
                    print!("{}", format!("mimiRust::{} @ ", addition));
                } else {
                    print!("mimiRust @ ");
                }
            },
            1 => {
                //Admin: #
                if let Some(addition) = addition {
                    print!("{}", format!("mimiRust::{} # ", addition));
                } else {
                    print!("mimiRust # ");
                }
            },
            _ => {
                //User: $
                if let Some(addition) = addition {
                    print!("{}", format!("mimiRust::{} $ ", addition));
                } else {
                    print!("mimiRust $ ");
                }
            },
        };
    
        let _=stdout().flush();
        stdin().read_line(&mut s).expect("Did not enter correct characters");
        if let Some('\n')=s.chars().next_back() {
            s.pop();
        }
        if let Some('\r')=s.chars().next_back() {
            s.pop();
        }
        
        for string in s.split(" ") {
            result.push(string.to_string());
        }
    
        return result;
    }

    pub fn parse_arguments(full_input: Vec<String>, poss_args: Vec<&str>, enf_args: Vec<String>) -> PSExec {
        let mut found_args = vec![];

        for arg in full_input {
            if arg.starts_with("/") && arg.contains(":") {
                let split_symbol: char = ':';
                let (command, argument) = arg.split_at(get_first_char_offset(arg.clone(), split_symbol));

                for poss_arg in &poss_args {
                    if command[1..].to_string() == poss_arg.to_string() {
                        found_args.push(vec![command[1..].to_string(), argument[1..].to_string()]);
                    }
                }
            }
        }

        if enforced_present(found_args.clone(), enf_args.clone()) {
            return PSExec {
                computer_name: handle_it(found_args.clone(), "computer".to_string()),
                binary_path: handle_it(found_args.clone(), "binary_path".to_string()),
                service_name: handle_it(found_args.clone(), "sn".to_string()),
                display_name: handle_it(found_args.clone(), "sdn".to_string()),
                username: handle_it(found_args.clone(), "user".to_string()),
                password: handle_it(found_args.clone(), "pass".to_string()),
            }
        } else {
            println!("[*] PSExec works as follows: psexec /computer:<computername> /binary_path:<binary_path> /sn:<optional service name> /sdn:<optional service display name> /user:<optional domain\\username> /pass:<optional password of domain\\username>");
        }
        PSExec {
            computer_name: String::from(""),
            binary_path: String::from(""),
            service_name: String::from(""),
            display_name: String::from(""),
            username: String::from(""),
            password: String::from(""),
        }
    }

}

fn handle_it(input: Vec<Vec<String>>, expected: String) -> String {

    for indexes in input {
        if indexes[0] == expected {
            return indexes[1].clone();
        }
    }

    String::from("")
}

fn enforced_present(input_vector: Vec<Vec<String>>, enf_args: Vec<String>) -> bool {
    let mut counter = 0;

    for indexes in input_vector {
        for enf_arg in &enf_args {
            if indexes[0].to_string() == enf_arg.to_string() {
                if indexes[1].len() > 0 {
                    counter += 1;
                }
            }
        }
    }

    if counter == enf_args.len() {
        return true;
    }

    false
}

fn get_permission_status() -> i32 {
    if Utils::is_elevated() {
        if Utils::is_system() {
            return 0;
        }
        return 1;
    } else {
        return 2;
    }
}

fn get_first_char_offset(input: String, target_character: char) -> usize {
    let mut offset = 0;

    for i in input.chars() {
        if i == target_character {
            return offset;
        } else {
            offset += 1;
        }
    }
    
    offset
}