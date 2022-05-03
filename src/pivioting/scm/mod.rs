use std::io::Error;
use std::ptr::null;
use std::ffi::CString;

use winapi::um::winsvc::{
    OpenSCManagerA,
    SC_HANDLE__,
    CreateServiceA,
    SERVICE_ALL_ACCESS,
    OpenServiceA,
    DeleteService,
    CloseServiceHandle,
    SC_MANAGER_ALL_ACCESS,
};

use winapi::um::winnt::{
    SERVICE_WIN32_OWN_PROCESS,
    SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL,
};

#[derive(Debug, Clone)]
pub struct PSExec {
    pub computer_name: String,
    pub binary_path: String,
    pub service_name: String,
    pub display_name: String,
    pub username: String,
    pub password: String,
}   

impl PSExec {
    pub fn new(input_computer_name: String, input_binary_path: String, input_service_name: Option<String>, input_display_name: Option<String>, input_username: Option<String>, input_password: Option<String>) -> Self {
        if let Some(input_service_name) = input_service_name {
            if let Some(input_display_name) = input_display_name {
                if let Some(input_username) = input_username {
                    if let Some(input_password) = input_password {
                        return Self {
                            computer_name: input_computer_name,
                            binary_path: input_binary_path,
                            service_name: input_service_name,
                            display_name: input_display_name,
                            username: input_username,
                            password: input_password,
                        }
                    }
                }
                return Self {
                    computer_name: input_computer_name,
                    binary_path: input_binary_path,
                    service_name: input_service_name,
                    display_name: input_display_name,
                    username: "".to_string(),
                    password: "".to_string(),
                }
            }
            return Self {
                computer_name: input_computer_name,
                binary_path: input_binary_path,
                service_name: input_service_name,
                display_name: "mimiRust Service".to_string(),
                username: "".to_string(),
                password: "".to_string(),
            }
        }
        Self {
            computer_name: input_computer_name,
            binary_path: input_binary_path,
            service_name: "mimiRust".to_string(),
            display_name: "mimiRust Service".to_string(),
            username: "".to_string(),
            password: "".to_string(),
        }
    }   

    //Need a better way to actually start process.
    //Now you need to start the process by doing; shell sc \\TARGET-HOST start TARGET-SERVICE
    //Will also have to make it non-blocking.

    pub fn execute(config: Self) -> bool {
        let handle_service_manager = open_service_manager(config.computer_name.clone());
        let handle_service = get_service_handle(handle_service_manager, config.service_name.clone());

        if config.username.clone().len() > 0 && config.password.clone().len() < 1 {
            println!("[!] You cannot authenticate a user without it's password");
            return false;
        } else if config.username.clone().len() < 1 && config.password.clone().len() > 0 {
            println!("[!] You cannot authenticate a user without it's username");
        }

        if handle_service != 0 as *mut SC_HANDLE__ {
            if delete_service(handle_service) {
                close_handle(handle_service);
            }
        }

        if create_service(handle_service_manager, config.service_name.clone(), config.display_name.clone(), config.binary_path.clone(), config.username.clone(), config.password.clone()) {
            println!("[+] Created service at: {} with name: {} and binary path: {}", config.computer_name.clone(), config.service_name.clone(), config.binary_path.clone());
            return true;
        } else {
            println!("[-] Creation of service failed: {}", Error::last_os_error());
        }
        false
    }
}

fn open_service_manager(computer_name: String) -> *mut SC_HANDLE__ {
    unsafe {
        let cstring = CString::new(computer_name).unwrap();
        let handle: *mut SC_HANDLE__ = OpenSCManagerA(cstring.as_ptr(), null(), SC_MANAGER_ALL_ACCESS);
        if handle == 0 as *mut SC_HANDLE__ {
            println!("[!] Failed to open service manager with error: {:?}", Error::last_os_error());
            std::process::exit(0x100);
        }
        return handle;
    }
}

fn create_service(service_manager_handle: *mut SC_HANDLE__, service_name: String, display_name: String, binary_path: String, username: String, password: String) -> bool {
    unsafe {

        let cstring_service_name = CString::new(service_name).unwrap();
        let cstring_display_name = CString::new(display_name).unwrap();
        let cstring_binary_path = CString::new(format!("{}",binary_path)).unwrap();

        if username.len() > 0 && password.len() > 0 {

            let cstring_username = CString::new(username).unwrap();
            let cstring_password = CString::new(password).unwrap();

            let handle = CreateServiceA(
                service_manager_handle,
                cstring_service_name.as_ptr(),
                cstring_display_name.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                cstring_binary_path.as_ptr(),
                null(),
                0 as *mut u32,
                null(),
                cstring_username.as_ptr(),
                cstring_password.as_ptr(),
            );

            if handle == 0 as *mut SC_HANDLE__ {
                return false;
            }
        } else {
            let handle = CreateServiceA(
                service_manager_handle,
                cstring_service_name.as_ptr(),
                cstring_display_name.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                cstring_binary_path.as_ptr(),
                null(),
                0 as *mut u32,
                null(),
                null(),
                null(),
            );

            if handle == 0 as *mut SC_HANDLE__ {
                return false;
            }
        }

        true
    }
}

fn get_service_handle(service_manager_handle: *mut SC_HANDLE__, service_name: String) -> *mut SC_HANDLE__ {
    let cstring_service_name = CString::new(service_name).unwrap();
    unsafe {return OpenServiceA(service_manager_handle, cstring_service_name.as_ptr(), 0x10000);}
}

fn delete_service(service_manager_handle: *mut SC_HANDLE__) -> bool {
    unsafe {
        if DeleteService(
            service_manager_handle
        ) != 0 {
            return true;
        }
    }
    return false;
}

fn close_handle(handle_to_close: *mut SC_HANDLE__) -> bool {
    unsafe {
        if CloseServiceHandle(handle_to_close) == 1 {
            return true;
        }
        return false;
    }
}