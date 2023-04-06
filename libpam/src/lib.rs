
use crypto_box::{
    aead::{Aead, AeadCore, Payload, OsRng},
    ChaChaBox, PublicKey, SecretKey
};
use pamsm::{PamServiceModule, Pam, PamFlags, PamError};
use pamsm::{pam_module, PamLibExt, PamMsgStyle};

use qrcode::QrCode;
use qrcode::render::unicode;

use std::io::Read;
use std::io::BufReader;
use std::fs::File;
use rand::Rng;
use rand::distributions::Alphanumeric;
use std::path::PathBuf;
use qrcode::types::QrError;
use std::str::Utf8Error;
use std::array::TryFromSliceError;

use base64::{Engine as _, engine::{general_purpose}};
use std::collections::HashMap;
use std::num::ParseIntError;


struct PamSMC;

#[derive(Debug)]
enum PamSMCError {
    IO(std::io::Error),
    Crypto(crypto_box::aead::Error),
    UTF8(Utf8Error),
    Pam(PamError),
    TryFromSlice(TryFromSliceError),
    QR(QrError),
    MaxTries,
    PasswordAttemptsArgParseError(ParseIntError),
}

impl std::convert::From<PamSMCError> for PamError {
    fn from(inner: PamSMCError) -> PamError {
        match inner {
            PamSMCError::MaxTries => PamError::MAXTRIES,
            PamSMCError::Pam(e) => e,
            _ => PamError::AUTH_ERR,
        }
    }
}

impl std::convert::From<PamError> for PamSMCError {
    fn from(inner: PamError) -> PamSMCError {
        PamSMCError::Pam(inner)
    }
}

impl std::convert::From<QrError> for PamSMCError {
    fn from(inner: QrError) -> PamSMCError {
        PamSMCError::QR(inner)
    }
}

impl std::convert::From<TryFromSliceError> for PamSMCError {
    fn from(inner: TryFromSliceError) -> PamSMCError {
        PamSMCError::TryFromSlice(inner)
    }
}

impl std::convert::From<std::io::Error> for PamSMCError {
    fn from(inner: std::io::Error) -> PamSMCError {
        PamSMCError::IO(inner)
    }
}

impl std::convert::From<crypto_box::aead::Error> for PamSMCError {
    fn from(inner: crypto_box::aead::Error) -> PamSMCError {
        PamSMCError::Crypto(inner)
    }
}

impl std::convert::From<Utf8Error> for PamSMCError {
    fn from(inner: Utf8Error) -> PamSMCError {
        PamSMCError::UTF8(inner)
    }
}

fn read_key<T: Into<PathBuf>>(path: T) -> Result<[u8; 32], PamSMCError> {
    let f = File::open(path.into())?;
    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();

    reader.read_to_end(&mut buffer)?;
    Ok(buffer.as_slice().try_into()?)
}

fn parse_args(args: Vec<String>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for a in args {
        let parts: Vec<&str> = a.split('=').collect();
        if let Some(key) = parts.get(0) {
            map.insert(key.to_string(), parts.get(1).unwrap_or(&"").to_string());
        }
    }
    map
}

impl PamServiceModule for PamSMC {
    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
    fn authenticate(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        match || -> Result<(), PamSMCError> {
            let username = pamh.get_user(None)?.ok_or(PamError::AUTH_ERR)?;

            let kv_args = parse_args(args);
            let key_dir = PathBuf::from(kv_args.get("key_dir").unwrap_or(&"/var/secrets".to_string()));
            let server_private_key_path = key_dir.join("server.private");
            let user_public_key_path = key_dir.join(&format!("{}.public", username.to_str()?));

            let key = read_key(server_private_key_path)?;
            let server_secret_key = SecretKey::from(key);

            let key = read_key(user_public_key_path)?;
            let user_public_key = PublicKey::from(key);

            let user_public_key_bytes = user_public_key.as_bytes().clone();
            
            let user_public_key = PublicKey::from(user_public_key_bytes);
            let encryption_box = ChaChaBox::new(&user_public_key, &server_secret_key);
            let nonce = ChaChaBox::generate_nonce(&mut OsRng);
        
            let challenge: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(6)
                .map(char::from)
                .collect();

            let challenge = challenge.to_lowercase();

            // Message to encrypt
            let associated_data = b"".as_ref();
        
            // Encrypt the message using the box
            let ciphertext = encryption_box.encrypt(&nonce, Payload {
                msg: challenge.as_bytes(), // your message to encrypt
                aad: associated_data, // not encrypted, but authenticated in tag
            })?; //TODO: don't panic
        
            let b64 = general_purpose::STANDARD;
            let b64_ciphertext = b64.encode(ciphertext);
            let b64_nonce = b64.encode(nonce);
            
            let code_data = format!("{}:{}", b64_ciphertext, b64_nonce);

            let code = QrCode::new(&code_data)?;
            let image = code.render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .build();

            pamh.conv(Some(&image), PamMsgStyle::TEXT_INFO)?;
            pamh.conv(Some(&format!("Challenge: {}", code_data)), PamMsgStyle::TEXT_INFO)?;

            let mut attempts = 0;
            let max_attempts: u8 = kv_args.get("attempts").unwrap_or(&"3".to_string()).parse().map_err(|e| PamSMCError::PasswordAttemptsArgParseError(e))?;
            while attempts < max_attempts {
                let passcode = pamh.conv(Some("One-time passcode: "), PamMsgStyle::PROMPT_ECHO_ON)?.ok_or(PamError::AUTH_ERR)?;
                if passcode.to_str().map_err(|_| PamError::AUTH_ERR)? == challenge {
                    return Ok(())
                } else {
                    pamh.conv(Some(&format!("Sorry, try again.")), PamMsgStyle::TEXT_INFO)?;
                    attempts=attempts+1;
                }
            }
            pamh.conv(Some(&format!("Too many incorrect attempts")), PamMsgStyle::TEXT_INFO)?;
            Err(PamSMCError::MaxTries)
        }() {
            Ok(_) => PamError::SUCCESS,
            Err(e) => e.into(),
        }
    }
}

pam_module!(PamSMC);
