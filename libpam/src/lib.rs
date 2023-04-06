
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


struct PamSMC;

#[derive(Debug)]
enum PamSMCError {
    IO(std::io::Error),
    Crypto(crypto_box::aead::Error),
    UTF8(Utf8Error),
    Pam(PamError),
    TryFromSlice(TryFromSliceError),
    TryAgain,
    QR(QrError),
}

impl std::convert::From<PamSMCError> for PamError {
    fn from(inner: PamSMCError) -> PamError {
        match inner {
            PamSMCError::TryAgain => PamError::CONV_AGAIN,
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

impl PamServiceModule for PamSMC {
    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
    fn authenticate(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        match || -> Result<(), PamSMCError> {
            let username = pamh.get_user(None)?.ok_or(PamError::AUTH_ERR)?;

            println!("{:?}", args);

            let key = read_key("/var/secrets/smartconsole.server.private")?;
            let server_secret_key = SecretKey::from(key);

            let key = read_key(&format!("/var/secrets/{}.public", &username.to_str()?))?;
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

            let passcode = pamh.conv(Some("One-time passcode: "), PamMsgStyle::PROMPT_ECHO_ON)?.ok_or(PamError::AUTH_ERR)?;
            if passcode.to_str().map_err(|_| PamError::AUTH_ERR)? == challenge {
                Ok(())
            } else {
                Err(PamSMCError::TryAgain)
            }
        }() {
            Ok(_) => PamError::SUCCESS,
            Err(e) => e.into(),
        }
    }
}

pam_module!(PamSMC);
