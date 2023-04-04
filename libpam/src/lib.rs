
use crypto_box::{
    aead::{Aead, AeadCore, Payload, OsRng},
    ChaChaBox, PublicKey, SecretKey
};
use pamsm::{PamServiceModule, Pam, PamFlags, PamError};
use pamsm::{pam_module, PamLibExt, PamMsgStyle};
use std::ffi::CString;

use qrcode::QrCode;
use qrcode::render::unicode;

use std::io::{Read, Write};
use std::io::BufReader;
use std::fs::File;
use rand::Rng;
use rand::distributions::Alphanumeric;


struct PamPlat;

impl PamServiceModule for PamPlat {
    fn setcred(pamh: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
    fn authenticate(pamh: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        match || -> Result<(), PamError> {
/*            
            let alice_secret_key = SecretKey::generate(&mut OsRng);
            let bob_secret_key = SecretKey::generate(&mut OsRng);
            let bob_public_key = bob_secret_key.public_key();
*/          
            let username = pamh.get_user(None)?.ok_or(PamError::AUTH_ERR)?;

            let f = File::open("server.private").unwrap();
            let mut reader = BufReader::new(f);
            let mut buffer = Vec::new();
            
            // Read file into vector.
            reader.read_to_end(&mut buffer).unwrap();
            let bytes: [u8; 32] = buffer.as_slice().try_into().unwrap();
            let alice_secret_key = SecretKey::from(bytes);

            let f = File::open(&format!("{}.public", &username.to_str().unwrap())).unwrap();
            let mut reader = BufReader::new(f);
            let mut buffer = Vec::new();
            
            // Read file into vector.
            reader.read_to_end(&mut buffer).unwrap();
            let bytes: [u8; 32] = buffer.as_slice().try_into().unwrap();
            let bob_public_key = PublicKey::from(bytes);

            let alice_public_key_bytes = alice_secret_key.public_key().as_bytes().clone();
            let bob_public_key_bytes = bob_public_key.as_bytes().clone();
/*            
            let mut f = std::fs::File::create("alice.private").unwrap();
            f.write_all(alice_secret_key.as_bytes());
            let mut f = std::fs::File::create("alice.public").unwrap();
            f.write_all(&alice_public_key_bytes);
            let mut f = std::fs::File::create("bob.private").unwrap();
            f.write_all(bob_secret_key.as_bytes());
            let mut f = std::fs::File::create("bob.public").unwrap();
            f.write_all(&bob_public_key_bytes);
*/
            
            let bob_public_key = PublicKey::from(bob_public_key_bytes);
            let alice_box = ChaChaBox::new(&bob_public_key, &alice_secret_key);
            let nonce = ChaChaBox::generate_nonce(&mut OsRng);
        
            let s: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(6)
                .map(char::from)
                .collect();

            let s = s.to_lowercase();

            // Message to encrypt
            let plaintext = s.as_bytes();
            let associated_data = b"".as_ref();
        
            // Encrypt the message using the box
            let ciphertext = alice_box.encrypt(&nonce, Payload {
                msg: plaintext, // your message to encrypt
                aad: associated_data, // not encrypted, but authenticated in tag
            }).unwrap(); //TODO: don't panic
        
            let b64_ciphertext = base64::encode(ciphertext);
            let b64_nonce = base64::encode(nonce); 
            
            let code_data = format!("{}:{}", b64_ciphertext, b64_nonce);

            let code = QrCode::new(&code_data).unwrap();
            let image = code.render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .build();

            pamh.conv(Some(&image), PamMsgStyle::TEXT_INFO)?;
            pamh.conv(Some(&format!("Challenge: {}", code_data)), PamMsgStyle::TEXT_INFO)?;

            let passcode = pamh.conv(Some("One-time passcode: "), PamMsgStyle::PROMPT_ECHO_ON)?.ok_or(PamError::AUTH_ERR)?;
            if passcode.to_str().map_err(|_| PamError::AUTH_ERR)? == s {
                //pamh.set_authtok(&CString::new("wf9wao").unwrap())?;
                Ok(())
            } else {
                Err(PamError::CONV_AGAIN)
            }
        }() {
            Ok(_) => PamError::SUCCESS,
            Err(e) => e,
        }
    }
}

pam_module!(PamPlat);
