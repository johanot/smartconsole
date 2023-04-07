use arboard::Clipboard;
use image::{DynamicImage, ImageBuffer, RgbaImage, ImageError, GenericImageView};
use zbar_rust::ZBarImageScanner;

use std::io::{Read, Write};
use std::io::BufReader;
use std::fs::File;

use crypto_box::{
  aead::{Aead, OsRng},
  ChaChaBox, PublicKey, SecretKey
};

use base64::{Engine as _, engine::{general_purpose}};

use std::path::PathBuf;

use thiserror::Error;
use log::{error, info};
use std::string::FromUtf8Error;
use std::num::TryFromIntError;

use once_cell::sync::OnceCell;
static ENCRYPTION_CONFIG: OnceCell<EncryptionConfig> = OnceCell::new();

#[derive(Debug)]
struct EncryptionConfig {
  public_key_path: Option<PathBuf>,
  private_key_path: PathBuf,
}

#[derive(Error, Debug)]
enum SmartConsoleCLIError {
  #[error("Key path already exists: {:?}", .0)]
  KeyPathExists(PathBuf),
  #[error("IO related error")]
  IO(std::io::Error),
  #[error("Image error")]
  Image(ImageError),
  #[error("Utf8 Convertion error")]
  UTF8(FromUtf8Error),
  #[error("Barcode scan error")]
  Scan(String),
  #[error("Clipboard is empty or does not contain an image")]
  ClipboardEmpty,
  #[error("Clipboard error")]
  ClipboardError(arboard::Error),
  #[error("Image from raw error")]
  ImageFromRaw,
  #[error("Image data error, field: {}, error: {:?}", .0, .1)]
  ImageData(&'static str, TryFromIntError),
  #[error("Challenge is not formatted correctly -> as two parts separated by :")]
  ChallengeParts,
  #[error("Challenge parts are not valid base64: {:?}", .0)]
  ChallengeBase64(base64::DecodeError),
  #[error("Challenge decrypt error: {:?}", .0)]
  ChallengeDecrypt(crypto_box::aead::Error),
  #[error("Private key format error")]
  PrivateKeyFormat,
  #[error("Public key format error")]
  PublicKeyFormat,
  #[error("Encryption config error")]
  EncryptionConfigError,
}

impl std::convert::From<std::io::Error> for SmartConsoleCLIError {
  fn from(inner: std::io::Error) -> Self {
    SmartConsoleCLIError::IO(inner)
  }
}

impl std::convert::From<ImageError> for SmartConsoleCLIError {
  fn from(inner: ImageError) -> Self {
    SmartConsoleCLIError::Image(inner)
  }
}

impl std::convert::From<FromUtf8Error> for SmartConsoleCLIError {
  fn from(inner: FromUtf8Error) -> Self {
    SmartConsoleCLIError::UTF8(inner)
  }
}

impl std::convert::From<arboard::Error> for SmartConsoleCLIError {
  fn from(inner: arboard::Error) -> Self {
    SmartConsoleCLIError::ClipboardError(inner)
  }
}

impl std::convert::From<base64::DecodeError> for SmartConsoleCLIError {
  fn from(inner: base64::DecodeError) -> Self {
    SmartConsoleCLIError::ChallengeBase64(inner)
  }
}

impl std::convert::From<crypto_box::aead::Error> for SmartConsoleCLIError {
  fn from(inner: crypto_box::aead::Error) -> Self {
    SmartConsoleCLIError::ChallengeDecrypt(inner)
  }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

type Challenge = String;

fn main() {
  // set default log-level to "info" if RUST_LOG is not set in the environment
  match std::env::var("RUST_LOG") {
    Err(std::env::VarError::NotPresent) => std::env::set_var("RUST_LOG", "info"),
    Ok(_) | Err(_) => {},
  };
  pretty_env_logger::init();

  let matches = clap::Command::new("smartconsole")
        .version(VERSION)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
          clap::Command::new("keygen")
          .arg(
            clap::Arg::new("key-pair-path")
            .long("key-pair-path")
            .takes_value(true)
            .default_value("key")
          )
        )
        .subcommand(
          clap::Command::new("decrypt")
            .arg(
              clap::Arg::new("clipboard")
                .short('c')
                .long("clipboard")
                .help("decrypt from barcode image in the clipboard (default)")
                .action(clap::ArgAction::SetTrue)
            )
            .arg(
              clap::Arg::new("file")
                .short('f')
                .long("file")
                .help("decrypt from barcode image at file path")
                .takes_value(true)
            )
            .arg(
              clap::Arg::new("public-key")
                .short('p')
                .long("public-key")
                .help("optionally, use this server public key to verify the decrypted challenge")
                .takes_value(true)
                .required(false)
            )
            .arg(
              clap::Arg::new("private-key")
                .short('k')
                .long("private-key")
                .help("use this identity private key to decrypt the challenge")
                .takes_value(true)
                .required(true)
            )
        )
        .get_matches();

  let cmd_res = {
    if matches.subcommand_name().unwrap() == "keygen" {
      let key_gen_matches = matches.subcommand_matches("keygen").unwrap();
      let key_pair_path: &String = key_gen_matches.get_one::<String>("key-pair-path").unwrap();
      cli_key_gen(&key_pair_path.into())
    } else if matches.subcommand_name().unwrap() == "decrypt" {
      let decrypt_matches = matches.subcommand_matches("decrypt").unwrap();
      let public_key_path: Option<&String> = decrypt_matches.get_one::<String>("public-key");
      let private_key_path: &String = decrypt_matches.get_one::<String>("private-key").unwrap();
      ENCRYPTION_CONFIG.set(EncryptionConfig {
        public_key_path: public_key_path.map(|p| p.into()),
        private_key_path: private_key_path.into(),
      }).unwrap();
      (if decrypt_matches.is_present("file") {
        let image_file_path: &String = matches.get_one::<String>("file").unwrap();
        decrypt_from_file(image_file_path.into())
      } else {
        decrypt_from_clipboard()
      }).map(|challenge| {
        println!("decrypted challenge: {}", &challenge);
      })
    } else {
      Ok(())
    }
  };

  match cmd_res {
    Ok(_) => { std::process::exit(0); },
    Err(e) => {
      error!("{}", &e);
      std::process::exit(1);
    }
  }
}

fn cli_key_gen(path: &PathBuf) -> Result<(), SmartConsoleCLIError> {

  let die_if_exists = |path: &PathBuf| {
    match path.exists() {
      true => Err(SmartConsoleCLIError::KeyPathExists(std::fs::canonicalize(path).unwrap())),
      false => Ok(())
    }
  };

  let private_key_path = path.with_extension("private");
  let public_key_path = path.with_extension("public");

  info!("generating key pair: {:?} / {:?}", private_key_path, public_key_path);

  die_if_exists(&private_key_path)?;
  die_if_exists(&public_key_path)?;

  path.parent().map_or(Ok(()), |p| std::fs::create_dir_all(p))?;

  let private_key = SecretKey::generate(&mut OsRng);
  let public_key = private_key.public_key();
  let mut private_key_file = File::create(private_key_path)?;
  private_key_file.write_all(private_key.as_bytes())?;
  let mut public_key_file = File::create(public_key_path)?;
  public_key_file.write_all(public_key.as_bytes())?;
  
  Ok(())
}

fn decrypt_from_clipboard() -> Result<Challenge, SmartConsoleCLIError> {
  let mut cb = Clipboard::new()?;
  let image_data = match cb.get_image() {
    Ok(data) => Ok(data),
    Err(arboard::Error::ContentNotAvailable) => Err(SmartConsoleCLIError::ClipboardEmpty),
    Err(e) => Err(e.into())
  }?;
  let width = image_data.width.try_into().map_err(|e| SmartConsoleCLIError::ImageData("width", e))?;
  let height = image_data.height.try_into().map_err(|e| SmartConsoleCLIError::ImageData("height", e))?;

  let rgba: RgbaImage = ImageBuffer::from_raw(width, height, (*image_data.into_owned_bytes()).to_vec()).ok_or(SmartConsoleCLIError::ImageFromRaw)?;
  let image = DynamicImage::ImageRgba8(rgba);
  decrypt_from_image(image, width, height)
}

fn decrypt_from_file(path: PathBuf) -> Result<Challenge, SmartConsoleCLIError> {
  let image = image::open(path)?;
  let width = image.width();
  let height = image.height();
  decrypt_from_image(image, width, height)
}

fn decrypt_from_image(image: DynamicImage, width: u32, height: u32) -> Result<Challenge, SmartConsoleCLIError> {
  let luma_img = image.into_luma8();

  let luma_img_data: Vec<u8> = luma_img.to_vec();

  let mut scanner = ZBarImageScanner::new();

  let results = scanner.scan_y800(&luma_img_data, width, height).map_err(|msg| SmartConsoleCLIError::Scan(msg.to_string()))?;

  let mut challenge = String::new();
  for result in results {
    challenge = decrypt(&String::from_utf8(result.data)?)?;
  }

  Ok(challenge)
}

fn decrypt(content: &str) -> Result<Challenge, SmartConsoleCLIError> {

  let parts: Vec<&str> = content.split(':').collect();
  let b64 = general_purpose::STANDARD;
  let ciphertext = b64.decode(parts.get(0).ok_or(SmartConsoleCLIError::ChallengeParts)?)?;
  let nonce = b64.decode(parts.get(1).ok_or(SmartConsoleCLIError::ChallengeParts)?)?;

  let encryption_config = ENCRYPTION_CONFIG.get().ok_or(SmartConsoleCLIError::EncryptionConfigError)?;

  let server_public_key = match &encryption_config.public_key_path {
    Some(path) => {
      let f = File::open(&path)?;
      let mut reader = BufReader::new(f);
      let mut buffer = Vec::new();
      reader.read_to_end(&mut buffer)?;
      buffer
    },
    None => b64.decode(parts.get(2).ok_or(SmartConsoleCLIError::ChallengeParts)?)?,
  };

  let bytes: [u8; 32] = server_public_key.try_into().map_err(|_| SmartConsoleCLIError::PublicKeyFormat)?;
  let server_public_key = PublicKey::from(bytes);

  let f = File::open(&encryption_config.private_key_path)?;
  let mut reader = BufReader::new(f);
  let mut buffer = Vec::new();
  
  // Read file into vector.
  reader.read_to_end(&mut buffer)?;
  let bytes: [u8; 32] = buffer.as_slice().try_into().map_err(|_| SmartConsoleCLIError::PrivateKeyFormat)?;
  let identity_private_key = SecretKey::from(bytes);

  let decryption_box = ChaChaBox::new(&server_public_key, &identity_private_key);
  Ok(String::from_utf8(decryption_box.decrypt(nonce.as_slice().into(), &ciphertext[..])?)?)
}