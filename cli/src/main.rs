use arboard::Clipboard;
use image::{DynamicImage, ImageBuffer, RgbaImage, ImageError};
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
use log::{debug, error, info};
use std::string::FromUtf8Error;
use std::num::TryFromIntError;

use chrono::{DateTime, Utc};

use once_cell::sync::OnceCell;
static ENCRYPTION_CONFIG: OnceCell<EncryptionConfig> = OnceCell::new();

#[derive(Debug)]
struct EncryptionConfig {
  key_dir: PathBuf,
  public_key_path: Option<PathBuf>,
  private_key_path: Option<PathBuf>,
}

//DEBUG purposely not derived in order to not risk key leaking into the logs
struct DecryptionKey {
  path: PathBuf,
  key: SecretKey,
}

#[derive(Debug)]
struct DecryptionError {
  key: PathBuf,
  error: crypto_box::aead::Error,
}

impl std::fmt::Display for DecryptionError {
  // This trait requires `fmt` with this exact signature.
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
      write!(f, "key: {:?}, error: {}", self.key, self.error)
  }
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
  #[error("Challenge decryption failed: {:?}", .0)]
  ChallengeDecrypt(Vec<DecryptionError>),
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
        .arg(
          clap::Arg::new("key-dir")
            .long("key-dir")
            .help("Path at which to read and write keys (overrides env var: $SMARTCONSOLE_KEY_DIR)")
            .takes_value(true)
        )
        .subcommand(
          clap::Command::new("keygen")
          .arg(
            clap::Arg::new("path")
            .long("path")
            .help("Path in which to place the generated keypair, defaults to \"--key-dir\"")
            .takes_value(true)
          )
          .arg(
            clap::Arg::new("name")
            .long("name")
            .help("Name of the generated keypair (default: <current-timestamp>)")
            .takes_value(true)
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
                .help("optionally, use this identity private key to decrypt the challenge (if not set, key_dir will be scanned for private keys)")
                .takes_value(true)
                .required(false)
            )
        )
        .get_matches();

  let key_dir: PathBuf = matches.get_one::<String>("key-dir")
    .or(std::env::var("SMARTCONSOLE_KEY_DIR").ok().as_ref())
    .map(PathBuf::from)
    .or(home::home_dir().map(|p| p.join(".smartconsole")))
    .unwrap();

  let cmd_res = {
    if matches.subcommand_name().unwrap() == "keygen" {
      let key_gen_matches = matches.subcommand_matches("keygen").unwrap();
      let key_pair_path: PathBuf = key_gen_matches.get_one::<String>("path").map(PathBuf::from).unwrap_or(key_dir);
      let key_pair_name: String = key_gen_matches.get_one::<String>("name").map(std::borrow::ToOwned::to_owned).unwrap_or({
        let now: DateTime<Utc> = Utc::now();
        now.format("%Y-%m-%dT%H%M%S").to_string()
      });
      cli_key_gen(&key_pair_path.into(), &key_pair_name)
    } else if matches.subcommand_name().unwrap() == "decrypt" {
      let decrypt_matches = matches.subcommand_matches("decrypt").unwrap();
      let public_key_path: Option<&String> = decrypt_matches.get_one::<String>("public-key");
      let private_key_path: Option<&String> = decrypt_matches.get_one::<String>("private-key");
      ENCRYPTION_CONFIG.set(EncryptionConfig {
        key_dir,
        public_key_path: public_key_path.map(|p| p.into()),
        private_key_path: private_key_path.map(|p| p.into()),
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

fn cli_key_gen(path: &PathBuf, name: &String) -> Result<(), SmartConsoleCLIError> {

  let die_if_exists = |path: &PathBuf| {
    match path.exists() {
      true => Err(SmartConsoleCLIError::KeyPathExists(std::fs::canonicalize(path).unwrap())),
      false => Ok(())
    }
  };

  let base_path = path.join(name);
  let private_key_path = base_path.with_extension("private");
  let public_key_path = base_path.with_extension("public");

  info!("generating key pair: {:?} / {:?}", private_key_path, public_key_path);

  die_if_exists(&private_key_path)?;
  die_if_exists(&public_key_path)?;

  // if this already exists, it should be ok
  std::fs::create_dir_all(path)?;

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

  let decryption_keys = get_decryption_keys()?;
  let mut decryption_errors = Vec::new();

  for k in decryption_keys {
    debug!("trying to decrypt with key: {:?}", &k.path);
    let decryption_box = ChaChaBox::new(&server_public_key, &k.key);
    match decryption_box.decrypt(nonce.as_slice().into(), &ciphertext[..]) {
      Ok(decrypted) => return Ok(String::from_utf8(decrypted)?),
      Err(error) => {
        let wrapped_error = DecryptionError {
          key: k.path,
          error,
        };
        debug!("{:?}", &wrapped_error);
        decryption_errors.push(wrapped_error);
      },
    };
  }
  Err(SmartConsoleCLIError::ChallengeDecrypt(decryption_errors))
}

fn get_decryption_keys() -> Result<Vec<DecryptionKey>, SmartConsoleCLIError> {
  let config = ENCRYPTION_CONFIG.get().ok_or(SmartConsoleCLIError::EncryptionConfigError)?;

  let keys_to_read: Vec<PathBuf> = match &config.private_key_path {
    Some(p) => vec!(p.to_owned()), // if private-key is set on cmdline, read _only_ that
    None => { // otherwise scan key-dir for .private files
      std::fs::read_dir(&config.key_dir)?
        .filter_map(|e| {
          e.ok().map(|ee| {
            let is_file = ee.file_type().map(|t| t.is_file() || t.is_symlink()).unwrap_or(false);
            let file_name = ee.file_name().to_str().unwrap_or("").to_string();
            match is_file && file_name.ends_with(".private") {
              true => Some(ee.path()),
              false => None,
            }
          }).unwrap_or(None)
        })
        .collect()
    },
  };

  Ok(keys_to_read.iter().filter_map(|k| match read_key(k) {
    Ok(kk) => Some(kk),
    Err(e) => { error!("failed to read key: {:?}, error: {:?} - ignoring", k, e); None },
  }).collect())
}

fn read_key(path: &PathBuf) -> Result<DecryptionKey, SmartConsoleCLIError> {
  debug!("trying to read and parse private key: {:?}", &path);
  let f = File::open(path)?;
  let mut reader = BufReader::new(f);
  let mut buffer = Vec::new();
  
  // Read file into vector.
  reader.read_to_end(&mut buffer)?;
  let bytes: [u8; 32] = buffer.as_slice().try_into().map_err(|_| SmartConsoleCLIError::PrivateKeyFormat)?;
  Ok(DecryptionKey {
    path: path.to_owned(),
    key: SecretKey::from(bytes),
  })
}
