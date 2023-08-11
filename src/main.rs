use base64ct::{Base64, Encoding};
use clap::{Arg, ArgAction, Command};
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info};
use owo_colors::colored::*;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use std::{
    error::Error,
    fs,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    process,
    str::FromStr,
    time::Duration,
};

// TODO add more methods
// available methods for en-/decoding // en-/decrypting
#[derive(Debug, EnumIter)]
enum Method {
    Base64ct,
    Caesar,
    Hex,
}

#[derive(Debug)]
struct MethodError;

impl FromStr for Method {
    type Err = MethodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "base64ct" | "base64" => Ok(Method::Base64ct),
            "caesar" => Ok(Method::Caesar),
            "hex" => Ok(Method::Hex),
            _ => {
                error!("{:?}: Unknown method", MethodError);
                info!("Type: 'gib --list' to see all available methods");
                process::exit(0);
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // handle Ctrl+C
    ctrlc::set_handler(move || {
        println!(
            "{} {} {} {}",
            "Received Ctrl-C!".bold().red(),
            "🤬",
            "Exit program!".bold().red(),
            "☠",
        );
        process::exit(0)
    })
    .expect("Error setting Ctrl-C handler");

    // get config dir
    let config_dir = check_create_config_dir().unwrap_or_else(|err| {
        error!("Unable to find or create a config directory: {err}");
        process::exit(1);
    });

    // initialize the logger
    let _logger = Logger::try_with_str("info") // log warn and error
        .unwrap()
        .format_for_files(detailed_format) // use timestamp for every log
        .log_to_file(
            FileSpec::default()
                .directory(&config_dir)
                .suppress_timestamp(),
        ) // change directory for logs, no timestamps in the filename
        .append() // use only one logfile
        .duplicate_to_stderr(Duplicate::Info) // print infos, warnings and errors also to the console
        .start()
        .unwrap();

    // handle arguments
    let matches = gib().get_matches();
    let list_flag = matches.get_flag("list");

    if list_flag {
        // list all available encoding/decoding methods
        list_methods();
    } else if let Some(arg) = matches.get_one::<String>("arg") {
        // get search path from arguments
        let path = Path::new(arg);

        if !path.exists() {
            error!("The file doesn`t exist");
            process::exit(0);
        }

        // TODO use threading for multiple file input
        // TODO use multiple spinners
        // spinner
        let spinner_style = ProgressStyle::with_template("{spinner:.red} {msg}").unwrap();
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(spinner_style);

        // start encoding / decoding
        let content =
            read_file_content(&path.to_path_buf()).expect("Error while reading content to file");

        if let Some(method) = matches.get_one::<String>("encode") {
            pb.set_message(format!("{}", "encoding...".truecolor(250, 0, 104)));

            let mut encoded = Vec::new();
            match method.parse::<Method>().unwrap() {
                Method::Base64ct => {
                    let mut tmp_encoded_vec = encode_base64ct(content)?;
                    encoded.append(&mut tmp_encoded_vec);
                }
                Method::Caesar => {
                    let mut tmp_encoded_vec = encode_caesar(content)?;
                    encoded.append(&mut tmp_encoded_vec);
                }
                Method::Hex => {
                    let mut tmp_encoded_vec = encode_hex(content)?;
                    encoded.append(&mut tmp_encoded_vec);
                }
            }

            // write encrpyted content back to file
            write_file_content(&path.to_path_buf(), &encoded).expect("Error while writing to file");
        } else if let Some(method) = matches.get_one::<String>("decode") {
            pb.set_message(format!("{}", "decoding...".truecolor(250, 0, 104)));

            let mut decoded = Vec::new();
            match method.parse::<Method>().unwrap() {
                Method::Base64ct => {
                    let mut tmp_decoded_vec = decode_base64ct(content)?;
                    decoded.append(&mut tmp_decoded_vec);
                }
                Method::Caesar => {
                    let mut tmp_decoded_vec = decode_caesar(content)?;
                    decoded.append(&mut tmp_decoded_vec);
                }
                Method::Hex => {
                    let mut tmp_decoded_vec = decode_hex(content)?;
                    decoded.append(&mut tmp_decoded_vec);
                }
            }

            // write decrpyted content back to file
            write_file_content(&path.to_path_buf(), &decoded).expect("Error while writing to file");
        } else {
            // TODO replace with something useful
            // TODO what should be the default command if nothing is specified?
            // info!("Usage: 'gib [OPTIONS] [PATH] [COMMAND]'");
            // info!("Type: 'gib help' to get more information");
            // process::exit(0);

            default_encoding(&path.to_path_buf())?;
        }

        pb.finish_and_clear();
    } else {
        // handle commands
        match matches.subcommand() {
            Some(("log", _)) => {
                if let Ok(logs) = show_log_file(&config_dir) {
                    println!("{}", "Available logs:".bold().yellow());
                    println!("{}", logs);
                } else {
                    error!("Unable to read logs");
                    process::exit(1);
                }
            }
            _ => {
                info!("Usage: 'gib [OPTIONS] [PATH] [COMMAND]'");
                info!("Type: 'gib help' to get more information");
                process::exit(0);
            }
        }
    }

    Ok(())
}

// build cli
fn gib() -> Command {
    Command::new("gib")
        .bin_name("gib")
        .before_help(format!(
            "{}\n{}",
            "GIB".bold().truecolor(250, 0, 104),
            "Leann Phydon <leann.phydon@gmail.com>".italic().dimmed()
        ))
        .about("Encode / Decode files")
        .before_long_help(format!(
            "{}\n{}",
            "GIB".bold().truecolor(250, 0, 104),
            "Leann Phydon <leann.phydon@gmail.com>".italic().dimmed()
        ))
        .long_about(format!(
            "{}\n{}",
            "GIBBERISH".italic(),
            "Quickly en-/decode // en-/decrypt files 'on the fly'",
        ))
        // TODO update version
        .version("1.0.0")
        .author("Leann Phydon <leann.phydon@gmail.com>")
        .arg_required_else_help(true)
        .arg(
            Arg::new("arg")
                .help("Add a path")
                .action(ArgAction::Set)
                .num_args(1)
                .value_names(["PATH"]),
        )
        .arg(
            Arg::new("decode")
                .short('d')
                .long("decode")
                .help("Decode/Decrypt the file")
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("Decoding/Decrypting method")
                .conflicts_with("encode"),
        )
        .arg(
            Arg::new("encode")
                .short('e')
                .long("encode")
                .help("Encode/Encrypt the file")
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("Encoding/Encrypting method"),
        )
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .help("List all available en-/decoding // en-/decrypting methods")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["decode", "encode"]),
        )
        .subcommand(
            Command::new("log")
                .short_flag('L')
                .long_flag("log")
                .about("Show content of the log file"),
        )
}

// list all available methods
fn list_methods() {
    for method in Method::iter() {
        println!("{:?}", method);
    }
}

// encoding with base64 constant time
fn encode_base64ct(content: String) -> io::Result<Vec<u8>> {
    let encoded = Base64::encode_string(content.trim().to_string().as_bytes());

    Ok(encoded.into_bytes())
}

// decoding base64 constant time
fn decode_base64ct(content: String) -> io::Result<Vec<u8>> {
    let decoded = Base64::decode_vec(&content).expect("Error while decoding file");
    Ok(decoded)
}

// encoding with caesar cipher
// based on https://github.com/TheAlgorithms/Rust
fn encode_caesar(content: String) -> io::Result<Vec<u8>> {
    // TODO let user choose a key between 1 <= key <= 26
    let key: u8 = 13;
    assert!(key <= 26 && key >= 1);

    let encoded: String = content
        .chars()
        .map(|char| {
            if char.is_ascii_alphabetic() {
                let value = if char.is_ascii_lowercase() {
                    b'a'
                } else {
                    b'A'
                };
                (value + (char as u8 + key - value) % 26) as char
            } else {
                char
            }
        })
        .collect();

    Ok(encoded.into_bytes())
}

// decoding caesar cipher
// based on https://github.com/TheAlgorithms/Rust
fn decode_caesar(content: String) -> io::Result<Vec<u8>> {
    // TODO get key from user
    let key: u8 = 13;
    assert!(key <= 26 && key >= 1);

    let decoded: String = content
        .chars()
        .map(|char| {
            if char.is_ascii_alphabetic() {
                let value = if char.is_ascii_lowercase() {
                    b'a'
                } else {
                    b'A'
                };
                (value + (char as u8 + (26 - key) - value) % 26) as char
            } else {
                char
            }
        })
        .collect();

    Ok(decoded.into_bytes())
}

// encoding with hex
fn encode_hex(content: String) -> io::Result<Vec<u8>> {
    // TODO workaround: error in crate hex?
    // TODO remove later
    assert!(!content.contains("§"));

    let encoded = hex::encode(content.trim().to_string());

    Ok(encoded.into_bytes())
}

// decoding hex
fn decode_hex(content: String) -> io::Result<Vec<u8>> {
    // TODO workaround: error in crate hex?
    // TODO remove later
    assert!(!content.contains("a7"));

    let decoded = hex::decode(&content).expect("Error while decoding file");

    Ok(decoded)
}

fn default_encoding(path: &PathBuf) -> io::Result<()> {
    let content =
        read_file_content(&path.to_path_buf()).expect("Error while reading content to file");
    let mut encoded_base64 = Vec::new();
    let mut tmp_base64_encoded_vec = encode_base64ct(content)?;
    encoded_base64.append(&mut tmp_base64_encoded_vec);

    // write encrpyted content back to file
    write_file_content(&path.to_path_buf(), &encoded_base64).expect("Error while writing to file");

    let content2 =
        read_file_content(&path.to_path_buf()).expect("Error while reading content to file");
    let mut encoded_caesar = Vec::new();
    let mut tmp_caesar_encoded_vec = encode_caesar(content2)?;
    encoded_caesar.append(&mut tmp_caesar_encoded_vec);

    // write encrpyted content back to file
    write_file_content(&path.to_path_buf(), &encoded_caesar).expect("Error while writing to file");

    Ok(())
}

fn read_file_content(path: &PathBuf) -> io::Result<String> {
    let file = fs::File::open(path)?;
    let mut buf_reader = BufReader::new(file);
    let mut content = String::new();
    buf_reader.read_to_string(&mut content)?;

    Ok(content.trim().to_string())
}

fn write_file_content(path: &PathBuf, content: &[u8]) -> io::Result<()> {
    let mut newfile = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)?;
    newfile.write_all(&content)?;

    Ok(())
}

fn check_create_config_dir() -> io::Result<PathBuf> {
    let mut new_dir = PathBuf::new();
    match dirs::config_dir() {
        Some(config_dir) => {
            new_dir.push(config_dir);
            new_dir.push("gib");
            if !new_dir.as_path().exists() {
                fs::create_dir(&new_dir)?;
            }
        }
        None => {
            error!("Unable to find config directory");
        }
    }

    Ok(new_dir)
}

fn show_log_file(config_dir: &PathBuf) -> io::Result<String> {
    let log_path = Path::new(&config_dir).join("gib.log");
    match log_path.try_exists()? {
        true => {
            return Ok(format!(
                "{} {}\n{}",
                "Log location:".italic().dimmed(),
                &log_path.display(),
                fs::read_to_string(&log_path)?
            ));
        }
        false => {
            return Ok(format!(
                "{} {}",
                "No log file found:"
                    .truecolor(250, 0, 104)
                    .bold()
                    .to_string(),
                log_path.display()
            ))
        }
    }
}

#[test]
fn encode_base64ct_test() {
    assert_eq!(
        encode_base64ct("This is a test".to_string()).unwrap(),
        "VGhpcyBpcyBhIHRlc3Q=".as_bytes()
    );
}

#[test]
fn decode_base64ct_test() {
    assert_eq!(
        decode_base64ct("VGhpcyBpcyBhIHRlc3Q=".to_string()).unwrap(),
        "This is a test".as_bytes()
    );
}

#[test]
fn encode_base64ct_special_chars_test() {
    assert_eq!(
        encode_base64ct("Random chars: !\"§$%&/()=?`+#*'-_~@".to_string()).unwrap(),
        "UmFuZG9tIGNoYXJzOiAhIsKnJCUmLygpPT9gKyMqJy1ffkA=".as_bytes()
    );
}

#[test]
fn decode_base64ct_special_chars_test() {
    assert_eq!(
        decode_base64ct("UmFuZG9tIGNoYXJzOiAhIsKnJCUmLygpPT9gKyMqJy1ffkA=".to_string()).unwrap(),
        "Random chars: !\"§$%&/()=?`+#*'-_~@".as_bytes()
    );
}

#[test]
fn encode_caesar_test() {
    assert_eq!(
        encode_caesar("This is a test".to_string()).unwrap(),
        "Guvf vf n grfg".as_bytes()
    );
}

#[test]
fn decode_caesar_test() {
    assert_eq!(
        decode_caesar("Guvf vf n grfg".to_string()).unwrap(),
        "This is a test".as_bytes()
    );
}

#[test]
fn encode_caesar_special_chars_test() {
    assert_eq!(
        encode_caesar("Random chars: !\"§$%&/()=?`+#*'-_~@".to_string()).unwrap(),
        "Enaqbz punef: !\"§$%&/()=?`+#*'-_~@".as_bytes()
    );
}

#[test]
fn decode_caesar_special_chars_test() {
    assert_eq!(
        decode_caesar("Enaqbz punef: !\"§$%&/()=?`+#*'-_~@".to_string()).unwrap(),
        "Random chars: !\"§$%&/()=?`+#*'-_~@".as_bytes()
    );
}

#[test]
fn encode_hex_test() {
    assert_eq!(
        encode_hex("This is a test".to_string()).unwrap(),
        "5468697320697320612074657374".as_bytes()
    );
}

#[test]
fn decode_hex_test() {
    assert_eq!(
        decode_hex("5468697320697320612074657374".to_string()).unwrap(),
        "This is a test".as_bytes()
    );
}

#[test]
fn encode_hex_special_chars_test() {
    assert_eq!(
        // FIXME fails with §
        // see encode_hex_special_chars_test_2
        encode_hex("Random chars: !\"$%&/()=?`+#*'-_~@".to_string()).unwrap(),
        "52616e646f6d2063686172733a2021222425262f28293d3f602b232a272d5f7e40".as_bytes()
    );
}

#[test]
fn decode_hex_special_chars_test() {
    assert_eq!(
        // FIXME fails with §
        // see decode_hex_special_chars_test_2
        decode_hex(
            "52616e646f6d2063686172733a2021222425262f28293d3f602b232a272d5f7e40".to_string()
        )
        .unwrap(),
        "Random chars: !\"$%&/()=?`+#*'-_~@".as_bytes()
    );
}

#[test]
// FIXME
// error in hex crate ???
fn encode_hex_special_chars_test_2() {
    assert_eq!(encode_hex("§".to_string()).unwrap(), "a7".as_bytes());
}

#[test]
// FIXME
// error in hex crate ???
fn decode_hex_special_chars_test_2() {
    assert_eq!(decode_hex("a7".to_string()).unwrap(), "§".as_bytes());
}
