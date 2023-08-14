use argon2::{self, Config};
use base64ct::{Base64, Encoding};
use clap::{Arg, ArgAction, Command};
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info, warn};
use owo_colors::colored::*;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use std::{
    error::Error,
    fs,
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process,
    str::FromStr,
    time::Duration,
};

const SPINNER_BINARY: &[&str; 10] = &[
    "010010", "001100", "100101", "111010", "111101", "010111", "101011", "111000", "110011",
    "110101",
];
const SPINNER_ARC: &[&str; 6] = &["◜", "◠", "◝", "◞", "◡", "◟"];

enum CodingMethod {
    Decoding,
    Encoding,
}

// TODO add more methods
// available methods for en-/decoding // en-/decrypting
#[derive(Debug, EnumIter)]
enum Method {
    Base64ct,
    Caesar,
    Hex,
    Testing,
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
            "test" | "testing" => Ok(Method::Testing),
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
    let password_flag = matches.get_flag("password");

    if list_flag {
        // list all available en-/decoding // en-/decrypting methods
        list_methods();
    } else if let Some(arg) = matches.get_one::<String>("arg") {
        // get search path from arguments
        let path = Path::new(arg);

        if !path.exists() {
            error!("The file doesn`t exist");
            process::exit(0);
        }

        // TODO limit max filesize??

        // TODO use threading for multiple file input
        // TODO use multiple spinners
        // spinner
        let spinner_style = ProgressStyle::with_template("{spinner:.red} {msg}").unwrap();
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(spinner_style);

        // start encoding / decoding
        if let Some(method) = matches.get_one::<String>("encode") {
            let mut hash = String::new();
            if password_flag {
                let mut password = String::new();
                loop {
                    let pw = prompt_user_for_pw(pb.clone(), "Enter password".to_string());
                    let pw_confirmation =
                        prompt_user_for_pw(pb.clone(), "Confirm password".to_string());

                    if pw == pw_confirmation {
                        password.push_str(&pw);
                        break;
                    }

                    pb.suspend(|| {
                        println!(
                            "{}",
                            "Passwords didn`t match. Try again".truecolor(250, 0, 104)
                        );
                    });
                }

                let hash_string = calculate_hash(pb.clone(), password);
                hash.push_str(&hash_string);
            }

            let encoding_spinner_style = ProgressStyle::with_template("{spinner:.red} {msg}")
                .unwrap()
                .tick_strings(SPINNER_ARC);
            pb.set_style(encoding_spinner_style);
            pb.set_message(format!("{}", "encoding...".truecolor(250, 0, 104)));

            let (_, content) = read_file_content(&path.to_path_buf(), CodingMethod::Encoding)?;

            let mut encoded = Vec::new();
            match method.parse::<Method>().unwrap() {
                Method::Base64ct => {
                    let mut base64ct_encoded_vec = encode_base64ct(content)?;
                    encoded.append(&mut base64ct_encoded_vec);
                }
                Method::Caesar => {
                    let mut caesar_encoded_vec = encode_caesar(content)?;
                    encoded.append(&mut caesar_encoded_vec);
                }
                Method::Hex => {
                    let mut hex_encoded_vec = encode_hex(content)?;
                    encoded.append(&mut hex_encoded_vec);
                }
                Method::Testing => {
                    let mut testing_encoded_vec = encode_testing(content)?;
                    encoded.append(&mut testing_encoded_vec);
                }
            }

            // write encoded / encrpyted content back to file
            write_file_content(&path.to_path_buf(), hash, &encoded)?;
        } else if let Some(method) = matches.get_one::<String>("decode") {
            // non utf-8 data could be written to file via encrypting methods
            // -> reading the encoded / encrypted content from the file must be handled
            // seperatly incase non utf-8 data from the file should be handled differently
            let (hash, content) = read_file_content(&path.to_path_buf(), CodingMethod::Decoding)?;

            if password_flag {
                let password = prompt_user_for_pw(pb.clone(), "Enter password".to_string());
                let verification = verify_hash(pb.clone(), hash, password);
                if !verification {
                    warn!("Couldn`t verify password");
                    process::exit(0);
                }
            }

            let decoding_spinner_style = ProgressStyle::with_template("{spinner:.red} {msg}")
                .unwrap()
                .tick_strings(SPINNER_ARC);
            pb.set_style(decoding_spinner_style);
            pb.set_message(format!("{}", "decoding...".truecolor(250, 0, 104)));

            let mut decoded = Vec::new();
            match method.parse::<Method>().unwrap() {
                Method::Base64ct => {
                    let mut base64ct_decoded_vec = decode_base64ct(content)?;
                    decoded.append(&mut base64ct_decoded_vec);
                }
                Method::Caesar => {
                    let mut caesar_decoded_vec = decode_caesar(content)?;
                    decoded.append(&mut caesar_decoded_vec);
                }
                Method::Hex => {
                    let mut hex_decoded_vec = decode_hex(content)?;
                    decoded.append(&mut hex_decoded_vec);
                }
                Method::Testing => {
                    let mut testing_decoded_vec = decode_testing(content)?;
                    decoded.append(&mut testing_decoded_vec);
                }
            }

            // write decoded / decrpyted content back to file
            let empty_hash = String::new();
            write_file_content(&path.to_path_buf(), empty_hash, &decoded)?;
        } else {
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
        .about("En-/Decode // En-/Decrypt files")
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
        .version("1.1.0")
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
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .help("Secure a file with a password")
                .action(ArgAction::SetTrue)
                .conflicts_with("list"),
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

fn prompt_user_for_pw(pb: ProgressBar, msg: String) -> String {
    pb.suspend(|| {
        println!("{}", msg);
    });
    let pw_spin_style = ProgressStyle::with_template("{spinner:.black} {msg}").unwrap();
    pb.set_style(pw_spin_style.tick_chars("⬛⬛⬛⬛"));
    pb.enable_steady_tick(Duration::from_millis(20));

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    pb.enable_steady_tick(Duration::from_millis(120));

    input
}

fn calculate_hash(pb: ProgressBar, password: String) -> String {
    let calc_hash_spin_style = ProgressStyle::with_template("{spinner:.white} {msg}").unwrap();
    pb.set_style(calc_hash_spin_style.tick_strings(SPINNER_BINARY));

    pb.set_message(format!("{}", "calculating hash ...".truecolor(250, 0, 104)));

    let salt = b"gibberish_salt";
    let config = Config::rfc9106();
    let hash =
        argon2::hash_encoded(password.as_bytes(), salt, &config).expect("Unable to hash password");

    hash
}

fn verify_hash(pb: ProgressBar, hash: String, password: String) -> bool {
    let verify_hash_spin_style = ProgressStyle::with_template("{spinner:.white} {msg}").unwrap();
    pb.set_style(verify_hash_spin_style.tick_strings(SPINNER_BINARY));
    pb.set_message(format!("{}", "verifying hash ...".truecolor(250, 0, 104)));

    let matches =
        argon2::verify_encoded(&hash, password.as_bytes()).expect("Unable to verify hash");

    matches
}

fn encode_base64ct(content: String) -> io::Result<Vec<u8>> {
    let encoded = Base64::encode_string(content.to_string().as_bytes());
    Ok(encoded.into_bytes())
}

fn decode_base64ct(content: String) -> io::Result<Vec<u8>> {
    let decoded = Base64::decode_vec(&content).expect("Error while decoding file");
    Ok(decoded)
}

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

fn encode_hex(content: String) -> io::Result<Vec<u8>> {
    // TODO error in crate hex?
    // unable to convert '§' <-> 'a7'
    // remove later
    assert!(!content.contains("§"));

    let encoded = hex::encode(content.trim().to_string());

    Ok(encoded.into_bytes())
}

fn decode_hex(content: String) -> io::Result<Vec<u8>> {
    // TODO error in crate hex?
    // unable to convert '§' <-> 'a7'

    let decoded = hex::decode(&content).expect("Error while decoding file");

    Ok(decoded)
}

fn default_encoding(path: &PathBuf) -> io::Result<()> {
    let hash = String::new();
    let (_, content) = read_file_content(&path.to_path_buf(), CodingMethod::Encoding)?;
    let mut encoded_base64 = Vec::new();
    let mut tmp_base64_encoded_vec = encode_base64ct(content)?;
    encoded_base64.append(&mut tmp_base64_encoded_vec);

    // write encrpyted content back to file
    write_file_content(&path.to_path_buf(), hash.clone(), &encoded_base64)?;

    let (_, content2) = read_file_content(&path.to_path_buf(), CodingMethod::Encoding)?;
    let mut encoded_caesar = Vec::new();
    let mut tmp_caesar_encoded_vec = encode_caesar(content2)?;
    encoded_caesar.append(&mut tmp_caesar_encoded_vec);

    // write encrpyted content back to file
    write_file_content(&path.to_path_buf(), hash, &encoded_caesar)?;

    Ok(())
}

// for testing only -> remove later
fn encode_testing(_content: String) -> io::Result<Vec<u8>> {
    unimplemented!()
}

// for testing only -> remove later
fn decode_testing(_content: String) -> io::Result<Vec<u8>> {
    unimplemented!()
}

fn read_file_content(path: &PathBuf, codingmethod: CodingMethod) -> io::Result<(String, String)> {
    let file = fs::File::open(path)?;
    let buf_reader = BufReader::new(file);
    let mut buffer_lines = buf_reader
        .lines()
        .map(|line| line.expect("Failed to read line in encoded file"));

    let first_line: String = buffer_lines.next().unwrap().parse().unwrap();

    let mut rest = String::new();
    for line in buffer_lines {
        rest.push_str(&line);

        match codingmethod {
            CodingMethod::Decoding => {}
            CodingMethod::Encoding => rest.push_str("\n"),
        }
    }

    let mut hash = String::new();
    let mut content = String::new();
    if first_line.contains("$argon2id$v=19$m=2097152,t=1,p=1") {
        hash.push_str(&first_line);
        content.push_str(&rest);
    } else {
        content.push_str(&first_line);

        if !rest.is_empty() {
            content.push_str("\n");
            content.push_str(&rest);
        }
    }

    Ok((hash, content))
}

fn write_file_content(path: &PathBuf, hash: String, content: &[u8]) -> io::Result<()> {
    // FIXME when decoding hex -> no new lines
    let mut newfile = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)?;

    if !hash.is_empty() {
        newfile.write_all(hash.as_bytes())?;
        newfile.write_all("\n".as_bytes())?;
    }

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
