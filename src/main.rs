mod argon;
mod base64ct;
mod caesar;
mod chacha;
mod hex;
mod l33t;
mod methods;
mod utils;
mod xor;

use crate::argon::*;
use crate::base64ct::*;
use crate::caesar::*;
use crate::chacha::*;
use crate::hex::*;
use crate::methods::*;
use crate::utils::*;
use crate::xor::*;

use clap::{Arg, ArgAction, Command};
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use indicatif::{ProgressBar, ProgressStyle};
use l33t::encode_decode_l33t;
use log::{error, info, warn};
use owo_colors::colored::*;

use std::{error::Error, path::Path, process, time::Duration};

pub const SPINNER_ARC: &[&str; 6] = &["◜", "◠", "◝", "◞", "◡", "◟"];

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
    let sign_flag = matches.get_flag("sign");
    let copy_flag = matches.get_flag("copy");
    let key_flag = matches.get_flag("key");

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

        let path = path.to_path_buf();

        // TODO limit max filesize??

        // TODO use threading for multiple file input
        // TODO use multiple spinners
        // spinner
        let spinner_style = ProgressStyle::with_template("{spinner:.red} {msg}").unwrap();
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(spinner_style);

        // handle copy flag
        if copy_flag {
            pb.set_message(format!("{}", "making backup...".truecolor(250, 0, 104)));
            // TODO check if copying works correctly
            make_file_copy(pb.clone(), &path, &config_dir)?;
        }

        // read file
        pb.set_message(format!("{}", "reading file...".truecolor(250, 0, 104)));

        // close if file is empty
        check_file_size(&path);

        // TODO remove this var later
        // if methods write content separatly to file
        // set writing_done variable to true
        let mut writing_done = false;

        // read file content as bytes
        let byte_content: Vec<u8> = read_file_content(&path)?;

        // for storing hash
        let mut hash = String::new();
        // for storing rest of the content if there is a hash
        let mut rest = Vec::new();

        // for storing encoded / decoded content
        let mut encoded_decoded_content = Vec::new();

        // handle sign flag
        if sign_flag {
            // extract hash from content
            let (hash_bytes, rest_bytes) = extract_hash(&byte_content);
            // TODO is there a better way than cloning??
            let mut tmp_vec = Vec::from(rest_bytes.clone());
            rest.append(&mut tmp_vec);

            // if argon configs change, this changes as well
            if hash_bytes.starts_with("$argon2id$v=19$m=2097152,t=1,p=1".as_bytes()) {
                let h = String::from_utf8(hash_bytes).unwrap();
                hash.push_str(&h);
            }

            if hash.is_empty() {
                // calculate hash from file content
                let hash_string = calculate_hash(pb.clone(), &rest_bytes);
                hash.push_str(&hash_string);
            } else {
                let verification = verify_hash(pb.clone(), &hash, &rest_bytes);
                if !verification {
                    warn!("Couldn`t verify file");
                    process::exit(0);
                }

                pb.suspend(|| {
                    println!("{}", "Verification successful".green());
                });

                // no file changes needed
                writing_done = true;
            }
        } else if let Some(method) = matches.get_one::<String>("encode") {
            // start encoding
            let encoding_spinner_style = ProgressStyle::with_template("{spinner:.red} {msg}")
                .unwrap()
                .tick_strings(SPINNER_ARC);
            pb.set_style(encoding_spinner_style);
            pb.set_message(format!("{}", "encoding...".truecolor(250, 0, 104)));

            match method.parse::<Method>().unwrap() {
                Method::Base64ct => {
                    let mut base64ct_encoded_vec = encode_base64ct(&byte_content)?;
                    encoded_decoded_content.append(&mut base64ct_encoded_vec);
                }
                Method::Caesar => {
                    let mut caesar_encoded_vec = encode_caesar(&byte_content)?;
                    encoded_decoded_content.append(&mut caesar_encoded_vec);
                }
                Method::ChaCha20Poly1305 => {
                    // TODO ask user for key
                    // WARNING key must be 32 bytes long
                    let key = "passwordpasswordpasswordpassword".to_string().into_bytes();

                    // TODO handle unwrap()
                    let ciphertext = encode_chacha(&key, &byte_content).unwrap();

                    // TODO remove later
                    write_non_utf8_content(&path, &ciphertext)?;
                    writing_done = true;
                }
                Method::Hex => {
                    let mut hex_encoded_vec = encode_hex(&byte_content)?;
                    encoded_decoded_content.append(&mut hex_encoded_vec);
                }
                Method::L33t => {
                    // there should always be at least the default mode
                    if let Some(mode) = matches.get_one::<String>("l33t") {
                        let mut l33t_encoded_vec = encode_decode_l33t(&byte_content, mode)?;
                        encoded_decoded_content.append(&mut l33t_encoded_vec);
                    }
                }
                Method::XOR => {
                    let mut key = String::new();
                    if key_flag {
                        let input = prompt_user_for_input(pb.clone(), "Enter a key".to_string());
                        key.push_str(&input);
                    }

                    let mut xor_encoded_vec = encode_decode_xor(&byte_content, key)?;
                    encoded_decoded_content.append(&mut xor_encoded_vec);
                }
            }
        } else if let Some(method) = matches.get_one::<String>("decode") {
            // start decoding
            let decoding_spinner_style = ProgressStyle::with_template("{spinner:.red} {msg}")
                .unwrap()
                .tick_strings(SPINNER_ARC);
            pb.set_style(decoding_spinner_style);
            pb.set_message(format!("{}", "decoding...".truecolor(250, 0, 104)));

            match method.parse::<Method>().unwrap() {
                Method::Base64ct => {
                    let mut base64ct_decoded_vec = decode_base64ct(&byte_content)?;
                    encoded_decoded_content.append(&mut base64ct_decoded_vec);
                }
                Method::Caesar => {
                    let mut caesar_decoded_vec = decode_caesar(&byte_content)?;
                    encoded_decoded_content.append(&mut caesar_decoded_vec);
                }
                Method::ChaCha20Poly1305 => {
                    // TODO ask user for key
                    // WARNING key must be 32 bytes long
                    let key = "passwordpasswordpasswordpassword".to_string().into_bytes();

                    let (nonce, encrypted_text) = extract_nonce(&byte_content);

                    // TODO handle unwrap()
                    let decrypted_text = decode_chacha(&key, &nonce, &encrypted_text).unwrap();

                    // TODO remove later
                    write_non_utf8_content(&path, &decrypted_text)?;
                    writing_done = true;
                }
                Method::Hex => {
                    let mut hex_decoded_vec = decode_hex(&byte_content)?;
                    encoded_decoded_content.append(&mut hex_decoded_vec);
                }
                Method::L33t => {
                    // there should always be at least the default mode
                    if let Some(mode) = matches.get_one::<String>("l33t") {
                        let mut l33t_decoded_vec = encode_decode_l33t(&byte_content, mode)?;
                        encoded_decoded_content.append(&mut l33t_decoded_vec);
                    }
                }
                Method::XOR => {
                    let mut key = String::new();
                    if key_flag {
                        let input = prompt_user_for_input(pb.clone(), "Enter a key".to_string());
                        key.push_str(&input);
                    }

                    let mut xor_decoded_vec = encode_decode_xor(&byte_content, key)?;
                    encoded_decoded_content.append(&mut xor_decoded_vec);
                }
            }
        }

        // write encoded/encrypted // decoded/decrpyted content back to file
        if !writing_done {
            if !hash.is_empty() {
                // concat hash and rest of the byte_content
                let mut concated_hash_and_rest_bytes = hash.into_bytes();
                concated_hash_and_rest_bytes.append(&mut rest);

                write_non_utf8_content(&path, &concated_hash_and_rest_bytes)?;
            } else {
                // if no sign flag was set
                write_non_utf8_content(&path, &encoded_decoded_content)?;
            }
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
        .about(format!("{} {}", "Turning text into", "GIBBERISH".bold(),))
        .before_long_help(format!(
            "{}\n{}",
            "GIB".bold().truecolor(250, 0, 104),
            "Leann Phydon <leann.phydon@gmail.com>".italic().dimmed()
        ))
        .long_about(format!(
            "{} {}\n{}",
            "Turning text into",
            "GIBBERISH".bold(),
            "Quickly en-/decode // en-/decrypt files 'on the fly'",
        ))
        // TODO update version
        .version("1.7.0")
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
            Arg::new("copy")
                .short('c')
                .long("copy")
                .help("Create a copy of the file")
                .long_help("Create a copy of the file in the config directory")
                .action(ArgAction::SetTrue)
                .conflicts_with("list"),
        )
        .arg(
            Arg::new("decode")
                .short('d')
                .long("decode")
                .help("Decode/Decrypt the file")
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("DECODING/DECRYPTING METHOD")
                .conflicts_with("encode"),
        )
        .arg(
            Arg::new("encode")
                .short('e')
                .long("encode")
                .help("Encode/Encrypt the file")
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("ENCODING/ENCRYPTING METHOD"),
        )
        .arg(
            Arg::new("key")
                .short('k')
                .long("key")
                .help("Use a specific key for encoding")
                .long_help(format!(
                    "{}\n{}\n{}\n{}\n{}",
                    "Use a specific key for encoding",
                    "If the encoding method allows a custom key, you will get prompted to enter a key",
                    "To decode this file again correctly, the same key must be used",
                    "This flag gets ignored if the encoding method doesn`t allow a specific key",
                    "This is NOT a password",
                ))
                .action(ArgAction::SetTrue)
                .conflicts_with("list"),
        )
        .arg(
            Arg::new("l33t")
                .short('3')
                .long("l33t")
                .help("Set l33t mode")
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("Mode")
                .value_parser(["soft", "hard"])
                .default_value("soft"),
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
            Arg::new("sign")
                .short('s')
                .long("sign")
                .help("Verify a file with a signature")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["decode", "encode", "list"]),
        )
        .subcommand(
            Command::new("log")
                .short_flag('L')
                .long_flag("log")
                .about("Show content of the log file"),
        )
}

// TODO add default_decoding??
// fn default_encoding(path: &PathBuf, content: &String) -> io::Result<()> {
//     // let hash = String::new();
//     // let key = String::new();
//     // let xored = encode_decode_xor(&content.clone().into_bytes(), key.clone())?;
//     // let encoded = encode_hex(xored)?;
//     let b64 = encode_base64ct(content)?;
//     let encoded = encode_hex(&b64)?;

//     // write_utf8_content(&path, hash.clone(), &encoded)?;
//     write_non_utf8_content(&path, &encoded)?;

//     // read in bytes here
//     let byte_content = read_non_utf8(&path)?;

//     let hex_decoded = decode_hex(&byte_content)?;
//     let decoded = decode_base64ct(&String::from_utf8(hex_decoded).unwrap())?;

//     // write_utf8_content(&path, hash, &decoded)?;
//     write_non_utf8_content(&path, &decoded)?;

//     Ok(())
// }
