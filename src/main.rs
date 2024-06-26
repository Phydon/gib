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
use log::{error, warn};
use owo_colors::colored::*;

use std::{error::Error, path::Path, process, time::Duration};

pub const SPINNER_ARC: &[&str; 6] = &["◜", "◠", "◝", "◞", "◡", "◟"];

fn main() -> Result<(), Box<dyn Error>> {
    // handle Ctrl+C
    ctrlc::set_handler(move || {
        println!("{}", "Received Ctrl-C!".italic());
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
    let copy_flag = matches.get_flag("copy");
    let hash_flag = matches.get_flag("hash");
    let list_flag = matches.get_flag("list");
    let sign_flag = matches.get_flag("sign");

    if list_flag {
        // list all available en-/decoding // en-/decrypting methods
        list_methods();
    } else if let Some(arg) = matches.get_one::<String>("arg") {
        // get filepath from arguments
        let path = Path::new(arg);

        if !path.exists() {
            error!(
                "{}",
                format!("The file '{}' doesn`t exist", &path.display())
            );
            process::exit(0);
        }

        // TODO handle directories
        if !path.is_file() {
            error!("{}", format!("Not a file: '{}'", &path.display()));
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

        // close if file is empty
        if file_is_emtpy(&path) {
            warn!("{}", format!("The file '{}' is emtpy", &path.display()));
            pb.finish_and_clear();
            process::exit(0);
        };

        // read file
        pb.set_message(format!("{}", "reading file...".truecolor(250, 0, 104)));

        // if encrypting methods write content separately to file
        // set writing_done variable to true
        let mut writing_done = false;

        // read file content as bytes
        let mut byte_content: Vec<u8> = read_file_content(&path)?;

        // for storing encoded / decoded content
        let mut encoded_decoded_content = Vec::new();

        // for storing hash
        let mut sign_hash = Vec::new();

        // handle flags
        if hash_flag {
            let hash_bytes = calculate_hash(false, pb.clone(), &byte_content);
            pb.finish_and_clear();
            let hash = String::from_utf8(hash_bytes).unwrap_or_else(|err| {
                error!(
                    "{}",
                    format!("Unable to hash file '{}': {}", &path.display(), err)
                );
                process::exit(0);
            });

            println!("{hash}");

            // no file changes needed
            writing_done = true;
        } else if sign_flag {
            // handle sign flag
            // for storing rest of the content if there is a hash
            let mut rest_byte_content = Vec::new();

            // check if filecontent already contains a hash
            if byte_content.starts_with("$argon2id".as_bytes()) {
                // extract hash from content
                let (hash_base64, mut rest) = extract_hash(&byte_content);
                // decode hash_base64
                let mut hash_base64_decoded = decode_base64ct(&hash_base64)?;

                sign_hash.append(&mut hash_base64_decoded);
                rest_byte_content.append(&mut rest);
            }

            if sign_hash.is_empty() {
                // for identifying hash in file
                let mut argon_identifier = "$argon2id".to_string().into_bytes();
                sign_hash.append(&mut argon_identifier);

                // calculate hash from file content
                let hash_string = calculate_hash(true, pb.clone(), &byte_content);
                // encode hash to base64 (otherwise hash is non-utf8)
                let mut hash_base64 = encode_base64ct(&hash_string)?;

                sign_hash.append(&mut hash_base64);
                sign_hash.push('\n' as u8);
            } else {
                // verify found hash in filecontent
                let verification = verify_hash(pb.clone(), &sign_hash, &rest_byte_content);
                if !verification {
                    pb.finish_and_clear();
                    warn!("Couldn`t verify file '{}'", &path.display());
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
                    let mut base64ct_encoded = encode_base64ct(&byte_content)?;
                    encoded_decoded_content.append(&mut base64ct_encoded);
                }
                Method::Caesar => {
                    let mut caesar_encoded = encode_caesar(&byte_content)?;
                    encoded_decoded_content.append(&mut caesar_encoded);
                }
                Method::ChaCha20Poly1305 => {
                    // ask user for password
                    // TODO extract into function
                    let mut key = Vec::new();
                    loop {
                        let input = prompt_user_for_input(pb.clone(), "Enter password".to_string());
                        let input_two =
                            prompt_user_for_input(pb.clone(), "Confirm password".to_string());

                        if input == input_two {
                            key.append(&mut input.into_bytes());
                            break;
                        }

                        println!("Try again");
                    }

                    let hashed_key = calculate_hash(true, pb.clone(), &key);
                    // TODO does pb get restored?

                    let mut chacha_encoded = encode_chacha(&hashed_key, &byte_content)
                        .unwrap_or_else(|err| {
                            pb.finish_and_clear();
                            warn!("{}", format!("Unable to encode content: {}", err));
                            process::exit(0);
                        });

                    encoded_decoded_content.append(&mut chacha_encoded);
                }
                Method::Hex => {
                    let mut hex_encoded = encode_hex(&byte_content)?;
                    encoded_decoded_content.append(&mut hex_encoded);
                }
                Method::L33t => {
                    // there should always be at least the default mode
                    if let Some(mode) = matches.get_one::<String>("l33t") {
                        let mut l33t_encoded = encode_decode_l33t(&byte_content, mode)?;
                        encoded_decoded_content.append(&mut l33t_encoded);
                    }
                }
                Method::Xor => {
                    let mut xor_encoded = encode_decode_xor(&byte_content)?;
                    encoded_decoded_content.append(&mut xor_encoded);
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
                    let mut base64ct_decoded = decode_base64ct(&byte_content)?;
                    encoded_decoded_content.append(&mut base64ct_decoded);
                }
                Method::Caesar => {
                    let mut caesar_decoded = decode_caesar(&byte_content)?;
                    encoded_decoded_content.append(&mut caesar_decoded);
                }
                Method::ChaCha20Poly1305 => {
                    // ask user for password
                    let mut key = Vec::new();
                    let input = prompt_user_for_input(pb.clone(), "Enter password".to_string());
                    key.append(&mut input.into_bytes());

                    let hashed_key = calculate_hash(true, pb.clone(), &key);
                    // TODO does pb get restored?

                    let (nonce, encrypted_text) = extract_nonce(&byte_content);

                    let mut chacha_decoded = decode_chacha(&hashed_key, &nonce, &encrypted_text)
                        .unwrap_or_else(|err| {
                            pb.finish_and_clear();
                            warn!("{}", format!("Unable to decode content: {}", err));
                            process::exit(0);
                        });
                    encoded_decoded_content.append(&mut chacha_decoded);
                }
                Method::Hex => {
                    let mut hex_decoded = decode_hex(&byte_content)?;
                    encoded_decoded_content.append(&mut hex_decoded);
                }
                Method::L33t => {
                    // there should always be at least the default mode
                    if let Some(mode) = matches.get_one::<String>("l33t") {
                        let mut l33t_decoded = encode_decode_l33t(&byte_content, mode)?;
                        encoded_decoded_content.append(&mut l33t_decoded);
                    }
                }
                Method::Xor => {
                    let mut xor_decoded = encode_decode_xor(&byte_content)?;
                    encoded_decoded_content.append(&mut xor_decoded);
                }
            }
        } else {
            // no hashing, no signing, no en-/decoding => nothing to do
            pb.finish_and_clear();
            let _ = gib().print_help();
            process::exit(0);
        }

        // write encoded/encrypted // decoded/decrpyted content back to file
        if !writing_done {
            if !sign_hash.is_empty() {
                // concat hash and rest of the byte_content
                let mut concated_hash_and_rest_bytes = sign_hash;
                concated_hash_and_rest_bytes.append(&mut byte_content);

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
                gib().print_help().unwrap();
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
        .version("1.8.6")
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
                .long_help(format!(
                    "{}\n{}",
                    "Create a copy of the file in the config directory",
                    "Use the '--log' flag to find the config directory"
                ))
                .action(ArgAction::SetTrue),
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
            Arg::new("hash")
                .short('H')
                .long("hash")
                .help("Return the hash of a file")
                .long_help(format!(
                    "{}\n{}",
                    "Return the hash of a file", "hashing algorithm: [ argon2id ]"
                ))
                .action(ArgAction::SetTrue),
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
                .conflicts_with_all(["copy", "decode", "encode", "hash", "sign"]),
        )
        .arg(
            Arg::new("sign")
                .short('s')
                .long("sign")
                .help("Verify a file with a signature")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["decode", "encode", "hash", "list"]),
        )
        .subcommand(
            Command::new("log")
                .short_flag('L')
                .long_flag("log")
                .about("Show content of the log file"),
        )
}
