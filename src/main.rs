mod argon;
mod base64ct;
mod caesar;
mod hex;
mod l33t;
mod methods;
mod utils;
mod xor;

use crate::argon::{calculate_hash, verify_hash};
use crate::base64ct::{decode_base64ct, encode_base64ct};
use crate::caesar::{decode_caesar, encode_caesar};
use crate::hex::{decode_hex, encode_hex};
use crate::methods::{list_methods, CodingMethod, Method};
use crate::utils::{
    check_create_config_dir, make_file_copy, prompt_user_for_input, read_file_content,
    read_non_utf8_file, show_log_file, write_file_content,
};
use crate::xor::encode_decode_xor;
use clap::{Arg, ArgAction, Command};
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use indicatif::{ProgressBar, ProgressStyle};
use l33t::encode_decode_l33t;
use log::{error, info, warn};
use owo_colors::colored::*;

use std::{
    error::Error,
    io,
    path::{Path, PathBuf},
    process,
    time::Duration,
};

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
    let password_flag = matches.get_flag("password");
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
            make_file_copy(pb.clone(), &path.to_path_buf(), &config_dir)?;
        }

        // start encoding / decoding
        if let Some(method) = matches.get_one::<String>("encode") {
            let mut hash = String::new();
            if password_flag {
                let mut password = String::new();
                loop {
                    let pw = prompt_user_for_input(pb.clone(), "Enter password".to_string());
                    let pw_confirmation =
                        prompt_user_for_input(pb.clone(), "Confirm password".to_string());

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

            // FIXME handle non-utf-8 data -> catch error and use another function instead
            // let (_, content) = read_file_content(&path.to_path_buf(), CodingMethod::Encoding)?;
            let mut content = String::new();
            match read_file_content(&path.to_path_buf(), CodingMethod::Encoding) {
                Ok((_, cont)) => content.push_str(&cont),
                Err(err) => match err.kind() {
                    io::ErrorKind::InvalidData => {
                        let (_, cont) =
                            read_non_utf8_file(&path.to_path_buf(), CodingMethod::Encoding)?;
                        content.push_str(&cont);
                    }
                    _ => {
                        error!("Unable to read file");
                        process::exit(1);
                    }
                },
            }

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
                Method::L33t => {
                    // there should always be at least the default mode
                    if let Some(mode) = matches.get_one::<String>("l33t") {
                        let mut l33t_encoded_vec = encode_decode_l33t(content, mode)?;
                        encoded.append(&mut l33t_encoded_vec);
                    }
                }
                Method::XOR => {
                    let mut key = String::new();
                    if key_flag {
                        let input = prompt_user_for_input(pb.clone(), "Enter a key".to_string());
                        key.push_str(&input);
                    }

                    let mut xor_encoded_vec = encode_decode_xor(content, key)?;
                    encoded.append(&mut xor_encoded_vec);
                }
            }

            // write encoded / encrpyted content back to file
            write_file_content(&path.to_path_buf(), hash, &encoded)?;
            // FIXME error while decoding (e.g. xor encode and decode)
            // FIXME removes a char at the end of line
        } else if let Some(method) = matches.get_one::<String>("decode") {
            // non utf-8 data could be written to file via encrypting methods
            // -> reading the encoded / encrypted content from the file must be handled
            // seperatly incase non utf-8 data from the file should be handled differently
            // FIXME handle non-utf-8 data -> catch error and use another function instead
            // let (hash, content) = read_file_content(&path.to_path_buf(), CodingMethod::Decoding)?;
            let mut content = String::new();
            let mut hash = String::new();
            match read_file_content(&path.to_path_buf(), CodingMethod::Decoding) {
                Ok((h, c)) => {
                    content.push_str(&c);
                    hash.push_str(&h);
                }
                Err(err) => match err.kind() {
                    io::ErrorKind::InvalidData => {
                        let (h, c) =
                            read_non_utf8_file(&path.to_path_buf(), CodingMethod::Decoding)?;
                        content.push_str(&c);
                        hash.push_str(&h);
                    }
                    _ => {
                        error!("Unable to read file");
                        process::exit(1);
                    }
                },
            }

            if password_flag {
                let password = prompt_user_for_input(pb.clone(), "Enter password".to_string());
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
                Method::L33t => {
                    // there should always be at least the default mode
                    if let Some(mode) = matches.get_one::<String>("l33t") {
                        let mut l33t_decoded_vec = encode_decode_l33t(content, mode)?;
                        decoded.append(&mut l33t_decoded_vec);
                    }
                }
                Method::XOR => {
                    let mut key = String::new();
                    if key_flag {
                        let input = prompt_user_for_input(pb.clone(), "Enter a key".to_string());
                        key.push_str(&input);
                    }

                    // FIXME
                    let mut xor_decoded_vec = encode_decode_xor(content, key)?;
                    decoded.append(&mut xor_decoded_vec);
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

            // make copy in config directory
            make_file_copy(pb.clone(), &path.to_path_buf(), &config_dir)?;

            // default encoding
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
        .version("1.4.0")
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

fn default_encoding(path: &PathBuf) -> io::Result<()> {
    // let (_, content) = read_file_content(&path.to_path_buf(), CodingMethod::Encoding)?;
    let mut content = String::new();
    let hash = String::new();
    match read_file_content(&path.to_path_buf(), CodingMethod::Encoding) {
        Ok((_, c)) => {
            content.push_str(&c);
        }
        Err(err) => match err.kind() {
            io::ErrorKind::InvalidData => {
                let (_, c) = read_non_utf8_file(&path.to_path_buf(), CodingMethod::Encoding)?;
                content.push_str(&c);
            }
            _ => {
                error!("Unable to read file");
                process::exit(1);
            }
        },
    }

    let mut encoded_base64 = Vec::new();
    let mut tmp_base64_encoded_vec = encode_base64ct(content)?;
    encoded_base64.append(&mut tmp_base64_encoded_vec);

    // write encrpyted content back to file
    write_file_content(&path.to_path_buf(), hash.clone(), &encoded_base64)?;

    Ok(())
}
