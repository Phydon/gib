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
    collections::HashMap,
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
const SPINNER_DOTS: &[&str; 8] = &[".  ", ".. ", "...", "   ", "  .", " ..", "...", "   "];

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
    // ColumnarTransposition,
    // Feistel, // encrypt == decrypt (use as default?)
    Hex,
    L33t,
    // RC4,
    XOR,
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
            "l33t" | "1337" | "leet" => Ok(Method::L33t),
            "xor" => Ok(Method::XOR),
            _ => {
                error!("{:?}: Unknown method", MethodError);
                info!("Type: 'gib --list' to see all available methods");
                process::exit(0);
            }
        }
    }
}

#[derive(Debug, Clone)]
enum L33t {
    Hard,
    Soft,
}

#[derive(Debug)]
struct L33tError;

impl FromStr for L33t {
    type Err = L33tError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "hard" => Ok(L33t::Hard),
            "soft" => Ok(L33t::Soft),
            _ => {
                error!("{:?}: Unknown l33t mode", L33tError);
                info!("Available l33t modes: soft (default) & hard");
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
            let (hash, content) = read_file_content(&path.to_path_buf(), CodingMethod::Decoding)?;

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

// list all available methods
fn list_methods() {
    for method in Method::iter() {
        println!("{:?}", method);
    }
}

fn prompt_user_for_input(pb: ProgressBar, msg: String) -> String {
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

    input.trim().to_string()
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
    let encoded = Base64::encode_string(content.as_bytes());
    Ok(encoded.into_bytes())
}

fn decode_base64ct(content: String) -> io::Result<Vec<u8>> {
    let decoded = Base64::decode_vec(&content).expect("Error while decoding file");
    Ok(decoded)
}

// based on https://github.com/TheAlgorithms/Rust
fn encode_caesar(content: String) -> io::Result<Vec<u8>> {
    // TODO let user choose a key between 1 <= key <= 26
    // key = 13 == ROT13 (encrypting and decrypting is its own inverse)
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
// FIXME no new lines when writing decoded content back to file
fn decode_caesar(content: String) -> io::Result<Vec<u8>> {
    // TODO get key from user
    // key = 13 == ROT13 (encrypting and decrypting is its own inverse)
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

    let encoded = hex::encode(content.to_string());

    Ok(encoded.into_bytes())
}

fn decode_hex(content: String) -> io::Result<Vec<u8>> {
    // TODO error in crate hex?
    // unable to convert '§' <-> 'a7'

    let decoded = hex::decode(&content).expect("Error while decoding file");

    Ok(decoded)
}

// convert char to l33t
fn l33t_alphabet_hard() -> HashMap<&'static str, &'static str> {
    let l33t_alphabet: HashMap<&'static str, &'static str> = HashMap::from([
        ("a", "@"),
        ("@", "a"),
        ("b", "8"),
        ("8", "b"),
        ("c", "{"),
        ("{", "c"),
        ("e", "3"),
        ("3", "e"),
        ("g", "6"),
        ("6", "g"),
        ("h", "#"),
        ("#", "h"),
        ("i", "!"),
        ("!", "i"),
        ("l", "1"),
        ("1", "l"),
        ("o", "0"),
        ("0", "o"),
        ("p", "9"),
        ("9", "p"),
        ("s", "5"),
        ("5", "s"),
        ("t", "7"),
        ("7", "t"),
        ("x", "%"),
        ("%", "x"),
        ("z", "2"),
        ("2", "z"),
        ("(", ")"),
        (")", "("),
        ("A", "4"),
        ("4", "A"),
        ("B", "ß"),
        ("ß", "B"),
        ("C", "©"),
        ("©", "C"),
        ("E", "€"),
        ("€", "E"),
        ("J", "√"),
        ("√", "J"),
        ("N", "И"),
        ("И", "N"),
        ("O", "Ø"),
        ("Ø", "O"),
        ("R", "®"),
        ("®", "R"),
        ("S", "$"),
        ("$", "S"),
        ("Ш", "W"),
        ("W", "Ш"),
        ("Y", "¥"),
        ("¥", "Y"),
    ]);

    l33t_alphabet
}

// convert char to l33t soft
// TODO remove more pairs for better readability in soft mode???
fn l33t_alphabet_soft() -> HashMap<&'static str, &'static str> {
    let l33t_alphabet: HashMap<&'static str, &'static str> = HashMap::from([
        ("a", "4"),
        ("4", "a"),
        ("b", "8"),
        ("8", "b"),
        ("e", "3"),
        ("3", "e"),
        ("g", "6"),
        ("6", "g"),
        ("i", "!"),
        ("!", "i"),
        ("1", "l"),
        ("l", "1"),
        ("o", "0"),
        ("0", "o"),
        ("5", "s"),
        ("s", "5"),
        ("t", "7"),
        ("7", "t"),
        ("z", "2"),
        ("2", "z"),
    ]);

    l33t_alphabet
}

fn encode_decode_l33t(content: String, mode: &String) -> io::Result<Vec<u8>> {
    let l33t_alphabet = match mode.parse::<L33t>().unwrap() {
        L33t::Hard => l33t_alphabet_hard(),
        L33t::Soft => l33t_alphabet_soft(),
    };

    let encoded: String = content
        .chars()
        .map(|char| {
            l33t_alphabet
                .get(char.to_string().as_str())
                .unwrap_or(&char.to_string().as_str())
                .to_string()
        })
        .collect();

    Ok(encoded.into_bytes())
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

fn reduce_string(string: &mut String) -> String {
    while string.len() >= (u64::MAX as usize).to_string().len() {
        string.pop();
    }

    string.to_owned()
}

fn reduce_num(number: u64) -> u8 {
    let mut num = number as f64;

    while num > u8::MAX as f64 {
        num = num.sqrt();
    }

    num.round() as u8
}

fn convert_string_to_number(string: String) -> u8 {
    let mut s = String::new();
    for b in string.into_bytes() {
        s.push_str(&b.to_string());
    }

    let shrinked_s = reduce_string(&mut s);
    // make sure that returning string len() isn`t out of range of u64
    assert!(shrinked_s.len() < u64::MAX as usize);

    let n: u64 = shrinked_s.parse().unwrap();

    let num: u8 = reduce_num(n);
    // make sure that returning number isn`t out of range of u8
    assert!(num < u8::MAX);

    num
}

// FIXME decodes to non-uf8-data, which cannot be read
fn encode_decode_xor(content: String, key: String) -> io::Result<Vec<u8>> {
    let mut keystring = String::new();
    if key.is_empty() {
        keystring.push_str("42");
    } else {
        keystring.push_str(&key);
    }

    let keynum = convert_string_to_number(keystring);
    let encoded: Vec<u8> = content.as_bytes().iter().map(|c| c ^ keynum).collect();

    Ok(encoded)
}

// FIXME panics when reading non-utf-8 data -> extra function
fn read_file_content(path: &PathBuf, codingmethod: CodingMethod) -> io::Result<(String, String)> {
    let file_size = fs::metadata(path)?.len();
    if file_size <= 0 {
        warn!("The file is emtpy");
        process::exit(0);
    }

    let file = fs::File::open(path)?;
    let buf_reader = BufReader::new(file);
    let mut buffer_lines = buf_reader
        .lines()
        // TODO handle non-utf-8 data
        .map(|line| line.expect("Failed to read line in encoded file"));

    let first_line: String = buffer_lines
        .next()
        .expect("The file shouldn`t be empty")
        .parse()
        .unwrap();

    let mut rest = String::new();
    for line in buffer_lines {
        rest.push_str(&line);

        match codingmethod {
            // FIXME??
            CodingMethod::Decoding => {}
            CodingMethod::Encoding => rest.push_str("\n"),
        }
    }

    //remove '\n' from last line
    rest.pop();

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
    // FIXME when decoding (hex /) caesar -> no new lines
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

// make copy in config directory
fn make_file_copy(pb: ProgressBar, source_path: &PathBuf, config_dir: &PathBuf) -> io::Result<()> {
    let pw_spin_style = ProgressStyle::with_template("{spinner:.red} {msg}").unwrap();
    pb.set_style(pw_spin_style.tick_strings(SPINNER_DOTS));
    pb.set_message(format!("{}", "copying file ...".truecolor(250, 0, 104)));

    // get config dir
    let mut dest = PathBuf::new();
    dest.push(config_dir);
    // get filename and prepend 'copy_of_'
    let mut filename = "copy_of_".to_string();
    let name = source_path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    filename.push_str(&name);
    // join config dir and new filename
    let dest_path = dest.join(filename);

    // copy source to destination
    // TODO replace with crate fs_extra when working with directories
    fs::copy(source_path, dest_path)?;

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
fn encode_base64ct_multi_lines_test() {
    assert_eq!(
        encode_base64ct("This is a test.\nWith multiple lines in it.\nYour welcome.".to_string())
            .unwrap(),
        "VGhpcyBpcyBhIHRlc3QuCldpdGggbXVsdGlwbGUgbGluZXMgaW4gaXQuCllvdXIgd2VsY29tZS4=".as_bytes()
    );
}

#[test]
fn decode_base64ct_multi_lines_test() {
    assert_eq!(
        decode_base64ct(
            "VGhpcyBtdWx0aSBsaW5lIHRlc3RpbmcsCmlzIHdvcmtpbmcuCk9yIGlzIGl0Pw==".to_string()
        )
        .unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
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
fn encode_caesar_multi_lines_test() {
    assert_eq!(
        encode_caesar("This is a test.\nWith multiple lines in it.\nYour welcome.".to_string())
            .unwrap(),
        "Guvf vf n grfg.\nJvgu zhygvcyr yvarf va vg.\nLbhe jrypbzr.".as_bytes()
    );
}

#[test]
fn decode_caesar_multi_lines_test() {
    assert_eq!(
        decode_caesar("Guvf zhygv yvar grfgvat,\nvf jbexvat.\nBe vf vg?".to_string()).unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
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
        encode_hex("Random chars: !\"$%&/()=?`+#*'-_~@".to_string()).unwrap(),
        "52616e646f6d2063686172733a2021222425262f28293d3f602b232a272d5f7e40".as_bytes()
    );
}

#[test]
fn decode_hex_special_chars_test() {
    assert_eq!(
        decode_hex(
            "52616e646f6d2063686172733a2021222425262f28293d3f602b232a272d5f7e40".to_string()
        )
        .unwrap(),
        "Random chars: !\"$%&/()=?`+#*'-_~@".as_bytes()
    );
}

#[test]
// FIXME it should NOT panic
#[should_panic(expected = "assertion failed")]
// error in hex crate ???
fn encode_hex_special_chars_test_2() {
    assert_eq!(encode_hex("§".to_string()).unwrap(), "a7".as_bytes());
}

#[test]
// FIXME it should NOT panic
#[should_panic(expected = "assertion failed")]
// error in hex crate ???
fn decode_hex_special_chars_test_2() {
    assert_eq!(decode_hex("a7".to_string()).unwrap(), "§".as_bytes());
}

#[test]
fn encode_hex_multi_lines_test() {
    assert_eq!(
        encode_hex("This is a test.\nWith multiple lines in it.\nYour welcome.".to_string())
            .unwrap(),
        "54686973206973206120746573742e0a57697468206d756c7469706c65206c696e657320696e2069742e0a596f75722077656c636f6d652e".as_bytes()
    );
}

#[test]
fn decode_hex_multi_lines_test() {
    assert_eq!(
        decode_hex("54686973206d756c7469206c696e652074657374696e672c0a697320776f726b696e672e0a4f722069732069743f".to_string()).unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}

#[test]
fn encode_l33t_soft_test() {
    assert_eq!(
        encode_decode_l33t("This is a test".to_string(), &"soft".to_string()).unwrap(),
        "Th!5 !5 4 7357".as_bytes()
    );
}

#[test]
fn decode_l33t_soft_test() {
    assert_eq!(
        encode_decode_l33t("T357!n6 47 !7`5 8357".to_string(), &"soft".to_string()).unwrap(),
        "Testing at it`s best".as_bytes()
    );
}

#[test]
fn encode_l33t_soft_multi_lines_test() {
    assert_eq!(
        encode_decode_l33t(
            "This is a test.\nWith multiple lines in it.\nYour welcome.".to_string(),
            &"soft".to_string()
        )
        .unwrap(),
        "Th!5 !5 4 7357.\nW!7h mu17!p13 1!n35 !n !7.\nY0ur w31c0m3.".as_bytes()
    );
}

#[test]
fn decode_l33t_soft_multi_lines_test() {
    assert_eq!(
        encode_decode_l33t(
            "Th!5 mu17! 1!n3 7357!n6,\n!5 w0rk!n6.\nOr !5 !7?".to_string(),
            &"soft".to_string()
        )
        .unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}

#[test]
fn encode_l33t_hard_test() {
    assert_eq!(
        encode_decode_l33t("This is a test".to_string(), &"hard".to_string()).unwrap(),
        "T#!5 !5 @ 7357".as_bytes()
    );
}

#[test]
fn decode_l33t_hard_test() {
    assert_eq!(
        encode_decode_l33t("T357!n6 @7 !7`5 8357".to_string(), &"hard".to_string()).unwrap(),
        "Testing at it`s best".as_bytes()
    );
}

#[test]
fn encode_l33t_hard_multi_lines_test() {
    assert_eq!(
        encode_decode_l33t(
            "This is a test.\nWith multiple lines in it.\nYour welcome.".to_string(),
            &"hard".to_string()
        )
        .unwrap(),
        "T#!5 !5 @ 7357.\nШ!7# mu17!913 1!n35 !n !7.\n¥0ur w31{0m3.".as_bytes()
    );
}

#[test]
fn decode_l33t_hard_multi_lines_test() {
    assert_eq!(
        encode_decode_l33t(
            "T#!5 mu17! 1!n3 7357!n6,\n!5 w0rk!n6.\nØr !5 !7?".to_string(),
            &"hard".to_string()
        )
        .unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}

#[test]
fn encode_xor_test() {
    assert_eq!(
        encode_decode_xor(
            "This is a test".to_string(),
            "randomkeyfoundinherethatshouldnotbetobigforthisfunction".to_string()
        )
        .unwrap(),
        "~BCY
CY
K
^OY^"
            .as_bytes()
    );
}

#[test]
fn decode_xor_test() {
    assert_eq!(
        encode_decode_xor(
            "~OY^CDM
K^
C^JY
HOY^"
                .to_string(),
            "randomkey".to_string()
        )
        .unwrap(),
        "Testing at it`s best".as_bytes()
    );
}

#[test]
fn encode_xor_multi_lines_test() {
    assert_eq!(
        encode_decode_xor(
            "This is a test.\nWith multiple lines in it.\nYour welcome.".to_string(),
            "randomkey".to_string()
        )
        .unwrap(),
        "~BCY
CY
K
^OY^ }C^B
G_F^CZFO
FCDOY
CD
C^ sE_X
]OFIEGO"
            .as_bytes()
    );
}

#[test]
fn decode_xor_multi_lines_test() {
    assert_eq!(
        encode_decode_xor(
            "~BCY
G_F^C
FCDO
^OY^CDM CY
]EXACDM eX
CY
C^"
            .to_string(),
            "randomkey".to_string()
        )
        .unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}
