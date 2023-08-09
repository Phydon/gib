use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use clap::{Arg, ArgAction, Command};
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use indicatif::{ProgressBar, ProgressStyle};
use log::error;
use owo_colors::colored::*;

use std::{
    fs,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    process,
    time::Duration,
};

fn main() {
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
    let decode_flag = matches.get_flag("decode");

    if let Some(arg) = matches.get_one::<String>("arg") {
        // get search path from arguments
        let path = Path::new(arg);

        if !path.exists() {
            error!("The file doesn`t exist");
            process::exit(1);
        }

        // TODO use threading
        // TODO use multiple spinners
        // spinner
        let spinner_style = ProgressStyle::with_template("{spinner:.red} {msg}").unwrap();
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(spinner_style);

        // start encoding / decoding
        if decode_flag {
            pb.set_message(format!("{}", "decoding...".truecolor(250, 0, 104)));
            decode(path.to_path_buf()).unwrap_or_else(|err| {
                error!("Error while decoding file {}: {}", path.display(), err);
            });
        } else {
            pb.set_message(format!("{}", "encoding...".truecolor(250, 0, 104)));
            encode(path.to_path_buf()).unwrap_or_else(|err| {
                error!("Error while encoding file {}: {}", path.display(), err);
            });
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
                unreachable!();
            }
        }
    }
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
        .long_about(format!("{}", "Quickly encode / decode files 'on the fly'",))
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
                .help("Decode the file")
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new("log")
                .short_flag('L')
                .long_flag("log")
                .about("Show content of the log file"),
        )
}

fn encode(path: PathBuf) -> io::Result<()> {
    // TODO require password for later decoding
    // println!("Enter a password");

    let file = fs::File::open(path)?;
    let mut buf_reader = BufReader::new(file);
    let mut content = String::new();
    buf_reader.read_to_string(&mut content)?;

    // The encryption key can be generated randomly:
    let key = Aes256Gcm::generate_key(OsRng);

    // // Transformed from a byte array:
    // let key: &[u8; 32] = &[42; 32];
    // let key: &Key<Aes256Gcm> = key.into();

    // // Note that you can get byte array from slice using the `TryInto` trait:
    // let key: &[u8] = &[42; 32];
    // let key: [u8; 32] = key.try_into()?;

    // // Alternatively, the key can be transformed directly from a byte slice
    // // (panicks on length mismatch):
    // let key = Key::<Aes256Gcm>::from_slice(key);

    let cipher = Aes256Gcm::new(&key);

    // // TODO make NOT random???
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    dbg!(&nonce);

    let ciphertext = cipher.encrypt(&nonce, content.as_ref()).unwrap();
    dbg!(&ciphertext);

    // TODO write encrypted content back to file
    // with the nonce at the first line??? for later decoding
    let mut newfile = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open("testingresult.txt")?;

    // FIXME how to write nonce to file???
    let nonce_string: String = nonce.try_into().unwrap();
    let ciphertext_string = ciphertext.bytes().collect();

    newfile.write_all(nonce_string)?;
    newfile.write_all(ciphertext_string)?;

    Ok(())
}

fn decode(path: PathBuf) -> io::Result<()> {
    unimplemented!();

    // let mut file = fs::File::open(path)?;
    // let mut buf_reader = BufReader::new(file);
    // let mut content = String::new();
    // buf_reader.read_to_string(&mut content)?;

    // TODO nonce == password???
    // let plaintext = cipher.decrypt(&nonce, content.as_ref()).unwrap();
    // dbg!(&plaintext);

    // TODO write decrpyted content back to file

    // Ok(())
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
