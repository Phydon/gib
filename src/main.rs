use base64ct::{Base64, Encoding};
use clap::{Arg, ArgAction, Command};
use flexi_logger::{detailed_format, Duplicate, FileSpec, Logger};
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, warn};
use owo_colors::colored::*;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use std::{
    fs,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    process,
    str::FromStr,
    time::Duration,
};

// TODO add more methods
// available methods for encoding / decoding
#[derive(Debug, EnumIter)]
enum Method {
    Base64ct,
    // TODO change this to another useful encoding method
    NoEncoding,
}

// TODO create a better error
#[derive(Debug)]
struct MethodError;

impl FromStr for Method {
    type Err = MethodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "base64ct" | "base64" => Ok(Method::Base64ct),
            "noencoding" => Ok(Method::NoEncoding),
            _ => {
                error!("{:?}: Unknown method", MethodError);
                process::exit(1);
            }
        }
    }
}

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
    let list_flag = matches.get_flag("list");

    if list_flag {
        // list all available encoding / decoding methods
        list_methods();
    } else if let Some(arg) = matches.get_one::<String>("arg") {
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
        if let Some(method) = matches.get_one::<String>("encode") {
            pb.set_message(format!("{}", "encoding...".truecolor(250, 0, 104)));

            match method.parse::<Method>().unwrap() {
                Method::Base64ct => {
                    encode_base64ct(path.to_path_buf()).unwrap_or_else(|err| {
                        error!("Error while encoding file {}: {}", path.display(), err);
                    });
                }
                _ => {
                    warn!("Unknown method");
                    process::exit(1);
                }
            }
        } else if let Some(method) = matches.get_one::<String>("decode") {
            pb.set_message(format!("{}", "decoding...".truecolor(250, 0, 104)));

            match method.parse::<Method>().unwrap() {
                Method::Base64ct => {
                    decode_base64ct(path.to_path_buf()).unwrap_or_else(|err| {
                        error!("Error while decoding file {}: {}", path.display(), err);
                    });
                }
                _ => {
                    warn!("Unknown method");
                    process::exit(1);
                }
            }
        } else {
            // TODO replace with something useful
            // TODO what should be the default command if nothing is specified?
            println!("Choose encoding or decoding");
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

    process::exit(0);
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
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("Decoding method")
                .conflicts_with("encode"),
        )
        .arg(
            Arg::new("encode")
                .short('e')
                .long("encode")
                .help("Encode the file")
                .action(ArgAction::Set)
                .num_args(1)
                .value_name("Encoding method")
                .value_parser(clap::builder::NonEmptyStringValueParser::new()),
        )
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .help("List all available encoding / decoding methods")
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
fn encode_base64ct(path: PathBuf) -> io::Result<()> {
    let content = read_file_content(&path)?;
    let encoded = Base64::encode_string(content.trim().to_string().as_bytes());
    // write encrypted content back to file
    write_file_content(&path, encoded.as_bytes())?;

    Ok(())
}

// FIXME remove undecoded rest from file
// TODO decoding base64 constant time
fn decode_base64ct(path: PathBuf) -> io::Result<()> {
    let content = read_file_content(&path)?;
    let decoded = Base64::decode_vec(&content).expect("Error while decoding file");
    // write decrpyted content back to file
    write_file_content(&path, &decoded)?;

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
    let mut newfile = fs::OpenOptions::new().write(true).create(true).open(path)?;
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
