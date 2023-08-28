use indicatif::{ProgressBar, ProgressStyle};
use log::{error, warn};
use owo_colors::colored::*;

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
    time::Duration,
};

pub const SPINNER_DOTS: &[&str; 8] = &[".  ", ".. ", "...", "   ", "  .", " ..", "...", "   "];

pub fn prompt_user_for_input(pb: ProgressBar, msg: String) -> String {
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

pub fn convert_string_to_number(string: String) -> u8 {
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

pub fn check_file_size(path: &PathBuf) {
    let file_size = fs::metadata(path)
        .expect("Unable to read file metadata")
        .len();
    if file_size <= 0 {
        warn!("The file is emtpy");
        process::exit(0);
    }
}

pub fn read_file_content(path: &PathBuf) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);

    Ok(buf)
}

pub fn write_non_utf8_content(path: &PathBuf, content: &Vec<u8>) -> io::Result<()> {
    let mut newfile = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)?;

    newfile.write_all(&content)?;

    Ok(())
}

// make copy in config directory
pub fn make_file_copy(
    pb: ProgressBar,
    source_path: &PathBuf,
    config_dir: &PathBuf,
) -> io::Result<()> {
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

pub fn check_create_config_dir() -> io::Result<PathBuf> {
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

pub fn show_log_file(config_dir: &PathBuf) -> io::Result<String> {
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
