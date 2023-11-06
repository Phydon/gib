use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info};
use owo_colors::colored::*;

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub const SPINNER_DOTS: &[&str; 8] = &[".  ", ".. ", "...", "   ", "  .", " ..", "...", "   "];

pub fn prompt_user_for_input(pb: ProgressBar, msg: String) -> String {
    pb.suspend(|| {
        println!("{}", msg);
    });
    let pw_spin_style = ProgressStyle::with_template("{spinner:.black}").unwrap();
    pb.set_style(pw_spin_style.tick_chars("⬛⬛⬛⬛"));
    pb.enable_steady_tick(Duration::from_millis(20));

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    pb.enable_steady_tick(Duration::from_millis(120));

    input.trim().to_string()
}

pub fn file_is_emtpy(path: &PathBuf) -> bool {
    let file_size = fs::metadata(path)
        .expect("Unable to read file metadata")
        .len();
    if file_size <= 0 {
        return true;
    }

    false
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
    fs::copy(source_path, &dest_path)?;

    pb.suspend(|| {
        info!("Backup at {}", dest_path.display());
    });

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
