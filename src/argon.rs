use argon2::{self, Config};
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::colored::*;

const SPINNER_BINARY: &[&str; 10] = &[
    "010010", "001100", "100101", "111010", "111101", "010111", "101011", "111000", "110011",
    "110101",
];

pub fn calculate_hash(pb: ProgressBar, password: String) -> String {
    let calc_hash_spin_style = ProgressStyle::with_template("{spinner:.white} {msg}").unwrap();
    pb.set_style(calc_hash_spin_style.tick_strings(SPINNER_BINARY));
    pb.set_message(format!("{}", "calculating hash ...".truecolor(250, 0, 104)));

    let salt = b"gibberish_salt";
    let config = Config::rfc9106();
    let hash =
        argon2::hash_encoded(password.as_bytes(), salt, &config).expect("Unable to hash password");

    hash
}

pub fn verify_hash(pb: ProgressBar, hash: String, password: String) -> bool {
    let verify_hash_spin_style = ProgressStyle::with_template("{spinner:.white} {msg}").unwrap();
    pb.set_style(verify_hash_spin_style.tick_strings(SPINNER_BINARY));
    pb.set_message(format!("{}", "verifying hash ...".truecolor(250, 0, 104)));

    let matches =
        argon2::verify_encoded(&hash, password.as_bytes()).expect("Unable to verify hash");

    matches
}
