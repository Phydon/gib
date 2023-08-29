use std::io::{self, ErrorKind};

use argon2::{self, Config};
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::colored::*;

const SPINNER_BINARY: &[&str; 10] = &[
    "010010", "001100", "100101", "111010", "111101", "010111", "101011", "111000", "110011",
    "110101",
];

pub fn calculate_hash(pb: ProgressBar, text: &Vec<u8>) -> String {
    let calc_hash_spin_style = ProgressStyle::with_template("{msg} {spinner:.white}").unwrap();
    pb.set_style(calc_hash_spin_style.tick_strings(SPINNER_BINARY));
    pb.set_message(format!("{}", "calculating hash".truecolor(250, 0, 104)));

    let salt = b"gibberish_salt";
    let config = Config::rfc9106();
    let hash = argon2::hash_encoded(text, salt, &config).expect("Unable to hash input");

    hash
}

pub fn verify_hash(pb: ProgressBar, hash: &String, text: &Vec<u8>) -> bool {
    let verify_hash_spin_style = ProgressStyle::with_template("{msg} {spinner:.white}").unwrap();
    pb.set_style(verify_hash_spin_style.tick_strings(SPINNER_BINARY));
    pb.set_message(format!("{}", "verifying hash".truecolor(250, 0, 104)));

    let matches = argon2::verify_encoded(&hash, text).expect("Unable to verify hash");

    matches
}

pub fn extract_hash(filecontent: &Vec<u8>) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let argon2_hash_length = 96;

    // check if length filecontent >= length argon2 hash
    if filecontent.len() < argon2_hash_length {
        return Err(io::Error::from(ErrorKind::InvalidInput));
    }

    assert!(filecontent.len() >= argon2_hash_length);

    // TODO better way than cloning?
    let mut hash = filecontent.clone();
    let mut rest: Vec<u8> = hash.drain(argon2_hash_length..).collect();

    // remove the 97th byte (== '\n')
    // => written when adding hash to file
    rest.remove(0);

    Ok((hash.to_owned(), rest))
}
