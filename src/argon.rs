use argon2::{self, Config, Variant, Version};
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::colored::*;

const SPINNER_BINARY: &[&str; 10] = &[
    "010010", "001100", "100101", "111010", "111101", "010111", "101011", "111000", "110011",
    "110101",
];
const SALT: &[u8] = b"gibberish_salt";

pub fn calculate_hash(raw: bool, pb: ProgressBar, password: &Vec<u8>) -> Vec<u8> {
    let calc_hash_spin_style = ProgressStyle::with_template("{msg} {spinner:.white}").unwrap();
    pb.set_style(calc_hash_spin_style.tick_strings(SPINNER_BINARY));
    pb.set_message(format!("{}", "calculating hash".truecolor(250, 0, 104)));

    // INFO use low memory config for performance boost
    // let config = Config::rfc9106_low_mem();
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 3,
        lanes: 1,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };

    if raw {
        let hash = argon2::hash_raw(password, SALT, &config).expect("Unable to hash input");

        hash
    } else {
        let hash = argon2::hash_encoded(password, SALT, &config).expect("Unable to hash input");

        hash.into_bytes()
    }
}

pub fn verify_hash(pb: ProgressBar, hash: &Vec<u8>, password: &Vec<u8>) -> bool {
    let verify_hash_spin_style = ProgressStyle::with_template("{msg} {spinner:.white}").unwrap();
    pb.set_style(verify_hash_spin_style.tick_strings(SPINNER_BINARY));
    pb.set_message(format!("{}", "verifying hash".truecolor(250, 0, 104)));

    // rfc9106_low_mem
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 3,
        lanes: 1,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };

    let matches = argon2::verify_raw(password, SALT, hash, &config).expect("Unable to verify hash");

    matches
}

pub fn extract_hash(filecontent: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    // INFO if the hash config changes, this changes as well (most likely)
    let argon2_hash_length = 53; // argon_identifier + hash (base64 encoded)
    assert!(filecontent.len() >= argon2_hash_length);

    // TODO better way than cloning?
    let mut tmp = filecontent.clone();
    let mut rest: Vec<u8> = tmp.drain(argon2_hash_length..).collect();

    // remove argon_identifier
    let hash: Vec<u8> = tmp.drain(9..).collect();

    // remove the '\n' byte
    // => written when adding hash to file
    rest.remove(0);

    (hash, rest)
}
