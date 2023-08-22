use log::{error, info};
use std::{process, str::FromStr};

use strum::IntoEnumIterator;
use strum_macros::EnumIter;

// TODO add more methods
// available methods for en-/decoding // en-/decrypting
#[derive(Debug, EnumIter)]
pub enum Method {
    Base64ct,
    Caesar,
    // ColumnarTransposition,
    // Feistel, // encrypt == decrypt (use as default?)
    Hex,
    // LeannCrypt,
    L33t,
    // RC4,
    XOR,
}

#[derive(Debug)]
pub struct MethodError;

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

// list all available methods
pub fn list_methods() {
    for method in Method::iter() {
        println!("{:?}", method);
    }
}
