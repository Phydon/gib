use log::{error, info};

use std::{collections::HashMap, io, process, str::FromStr};

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

pub fn encode_decode_l33t(byte_content: &Vec<u8>, mode: &String) -> io::Result<Vec<u8>> {
    let l33t_alphabet = match mode.parse::<L33t>().unwrap() {
        L33t::Hard => l33t_alphabet_hard(),
        L33t::Soft => l33t_alphabet_soft(),
    };

    let content = String::from_utf8(byte_content.to_owned()).unwrap_or_else(|_| {
        error!("Unable to read non-utf8 content");
        process::exit(0);
    });
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

#[test]
fn encode_l33t_soft_test() {
    assert_eq!(
        encode_decode_l33t(
            &"This is a test".to_string().into_bytes(),
            &"soft".to_string()
        )
        .unwrap(),
        "Th!5 !5 4 7357".as_bytes()
    );
}

#[test]
fn decode_l33t_soft_test() {
    assert_eq!(
        encode_decode_l33t(
            &"T357!n6 47 !7`5 8357".to_string().into_bytes(),
            &"soft".to_string()
        )
        .unwrap(),
        "Testing at it`s best".as_bytes()
    );
}

#[test]
fn encode_l33t_soft_multi_lines_test() {
    assert_eq!(
        encode_decode_l33t(
            &"This is a test.\nWith multiple lines in it.\nYour welcome."
                .to_string()
                .into_bytes(),
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
            &"Th!5 mu17! 1!n3 7357!n6,\n!5 w0rk!n6.\nOr !5 !7?"
                .to_string()
                .into_bytes(),
            &"soft".to_string()
        )
        .unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}

#[test]
fn encode_l33t_hard_test() {
    assert_eq!(
        encode_decode_l33t(
            &"This is a test".to_string().into_bytes(),
            &"hard".to_string()
        )
        .unwrap(),
        "T#!5 !5 @ 7357".as_bytes()
    );
}

#[test]
fn decode_l33t_hard_test() {
    assert_eq!(
        encode_decode_l33t(
            &"T357!n6 @7 !7`5 8357".to_string().into_bytes(),
            &"hard".to_string()
        )
        .unwrap(),
        "Testing at it`s best".as_bytes()
    );
}

#[test]
fn encode_l33t_hard_multi_lines_test() {
    assert_eq!(
        encode_decode_l33t(
            &"This is a test.\nWith multiple lines in it.\nYour welcome."
                .to_string()
                .into_bytes(),
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
            &"T#!5 mu17! 1!n3 7357!n6,\n!5 w0rk!n6.\nØr !5 !7?"
                .to_string()
                .into_bytes(),
            &"hard".to_string()
        )
        .unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}
