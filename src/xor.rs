use std::io;

use crate::utils::convert_string_to_number;

// FIXME sometimes it cuts of last line
pub fn encode_decode_xor(content: &Vec<u8>, key: String) -> io::Result<Vec<u8>> {
    let mut keystring = String::new();
    if key.is_empty() {
        keystring.push_str("42");
    } else {
        keystring.push_str(&key);
    }

    let keynum = convert_string_to_number(keystring);
    let encoded: Vec<u8> = content.iter().map(|c| c ^ keynum).collect();

    Ok(encoded)
}

#[test]
fn encode_xor_easy_test() {
    let content = "This is a test".to_string().into_bytes();
    let key = String::new();
    let enc = encode_decode_xor(&content, key.clone()).unwrap();
    assert_eq!(content, encode_decode_xor(&enc, key).unwrap());
}

#[test]
fn xor_long_key_test() {
    let content = "This is a test".to_string().into_bytes();
    let key = "randomkeyfoundinherethatshouldnotbetobigforthisfunction".to_string();
    let enc = encode_decode_xor(&content, key.clone()).unwrap();
    assert_eq!(content, encode_decode_xor(&enc, key).unwrap());
}

#[test]
fn xor_short_key_test() {
    let content = "Testing at it`s best".to_string().into_bytes();
    let key = "randomkey".to_string();
    let enc = encode_decode_xor(&content, key.clone()).unwrap();
    let dec = encode_decode_xor(&enc, key.clone()).unwrap();
    assert_eq!(enc, encode_decode_xor(&dec, key).unwrap());
}

#[test]
fn xor_short_key_multi_lines_test() {
    let content = "This is a test.\nWith multiple lines in it.\nYour welcome."
        .to_string()
        .into_bytes();
    let key = "randomkey".to_string();
    let enc = encode_decode_xor(&content, key.clone()).unwrap();
    assert_eq!(content, encode_decode_xor(&enc, key).unwrap());
}

#[test]
fn xor_long_key_multi_lines_test() {
    let content = "This multi line testing,\nis working.\nOr is it?"
        .to_string()
        .into_bytes();
    let key = "randomkeyfoundinherethatshouldnotbetobigforthisfunction".to_string();
    let enc = encode_decode_xor(&content, key.clone()).unwrap();
    let dec = encode_decode_xor(&enc, key.clone()).unwrap();
    assert_eq!(enc, encode_decode_xor(&dec, key).unwrap());
}
