use std::io;

use crate::utils::convert_string_to_number;

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
fn encode_xor_test() {
    assert_eq!(
        encode_decode_xor(
            &"This is a test".to_string().into_bytes(),
            "randomkeyfoundinherethatshouldnotbetobigforthisfunction".to_string()
        )
        .unwrap(),
        "~BCY
CY
K
^OY^"
            .as_bytes()
    );
}

#[test]
fn decode_xor_test() {
    assert_eq!(
        encode_decode_xor(
            &"~OY^CDM
K^
C^JY
HOY^"
                .to_string()
                .into_bytes(),
            "randomkey".to_string()
        )
        .unwrap(),
        "Testing at it`s best".as_bytes()
    );
}

#[test]
fn encode_xor_multi_lines_test() {
    assert_eq!(
        encode_decode_xor(
            &"This is a test.\nWith multiple lines in it.\nYour welcome."
                .to_string()
                .into_bytes(),
            "randomkey".to_string()
        )
        .unwrap(),
        "~BCY
CY
K
^OY^ }C^B
G_F^CZFO
FCDOY
CD
C^ sE_X
]OFIEGO"
            .as_bytes()
    );
}

#[test]
fn decode_xor_multi_lines_test() {
    assert_eq!(
        encode_decode_xor(
            &"~BCY
G_F^C
FCDO
^OY^CDM CY
]EXACDM eX
CY
C^"
            .to_string()
            .into_bytes(),
            "randomkey".to_string()
        )
        .unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}
