use base64ct::{Base64, Encoding};

use std::io;

pub fn encode_base64ct(content: String) -> io::Result<Vec<u8>> {
    let encoded = Base64::encode_string(content.as_bytes());
    Ok(encoded.into_bytes())
}

pub fn decode_base64ct(content: String) -> io::Result<Vec<u8>> {
    let decoded = Base64::decode_vec(&content).expect("Error while decoding file");
    Ok(decoded)
}

#[test]
fn encode_base64ct_test() {
    assert_eq!(
        encode_base64ct("This is a test".to_string()).unwrap(),
        "VGhpcyBpcyBhIHRlc3Q=".as_bytes()
    );
}

#[test]
fn decode_base64ct_test() {
    assert_eq!(
        decode_base64ct("VGhpcyBpcyBhIHRlc3Q=".to_string()).unwrap(),
        "This is a test".as_bytes()
    );
}

#[test]
fn encode_base64ct_special_chars_test() {
    assert_eq!(
        encode_base64ct("Random chars: !\"§$%&/()=?`+#*'-_~@".to_string()).unwrap(),
        "UmFuZG9tIGNoYXJzOiAhIsKnJCUmLygpPT9gKyMqJy1ffkA=".as_bytes()
    );
}

#[test]
fn decode_base64ct_special_chars_test() {
    assert_eq!(
        decode_base64ct("UmFuZG9tIGNoYXJzOiAhIsKnJCUmLygpPT9gKyMqJy1ffkA=".to_string()).unwrap(),
        "Random chars: !\"§$%&/()=?`+#*'-_~@".as_bytes()
    );
}

#[test]
fn encode_base64ct_multi_lines_test() {
    assert_eq!(
        encode_base64ct("This is a test.\nWith multiple lines in it.\nYour welcome.".to_string())
            .unwrap(),
        "VGhpcyBpcyBhIHRlc3QuCldpdGggbXVsdGlwbGUgbGluZXMgaW4gaXQuCllvdXIgd2VsY29tZS4=".as_bytes()
    );
}

#[test]
fn decode_base64ct_multi_lines_test() {
    assert_eq!(
        decode_base64ct(
            "VGhpcyBtdWx0aSBsaW5lIHRlc3RpbmcsCmlzIHdvcmtpbmcuCk9yIGlzIGl0Pw==".to_string()
        )
        .unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}
