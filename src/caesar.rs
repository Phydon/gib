use std::io;

// based on https://github.com/TheAlgorithms/Rust
pub fn encode_caesar(byte_content: &Vec<u8>) -> io::Result<Vec<u8>> {
    // TODO let user choose a key between 1 <= key <= 26
    // key = 13 == ROT13 (encrypting and decrypting is its own inverse)
    let key: u8 = 13;
    assert!(key <= 26 && key >= 1);

    let content = String::from_utf8(byte_content.to_owned()).unwrap();
    let encoded: String = content
        .chars()
        .map(|char| {
            if char.is_ascii_alphabetic() {
                let value = if char.is_ascii_lowercase() {
                    b'a'
                } else {
                    b'A'
                };
                (value + (char as u8 + key - value) % 26) as char
            } else {
                char
            }
        })
        .collect();

    Ok(encoded.into_bytes())
}

// based on https://github.com/TheAlgorithms/Rust
pub fn decode_caesar(byte_content: &Vec<u8>) -> io::Result<Vec<u8>> {
    // TODO get key from user
    // key = 13 == ROT13 (encrypting and decrypting is its own inverse)
    let key: u8 = 13;
    assert!(key <= 26 && key >= 1);

    let content = String::from_utf8(byte_content.to_owned()).unwrap();
    let decoded: String = content
        .chars()
        .map(|char| {
            if char.is_ascii_alphabetic() {
                let value = if char.is_ascii_lowercase() {
                    b'a'
                } else {
                    b'A'
                };
                (value + (char as u8 + (26 - key) - value) % 26) as char
            } else {
                char
            }
        })
        .collect();

    Ok(decoded.into_bytes())
}

#[test]
fn encode_caesar_test() {
    assert_eq!(
        encode_caesar(&"This is a test".to_string().into_bytes()).unwrap(),
        "Guvf vf n grfg".as_bytes()
    );
}

#[test]
fn decode_caesar_test() {
    assert_eq!(
        decode_caesar(&"Guvf vf n grfg".to_string().into_bytes()).unwrap(),
        "This is a test".as_bytes()
    );
}

#[test]
fn encode_caesar_special_chars_test() {
    assert_eq!(
        encode_caesar(
            &"Random chars: !\"§$%&/()=?`+#*'-_~@"
                .to_string()
                .into_bytes()
        )
        .unwrap(),
        "Enaqbz punef: !\"§$%&/()=?`+#*'-_~@".as_bytes()
    );
}

#[test]
fn decode_caesar_special_chars_test() {
    assert_eq!(
        decode_caesar(
            &"Enaqbz punef: !\"§$%&/()=?`+#*'-_~@"
                .to_string()
                .into_bytes()
        )
        .unwrap(),
        "Random chars: !\"§$%&/()=?`+#*'-_~@".as_bytes()
    );
}

#[test]
fn encode_caesar_multi_lines_test() {
    assert_eq!(
        encode_caesar(
            &"This is a test.\nWith multiple lines in it.\nYour welcome."
                .to_string()
                .into_bytes()
        )
        .unwrap(),
        "Guvf vf n grfg.\nJvgu zhygvcyr yvarf va vg.\nLbhe jrypbzr.".as_bytes()
    );
}

#[test]
fn decode_caesar_multi_lines_test() {
    assert_eq!(
        decode_caesar(
            &"Guvf zhygv yvar grfgvat,\nvf jbexvat.\nBe vf vg?"
                .to_string()
                .into_bytes()
        )
        .unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}
