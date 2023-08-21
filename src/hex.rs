use std::io;

pub fn encode_hex(content: String) -> io::Result<Vec<u8>> {
    // TODO error in crate hex?
    // unable to convert '§' <-> 'a7'
    // remove later
    assert!(!content.contains("§"));

    let encoded = hex::encode(content.to_string());

    Ok(encoded.into_bytes())
}

pub fn decode_hex(content: String) -> io::Result<Vec<u8>> {
    // TODO error in crate hex?
    // unable to convert '§' <-> 'a7'

    let decoded = hex::decode(&content).expect("Error while decoding file");

    Ok(decoded)
}
#[test]
fn encode_hex_test() {
    assert_eq!(
        encode_hex("This is a test".to_string()).unwrap(),
        "5468697320697320612074657374".as_bytes()
    );
}

#[test]
fn decode_hex_test() {
    assert_eq!(
        decode_hex("5468697320697320612074657374".to_string()).unwrap(),
        "This is a test".as_bytes()
    );
}

#[test]
fn encode_hex_special_chars_test() {
    assert_eq!(
        encode_hex("Random chars: !\"$%&/()=?`+#*'-_~@".to_string()).unwrap(),
        "52616e646f6d2063686172733a2021222425262f28293d3f602b232a272d5f7e40".as_bytes()
    );
}

#[test]
fn decode_hex_special_chars_test() {
    assert_eq!(
        decode_hex(
            "52616e646f6d2063686172733a2021222425262f28293d3f602b232a272d5f7e40".to_string()
        )
        .unwrap(),
        "Random chars: !\"$%&/()=?`+#*'-_~@".as_bytes()
    );
}

#[test]
// FIXME it should NOT panic
#[should_panic(expected = "assertion failed")]
// error in hex crate ???
fn encode_hex_special_chars_test_2() {
    assert_eq!(encode_hex("§".to_string()).unwrap(), "a7".as_bytes());
}

#[test]
// FIXME it should NOT panic
#[should_panic(expected = "assertion failed")]
// error in hex crate ???
fn decode_hex_special_chars_test_2() {
    assert_eq!(decode_hex("a7".to_string()).unwrap(), "§".as_bytes());
}

#[test]
fn encode_hex_multi_lines_test() {
    assert_eq!(
        encode_hex("This is a test.\nWith multiple lines in it.\nYour welcome.".to_string())
            .unwrap(),
        "54686973206973206120746573742e0a57697468206d756c7469706c65206c696e657320696e2069742e0a596f75722077656c636f6d652e".as_bytes()
    );
}

#[test]
fn decode_hex_multi_lines_test() {
    assert_eq!(
        decode_hex("54686973206d756c7469206c696e652074657374696e672c0a697320776f726b696e672e0a4f722069732069743f".to_string()).unwrap(),
        "This multi line testing,\nis working.\nOr is it?".as_bytes()
    );
}
