use std::io;

pub fn encode_decode_xor(content: &Vec<u8>) -> io::Result<Vec<u8>> {
    let key = 42;
    let encoded: Vec<u8> = content.iter().map(|c| c ^ key).collect();

    Ok(encoded)
}

#[test]
fn encode_xor_easy_test() {
    let content = "This is a test".to_string().into_bytes();
    let enc = encode_decode_xor(&content).unwrap();
    assert_eq!(content, encode_decode_xor(&enc).unwrap());
}

#[test]
fn xor_multi_lines_test() {
    let content = "This is a test.\nWith multiple lines in it.\nYour welcome."
        .to_string()
        .into_bytes();
    let enc = encode_decode_xor(&content).unwrap();
    assert_eq!(content, encode_decode_xor(&enc).unwrap());
}
