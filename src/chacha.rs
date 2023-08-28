use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305,
};

pub fn encode_chacha(
    key: &Vec<u8>,
    plaintext: &Vec<u8>,
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 192-bits; unique per message
    let mut ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;

    let mut concated_vec: Vec<u8> = nonce.as_slice().into();
    concated_vec.append(&mut ciphertext);

    Ok(concated_vec)
}

pub fn decode_chacha(
    key: &Vec<u8>,
    nonce: &Vec<u8>,
    content: &Vec<u8>,
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let plaintext = cipher.decrypt(nonce.as_slice().into(), content.as_ref())?;

    Ok(plaintext)
}

pub fn extract_nonce(filecontent: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    // TODO better way than cloning?
    let mut nonce = filecontent.clone();
    let rest: Vec<u8> = nonce.drain(24..).collect();

    (nonce.to_owned(), rest)
}

#[test]
fn encode_decode_chacha_test() {
    let key = "passwordpasswordpasswordpassword".to_string().into_bytes();
    let plaintext = "This is a test".to_string().into_bytes();
    let ciphertext = encode_chacha(&key, &plaintext).unwrap();

    let (nonce, rest) = extract_nonce(&ciphertext);

    assert_eq!(decode_chacha(&key, &nonce, &rest).unwrap(), plaintext);
}

#[test]
fn encode_decode_chacha_special_chars_test() {
    let key = "passwordpasswordpasswordpassword".to_string().into_bytes();
    let plaintext = "RandomChars: !\"§$%&/()=?`*'_:;-.,#+~@µ|<>\\}][{}]`"
        .to_string()
        .into_bytes();
    let ciphertext = encode_chacha(&key, &plaintext).unwrap();

    let (nonce, rest) = extract_nonce(&ciphertext);

    assert_eq!(decode_chacha(&key, &nonce, &rest).unwrap(), plaintext);
}
