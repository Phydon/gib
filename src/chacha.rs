use std::{
    error::Error,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305,
};

pub fn encode_chacha(
    key: &Vec<u8>,
    plaintext: &String,
) -> Result<(Vec<u8>, Vec<u8>), chacha20poly1305::Error> {
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 192-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes().as_ref())?;

    Ok((nonce.as_slice().into(), ciphertext))
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
