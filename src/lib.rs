//! # bincode_aes
//! `bincode_aes` wraps bincode.  It encrypts data as it is encoded, and decrypts the data as it is decoded.
//!
//! ### Using Basic Functions
//!
//! ```rust
//! extern crate bincode_aes;
//! fn main() {
//!     let key = bincode_aes::random_key().unwrap();
//!     let bc = bincode_aes::with_key(key);
//!     let target: Option<String>  = Some("hello world".to_string());
//!
//!     let mut encoded: Vec<u8>    = bc.serialize(&target).unwrap();
//!     let decoded: Option<String> = bc.deserialize(&mut encoded).unwrap();
//!     assert_eq!(target, decoded);
//! }
//! ```

#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate crypto;
extern crate rand;

use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer};
use rand::rngs::OsRng;
use rand::Rng;
use std::error;

/// size of in-mem buffers used for crypto operations
const BUFFER_SIZE: usize = 8192;
/// key length (AES-256-CBC)
const KEY_LEN: usize = 32;
/// initialization vector length (AES-256-CBC)
const IV_LEN: usize = 16;

// distinct/strong types wrapping u8 vectors
#[derive(Serialize, Deserialize)]
pub struct EncryptedData(Vec<u8>);
#[derive(Serialize, Deserialize)]
pub struct IV(Vec<u8>);
pub struct Key(Vec<u8>);

#[derive(Serialize, Deserialize)]
struct SerializedResult {
    iv: IV,
    encrypted_data: EncryptedData,
}

pub struct BincodeCryptor {
    key: Key,
}

pub enum CryptorError {
    InvalidKeySize,
}

/// Returns a keyed BincodeCryptor
pub fn with_key(key: Key) -> BincodeCryptor {
    BincodeCryptor { key }
}

impl BincodeCryptor {
    /// Serializes a serializable object into a `Vec` of bytes
    pub fn serialize<T: ?Sized>(&self, value: &T) -> Result<Vec<u8>, Box<error::Error>>
    where
        T: serde::Serialize,
    {
        let iv = random_iv()?;
        let bincoded_value = bincode::serialize(value)?;
        let encrypted_value = encrypt(bincoded_value.as_slice(), &self.key, &iv)?;
        let encrypted_data = EncryptedData(encrypted_value);

        let serialized_result = SerializedResult { iv, encrypted_data };
        let result = bincode::serialize(&serialized_result)?;

        Ok(result)
    }

    /// Deserializes a slice of bytes into an instance of `T`
    pub fn deserialize<'a, T>(&'a self, bytes: &'a mut Vec<u8>) -> Result<T, Box<error::Error>>
    where
        T: serde::de::Deserialize<'a>,
    {
        let serialized_result: SerializedResult = bincode::deserialize(&bytes[..])?;

        // ideally, we would decrypt in-place
        let decrypted_data = decrypt(
            &serialized_result.encrypted_data.0.as_slice(),
            &self.key,
            &serialized_result.iv,
        )?;
        bytes.clear();
        bytes.extend_from_slice(decrypted_data.as_slice());
        Ok(bincode::deserialize(&bytes[..])?)
    }
}

/// creates a random AES key
pub fn random_key() -> Result<Key, Box<error::Error>> {
    let mut key = vec![0; KEY_LEN];
    let mut rng = OsRng::new()?;
    rng.fill(&mut key[..]);
    Ok(Key(key))
}

/// creates a chosen AES key
pub fn create_key(key_bytes: Vec<u8>) -> Result<Key, CryptorError> {
    if key_bytes.len() != KEY_LEN {
        return Err(CryptorError::InvalidKeySize);
    }
    Ok(Key(key_bytes))
}

fn random_iv() -> Result<IV, Box<error::Error>> {
    let mut iv = vec![0; IV_LEN];
    let mut rng = OsRng::new()?;
    rng.fill(&mut iv[..]);
    Ok(IV(iv))
}

fn encrypt(data: &[u8], key: &Key, iv: &IV) -> Result<Vec<u8>, Box<error::Error>> {
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        &key.0[..],
        &iv.0[..],
        blockmodes::PkcsPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; BUFFER_SIZE];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .cloned(),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

fn decrypt(encrypted_data: &[u8], key: &Key, iv: &IV) -> Result<Vec<u8>, Box<error::Error>> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        &key.0[..],
        &iv.0[..],
        blockmodes::PkcsPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; BUFFER_SIZE];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .cloned(),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}
