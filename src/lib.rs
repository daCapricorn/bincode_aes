#![cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]

extern crate bincode;
extern crate crypto;
extern crate rand;

pub use bincode::{Error, ErrorKind};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer, symmetriccipher};
use rand::rngs::OsRng;
use rand::Rng;

// constant sizes used for crypto operations
const BUFFER_SIZE: usize = 8192;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;

// wrapped types
pub struct Key(Vec<u8>);
pub struct IV(Vec<u8>);

pub struct EncryptedSerializer {
    key: Key,
    iv: IV,
}

pub fn new() -> EncryptedSerializer {
    EncryptedSerializer {
        key: random_key(),
        iv: random_iv(),
    }
}

pub fn with_params(key: Key, iv: IV) -> EncryptedSerializer {
    EncryptedSerializer {
        key,
        iv,
    }
}

impl EncryptedSerializer {
    pub fn serialize<T: ?Sized>(&mut self, value: &T) -> bincode::Result<Vec<u8>>
    where
        T: serde::Serialize,
    {
        let decrypted = bincode::serialize(value)?;
        //todo: replace with to_slice
        let encrypted = encrypt(&decrypted[..], &self.key, &self.iv).unwrap();

        Ok(encrypted.clone())
    }

    pub fn deserialize<'b, T>(&'b mut self, bytes: &'b mut Vec<u8>) -> bincode::Result<T>
    where
        T: serde::de::Deserialize<'b>,
    {
        let decrypted = decrypt(bytes.as_slice(), &self.key, &self.iv).ok().unwrap();
        bytes.clear();
        bytes.extend_from_slice(decrypted.as_slice());
        bincode::deserialize(&bytes[..])
    }

    pub fn update_key(&mut self) {
        self.key = random_key();
    }

    pub fn update_iv(&mut self) {
        self.iv = random_iv();
    }
}

/// Creates a random AES key.
pub fn random_key() -> Key {
    let mut key = vec![0; KEY_LEN];
    let mut rng = OsRng::new().unwrap();
    rng.fill(&mut key[..]);
    Key(key)
}

/// Creates a random AES initialization vector.
pub fn random_iv() -> IV {
    let mut iv = vec![0; IV_LEN];
    let mut rng = OsRng::new().unwrap();
    rng.fill(&mut iv[..]);
    IV(iv)
}

pub fn encrypt(
    data: &[u8],
    key: &Key,
    iv: &IV,
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
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

pub fn decrypt(
    encrypted_data: &[u8],
    key: &Key,
    iv: &IV,
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
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


