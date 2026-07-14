//! Symmetric encryption using a human password.
//!
//! This module works with any type that implements [`wincode`] serialization
//! traits, and should work well for large amounts of data.
//!
//! # Security Considerations
//!
//! This module intentionally separates authentication failures
//! ([`DecryptError::IncorrectPassword`]) from structural failures
//! ([`DecryptError::DeserializeFailed`]) to aid local debugging.
//!
//! However, if a server decrypts payloads using derived keys held in active
//! session memory, exposing this error distinction to a client with a hijacked
//! session creates a "chosen-ciphertext oracle" vulnerability. An active
//! attacker could exploit this feedback to mathematically reconstruct
//! plaintexts.
//!
//! To mitigate this in server-side environments, the caller must intercept all
//! decryption errors and map them to a single, indistinguishable generic error
//! before returning a response to the client.

use std::marker::PhantomData;

use argon2::{
    Argon2,
    password_hash::{Salt, SaltString, rand_core::OsRng},
};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use thiserror::Error;
use wincode::{Deserialize, SchemaRead, SchemaWrite, Serialize, deserialize, serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Hash, SchemaWrite, SchemaRead)]
pub struct Encrypted<T> {
    salt: [u8; Salt::MAX_LENGTH],
    nonce: [u8; 12],
    ciphertext: Box<[u8]>,
    _marker: PhantomData<T>,
}

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("failed to serialize:\n{0}")]
    SerializeFailed(#[from] wincode::WriteError),
    #[error("failed to generate salt:\n{0}")]
    GenerateSaltFailed(argon2::password_hash::Error),
    #[error("failed to hash password:\n{0}")]
    PasswordHashFailed(argon2::Error),
    #[error("encryption algorithm failed:\n{0}")]
    EncryptionAlgorithmFailed(chacha20poly1305::Error),
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("failed to hash password:\n{0}")]
    PasswordHashFailed(argon2::Error),
    #[error("incorrect password")]
    IncorrectPassword,
    #[error("failed to deserialize:\n{0}")]
    DeserializeFailed(#[from] wincode::ReadError),
}

pub trait EncryptExt: Sized {
    fn encrypt(&self, password: &str) -> Result<Encrypted<Self>, EncryptError>;
}

impl<T> EncryptExt for T
where
    T: Serialize<Src = T>,
{
    fn encrypt(&self, password: &str) -> Result<Encrypted<Self>, EncryptError> {
        let plaintext = Zeroizing::new(serialize(self)?);

        let mut rng = OsRng;

        let mut salt = [0u8; Salt::MAX_LENGTH];
        if let Err(err) = SaltString::generate(&mut rng).decode_b64(&mut salt) {
            return Err(EncryptError::GenerateSaltFailed(err));
        };

        let mut key = Zeroizing::new([0u8; 32]);
        let argon2 = match get_kdf_argon2() {
            Ok(ok) => ok,
            Err(err) => return Err(EncryptError::PasswordHashFailed(err)),
        };
        if let Err(err) = argon2.hash_password_into(password.as_bytes(), &salt, &mut *key) {
            return Err(EncryptError::PasswordHashFailed(err));
        }

        let cipher = ChaCha20Poly1305::new(&(*key).into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);

        let Ok(ciphertext) = cipher.encrypt(&nonce, plaintext.as_slice()) else {
            return Err(EncryptError::EncryptionAlgorithmFailed(
                chacha20poly1305::Error,
            ));
        };

        Ok(Encrypted {
            salt,
            nonce: nonce.into(),
            ciphertext: ciphertext.into_boxed_slice(),
            _marker: PhantomData,
        })
    }
}

impl<T> Encrypted<T>
where
    for<'a> T: Deserialize<'a, Dst = T>,
{
    pub fn decrypt(&self, password: &str) -> Result<T, DecryptError> {
        let mut key = Zeroizing::new([0u8; 32]);
        let argon2 = match get_kdf_argon2() {
            Ok(ok) => ok,
            Err(err) => return Err(DecryptError::PasswordHashFailed(err)),
        };
        if let Err(err) = argon2.hash_password_into(password.as_bytes(), &self.salt, &mut *key) {
            return Err(DecryptError::PasswordHashFailed(err));
        }

        let cipher = ChaCha20Poly1305::new(&(*key).into());
        let nonce = Nonce::from_slice(&self.nonce);

        let Ok(plaintext) = cipher.decrypt(nonce, self.ciphertext.as_ref()) else {
            return Err(DecryptError::IncorrectPassword);
        };
        let plaintext = Zeroizing::new(plaintext);

        Ok(deserialize(&plaintext)?)
    }
}

/// Configures Argon2 optimized specifically for Key Derivation (KDF) rather
/// than highly resource-intensive Password Hashing (PHF).
fn get_kdf_argon2() -> Result<Argon2<'static>, argon2::Error> {
    Ok(Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(16384, 3, 1, Some(32))?,
    ))
}

#[cfg(test)]
mod tests {
    use std::{assert_matches, error::Error};

    use crate::password_encryption::{DecryptError, EncryptExt};

    #[test]
    fn test_small_value_encryption() -> Result<(), Box<dyn Error>> {
        let password = "a good password";
        let value = (5, "text text text".to_string());

        assert_eq!(value.encrypt(password)?.decrypt(password)?, value);
        assert_matches!(
            value.encrypt(password)?.decrypt("wrong password"),
            Err(DecryptError::IncorrectPassword)
        );

        Ok(())
    }

    #[test]
    fn test_large_value_encryption() -> Result<(), Box<dyn Error>> {
        let password = "a good password";
        let value = (5, (0..1_000_000).map(|x| x as u8).collect::<Vec<u8>>());

        assert_eq!(value.encrypt(password)?.decrypt(password)?, value);
        assert_matches!(
            value.encrypt(password)?.decrypt("wrong password"),
            Err(DecryptError::IncorrectPassword)
        );

        Ok(())
    }
}
