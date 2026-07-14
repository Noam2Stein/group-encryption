//! Asymmetric encryption using a randomly generated keypair.
//!
//! This module works with any type that implements [`wincode`] serialization
//! traits, and should work well for large amounts of data.
//!
//! # Security Considerations
//!
//! This module intentionally separates authentication failures
//! ([`DecryptError::IncorrectPrivateKey`]) from structural failures
//! ([`DecryptError::DeserializeFailed`]) to aid local debugging.
//!
//! However, if decryption is performed on a remote server holding the private
//! key, exposing this error distinction over a public API creates a
//! "chosen-ciphertext oracle" vulnerability. An active attacker could exploit
//! this feedback to mathematically reconstruct plaintexts.
//!
//! To mitigate this in server-side environments, the caller must intercept all
//! decryption errors and map them to a single, indistinguishable generic error
//! before returning a response to the client.

use std::{fmt::Debug, marker::PhantomData, mem::MaybeUninit};

use hpke::{Deserializable, Kem, OpModeR, Serializable};
use thiserror::Error;
use wincode::{
    Deserialize, SchemaRead, SchemaWrite, Serialize, config::ConfigCore, deserialize, serialize,
};
use zeroize::Zeroizing;

// Define standard configuration for HPKE
type IdentityDh = hpke::kem::X25519HkdfSha256;
type IdentityHkdf = hpke::kdf::HkdfSha256;
type IdentityAead = hpke::aead::ChaCha20Poly1305;

#[derive(Clone, PartialEq, Eq)]
pub struct PrivKey(<IdentityDh as Kem>::PrivateKey);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubKey(<IdentityDh as Kem>::PublicKey);

#[derive(Clone, SchemaWrite, SchemaRead)]
pub struct Encrypted<T> {
    encapsulated_key: EncappedKey,
    ciphertext: Box<[u8]>,
    _marker: PhantomData<T>,
}

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("failed to serialize:\n{0}")]
    SerializeFailed(#[from] wincode::WriteError),
    #[error("encryption algorithm failed:\n{0}")]
    EncryptionAlgorithmFailed(hpke::HpkeError),
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("incorrect private key")]
    IncorrectPrivateKey,
    #[error("failed to deserialize:\n{0}")]
    DeserializeFailed(wincode::ReadError),
}

pub trait EncryptExt: Sized {
    fn encrypt(&self, key: &PubKey) -> Result<Encrypted<Self>, EncryptError>;
}

#[derive(Clone)]
struct EncappedKey(<IdentityDh as Kem>::EncappedKey);

impl Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey(...)")
    }
}

// SAFETY: Read the safety notes of `TYPE_META` and `size_of`.
unsafe impl<C> SchemaWrite<C> for PrivKey
where
    C: ConfigCore,
{
    type Src = Self;

    // SAFETY: `write` always writes exactly 32 bytes, `size_of` correctly
    // returns `Ok(32)` and `zero_copy` is false so there are no requirements.
    const TYPE_META: wincode::TypeMeta = wincode::TypeMeta::Static {
        size: 32,
        zero_copy: false,
    };

    fn write(mut writer: impl wincode::io::Writer, src: &Self::Src) -> wincode::WriteResult<()> {
        let bytes = Zeroizing::new(<[u8; 32]>::from(src.0.to_bytes()));
        writer.write(&*bytes)?;
        Ok(())
    }

    // SAFETY: `write` always writes exactly 32 bytes.
    fn size_of(_src: &Self::Src) -> wincode::WriteResult<usize> {
        Ok(32)
    }
}

// SAFETY: Read the safety notes of `TYPE_META` and `read`.
unsafe impl<'de, C> SchemaRead<'de, C> for PrivKey
where
    C: ConfigCore,
{
    type Dst = Self;

    // SAFETY: `read` always reads exactly 32 bytes and `zero_copy` is false so
    // there are no requirements.
    const TYPE_META: wincode::TypeMeta = wincode::TypeMeta::Static {
        size: 32,
        zero_copy: false,
    };

    // SAFETY: This function either returns an error early, or if it gets to the
    // end `dst` is initialized without a chance for more early returns then
    // `Ok` is returned. Its impossible for `Ok` to be returned unless `dst` is
    // initialized.
    fn read(
        mut reader: impl wincode::io::Reader<'de>,
        dst: &mut std::mem::MaybeUninit<Self::Dst>,
    ) -> wincode::ReadResult<()> {
        let bytes = Zeroizing::new(reader.take_array::<32>()?);
        let Ok(inner) = <IdentityDh as Kem>::PrivateKey::from_bytes(&*bytes) else {
            return Err(wincode::ReadError::Custom("invalid private key encoding"));
        };

        *dst = MaybeUninit::new(Self(inner));
        Ok(())
    }
}

// SAFETY: Read the safety notes of `TYPE_META` and `size_of`.
unsafe impl<C> SchemaWrite<C> for PubKey
where
    C: ConfigCore,
{
    type Src = Self;

    // SAFETY: `write` always writes exactly 32 bytes, `size_of` correctly
    // returns `Ok(32)` and `zero_copy` is false so there are no requirements.
    const TYPE_META: wincode::TypeMeta = wincode::TypeMeta::Static {
        size: 32,
        zero_copy: false,
    };

    fn write(mut writer: impl wincode::io::Writer, src: &Self::Src) -> wincode::WriteResult<()> {
        let bytes = <[u8; 32]>::from(src.0.to_bytes());
        writer.write(&bytes)?;
        Ok(())
    }

    // SAFETY: `write` always writes exactly 32 bytes.
    fn size_of(_src: &Self::Src) -> wincode::WriteResult<usize> {
        Ok(32)
    }
}

// SAFETY: Read the safety notes of `TYPE_META` and `read`.
unsafe impl<'de, C> SchemaRead<'de, C> for PubKey
where
    C: ConfigCore,
{
    type Dst = Self;

    // SAFETY: `read` always reads exactly 32 bytes and `zero_copy` is false so
    // there are no requirements.
    const TYPE_META: wincode::TypeMeta = wincode::TypeMeta::Static {
        size: 32,
        zero_copy: false,
    };

    // SAFETY: This function either returns an error early, or if it gets to the
    // end `dst` is initialized without a chance for more early returns then
    // `Ok` is returned. Its impossible for `Ok` to be returned unless `dst` is
    // initialized.
    fn read(
        mut reader: impl wincode::io::Reader<'de>,
        dst: &mut std::mem::MaybeUninit<Self::Dst>,
    ) -> wincode::ReadResult<()> {
        let bytes = reader.take_array::<32>()?;
        let Ok(inner) = <IdentityDh as Kem>::PublicKey::from_bytes(&bytes) else {
            return Err(wincode::ReadError::Custom("invalid public key encoding"));
        };

        *dst = MaybeUninit::new(Self(inner));
        Ok(())
    }
}

impl<T> Debug for Encrypted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Encrypted(...)")
    }
}

impl PrivKey {
    pub fn generate() -> Self {
        Self(IdentityDh::gen_keypair().0)
    }

    pub fn pub_key(&self) -> PubKey {
        PubKey(IdentityDh::sk_to_pk(&self.0))
    }
}

// SAFETY: Read the safety notes of `TYPE_META` and `size_of`.
unsafe impl<C> SchemaWrite<C> for EncappedKey
where
    C: ConfigCore,
{
    type Src = Self;

    // SAFETY: `write` always writes exactly 32 bytes, `size_of` correctly
    // returns `Ok(32)` and `zero_copy` is false so there are no requirements.
    const TYPE_META: wincode::TypeMeta = wincode::TypeMeta::Static {
        size: 32,
        zero_copy: false,
    };

    fn write(mut writer: impl wincode::io::Writer, src: &Self::Src) -> wincode::WriteResult<()> {
        let bytes = <[u8; 32]>::from(src.0.to_bytes());
        writer.write(&bytes)?;
        Ok(())
    }

    // SAFETY: `write` always writes exactly 32 bytes.
    fn size_of(_src: &Self::Src) -> wincode::WriteResult<usize> {
        Ok(32)
    }
}

// SAFETY: Read the safety notes of `TYPE_META` and `read`.
unsafe impl<'de, C> SchemaRead<'de, C> for EncappedKey
where
    C: ConfigCore,
{
    type Dst = Self;

    // SAFETY: `read` always reads exactly 32 bytes and `zero_copy` is false so
    // there are no requirements.
    const TYPE_META: wincode::TypeMeta = wincode::TypeMeta::Static {
        size: 32,
        zero_copy: false,
    };

    // SAFETY: This function either returns an error early, or if it gets to the
    // end `dst` is initialized without a chance for more early returns then
    // `Ok` is returned. Its impossible for `Ok` to be returned unless `dst` is
    // initialized.
    fn read(
        mut reader: impl wincode::io::Reader<'de>,
        dst: &mut std::mem::MaybeUninit<Self::Dst>,
    ) -> wincode::ReadResult<()> {
        let bytes = reader.take_array::<32>()?;
        let Ok(inner) = <IdentityDh as Kem>::EncappedKey::from_bytes(&bytes) else {
            return Err(wincode::ReadError::Custom("invalid encapped key encoding"));
        };

        *dst = MaybeUninit::new(Self(inner));
        Ok(())
    }
}

impl<T> EncryptExt for T
where
    T: Serialize<Src = T>,
{
    fn encrypt(&self, key: &PubKey) -> Result<Encrypted<Self>, EncryptError> {
        let plaintext = Zeroizing::new(serialize(self)?);

        let (encapsulated_key, mut sender_ctx) =
            hpke::setup_sender::<IdentityAead, IdentityHkdf, IdentityDh>(
                &hpke::OpModeS::Base,
                &key.0,
                b"wincode-asymmetric-envelope",
            )
            .map_err(EncryptError::EncryptionAlgorithmFailed)?;

        let ciphertext = sender_ctx
            .seal(&plaintext, b"")
            .map_err(EncryptError::EncryptionAlgorithmFailed)?;

        Ok(Encrypted {
            encapsulated_key: EncappedKey(encapsulated_key),
            ciphertext: ciphertext.into_boxed_slice(),
            _marker: PhantomData,
        })
    }
}

impl<T> Encrypted<T>
where
    for<'a> T: Deserialize<'a, Dst = T>,
{
    pub fn decrypt(&self, key: &PrivKey) -> Result<T, DecryptError> {
        // Set up the decryption receiver using the user's private key and
        // the encapsulated key stored inside the Encrypted struct envelope.
        let mut receiver_ctx = hpke::setup_receiver::<IdentityAead, IdentityHkdf, IdentityDh>(
            &OpModeR::Base,
            &key.0,
            &self.encapsulated_key.0,
            b"wincode-asymmetric-envelope",
        )
        .map_err(|_| DecryptError::IncorrectPrivateKey)?;

        // Decrypt the payload into a secure memory container
        let plaintext = receiver_ctx
            .open(&self.ciphertext, b"")
            .map_err(|_| DecryptError::IncorrectPrivateKey)?;
        let plaintext = Zeroizing::new(plaintext);

        // Silence structural verification oracles by turning parsing errors
        // into indistinguishable authentication failures.
        deserialize(&plaintext).map_err(DecryptError::DeserializeFailed)
    }
}

#[cfg(test)]
mod tests {
    use std::{assert_matches, error::Error};

    use crate::keypair_encryption::{DecryptError, EncryptExt, PrivKey};

    #[test]
    fn test_small_value_encryption() -> Result<(), Box<dyn Error>> {
        let priv_key = PrivKey::generate();
        let pub_key = priv_key.pub_key();
        let value = (5, "text text text".to_string());

        assert_eq!(value.encrypt(&pub_key)?.decrypt(&priv_key)?, value);
        assert_matches!(
            value.encrypt(&pub_key)?.decrypt(&PrivKey::generate()),
            Err(DecryptError::IncorrectPrivateKey)
        );
        assert_matches!(
            value
                .encrypt(&PrivKey::generate().pub_key())?
                .decrypt(&priv_key),
            Err(DecryptError::IncorrectPrivateKey)
        );

        Ok(())
    }

    #[test]
    fn test_large_value_encryption() -> Result<(), Box<dyn Error>> {
        let priv_key = PrivKey::generate();
        let pub_key = priv_key.pub_key();
        let value = (5, (0..1_000_000).map(|x| x as u8).collect::<Vec<u8>>());

        assert_eq!(value.encrypt(&pub_key)?.decrypt(&priv_key)?, value);
        assert_matches!(
            value.encrypt(&pub_key)?.decrypt(&PrivKey::generate()),
            Err(DecryptError::IncorrectPrivateKey)
        );
        assert_matches!(
            value
                .encrypt(&PrivKey::generate().pub_key())?
                .decrypt(&priv_key),
            Err(DecryptError::IncorrectPrivateKey)
        );

        Ok(())
    }
}
