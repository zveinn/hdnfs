use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 1,
        }
    }
}

pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

pub fn random_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    loop {
        fill_random(&mut nonce);
        if nonce != [0u8; 24] {
            return nonce;
        }
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    loop {
        fill_random(&mut out);
        if N < 16 || out.iter().any(|b| *b != 0) {
            return out;
        }
    }
}

pub fn validate_kdf(params: &KdfParams) -> Result<()> {
    if params.parallelism == 0 || params.parallelism > 8 {
        return Err(Error::Corrupt("argon2 parallelism out of range".into()));
    }
    if params.iterations == 0 || params.iterations > 8 {
        return Err(Error::Corrupt("argon2 iterations out of range".into()));
    }
    let min_memory = 8 * params.parallelism;
    if params.memory_kib < min_memory || params.memory_kib > 524_288 {
        return Err(Error::Corrupt("argon2 memory out of range".into()));
    }
    Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|err| Error::Corrupt(format!("argon2 parameters: {err}")))?;
    Ok(())
}

pub fn derive_kek(password: &str, salt: &[u8; 32], kdf: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    validate_kdf(kdf)?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|err| Error::Crypto(format!("argon2 parameters: {err}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|err| Error::Crypto(format!("argon2: {err}")))?;
    Ok(key)
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Crypto("invalid key length".into()))?;
    let nonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("encryption failed".into()))
}

pub fn open(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Crypto("invalid key length".into()))?;
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("authentication failed".into()))
}

pub fn wrap_key(
    parent: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    key: &[u8; 32],
) -> Result<[u8; 48]> {
    let sealed = seal(parent, nonce, aad, key)?;
    if sealed.len() != 48 {
        return Err(Error::Crypto("wrapped key has the wrong length".into()));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&sealed);
    Ok(out)
}

pub fn unwrap_key(
    parent: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    wrapped: &[u8; 48],
) -> Result<Zeroizing<[u8; 32]>> {
    let plain = open(parent, nonce, aad, wrapped)?;
    if plain.len() != 32 {
        return Err(Error::Crypto("unwrapped key has the wrong length".into()));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain);
    Ok(key)
}

pub struct SecretBuf {
    data: Vec<u8>,
}

impl SecretBuf {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl std::ops::Deref for SecretBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_rejects_a_changed_byte() {
        let key = random_bytes::<32>();
        let nonce = random_nonce();
        let aad = b"volume-aad";
        let mut sealed = seal(&key, &nonce, aad, b"hello hdnfs").unwrap();
        let opened = open(&key, &nonce, aad, &sealed).unwrap();
        assert_eq!(opened, b"hello hdnfs");
        sealed[10] ^= 0xff;
        assert!(open(&key, &nonce, aad, &sealed).is_err());
        sealed[10] ^= 0xff;
        assert!(open(&key, &nonce, b"other-aad", &sealed).is_err());
    }

    #[test]
    fn derives_a_stable_key() {
        let kdf = KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        };
        let salt = random_bytes::<32>();
        let a = derive_kek("correct horse battery", &salt, &kdf).unwrap();
        let b = derive_kek("correct horse battery", &salt, &kdf).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        let c = derive_kek("correct horse batterz", &salt, &kdf).unwrap();
        assert_ne!(a.as_slice(), c.as_slice());
    }
}
