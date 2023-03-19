/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use std::convert::TryFrom;

use aes::{Aes128, Aes256};
use ccm::{
    aead::generic_array::GenericArray,
    consts::{U10, U13, U16},
    Ccm,
};
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use hmac::Mac;
use log::error;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::Rng;
use sha2::Digest;

use crate::error::Error;

use super::CryptoKeyPair;

type HmacSha256I = hmac::Hmac<sha2::Sha256>;
type AesCcm = Ccm<Aes128, U16, U13>;
type Aes256Ccm = Ccm<Aes256, U10, U13>;

#[derive(Clone)]
pub struct Sha256 {
    hasher: sha2::Sha256,
}

impl Sha256 {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            hasher: sha2::Sha256::new(),
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.hasher.update(data);
        Ok(())
    }

    pub fn finish(self, digest: &mut [u8]) -> Result<(), Error> {
        let output = self.hasher.finalize();
        digest.copy_from_slice(output.as_slice());
        Ok(())
    }
}

pub struct HmacSha256 {
    inner: HmacSha256I,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            inner: HmacSha256I::new_from_slice(key).map_err(|e| {
                error!("Error creating HmacSha256 {:?}", e);
                Error::TLSStack
            })?,
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner.update(data);
        Ok(())
    }

    pub fn finish(self, out: &mut [u8]) -> Result<(), Error> {
        let result = &self.inner.finalize().into_bytes()[..];
        assert!(result.len() == out.len(), "Buffers not equal");
        // TODO: efficient way of replacing the slice?
        out.clone_from_slice(result);
        Ok(())
    }
}

// Why do we need to store pub and secret? Shouldn't we store both together?
pub enum KeyType {
    Private(p256::SecretKey),
    Public(p256::PublicKey),
}

pub struct KeyPair {
    key: KeyType,
}

impl KeyPair {
    pub fn new() -> Result<Self, Error> {
        let mut rng = rand::thread_rng();
        let secret_key = p256::SecretKey::random(&mut rng);

        Ok(Self {
            key: KeyType::Private(secret_key),
        })
    }

    pub fn new_from_components(_pub_key: &[u8], priv_key: &[u8]) -> Result<Self, Error> {
        error!("This API new_from_components should never get called");
        panic!()

        // Ok(Self {})
    }

    pub fn new_from_public(pub_key: &[u8]) -> Result<Self, Error> {
        let encoded_point = p256::EncodedPoint::from_bytes(pub_key).unwrap();
        Ok(Self {
            key: KeyType::Public(p256::PublicKey::from_encoded_point(&encoded_point).unwrap()),
        })
    }

    fn public_key_point(&self) -> p256::AffinePoint {
        match &self.key {
            KeyType::Private(k) => *(k.public_key().as_affine()),
            KeyType::Public(k) => *(k.as_affine()),
        }
    }
}

impl CryptoKeyPair for KeyPair {
    fn get_private_key(&self, _priv_key: &mut [u8]) -> Result<usize, Error> {
        panic!("This API get_private_key should never get called");

        // I'm unsure of what format the bytes should be.
        Err(Error::Invalid)
    }
    fn get_csr<'a>(&self, _out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        panic!("This API get_csr should never get called");
        Err(Error::Invalid)
    }
    fn get_public_key(&self, pub_key: &mut [u8]) -> Result<usize, Error> {
        let point = self.public_key_point().to_encoded_point(false);
        let bytes = point.as_bytes();
        let len = bytes.len();
        pub_key[..len].copy_from_slice(bytes);
        Ok(len)
    }
    fn derive_secret(self, _peer_pub_key: &[u8], _secret: &mut [u8]) -> Result<usize, Error> {
        panic!("This API derive_secret should never get called");
        Err(Error::Invalid)
    }
    fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        use p256::ecdsa::signature::Signer;

        match &self.key {
            KeyType::Private(k) => {
                let signing_key = SigningKey::from(k);
                let sig: p256::ecdsa::Signature = signing_key.sign(msg);
                let bytes = sig.to_bytes().to_vec();
                let len = bytes.len();
                signature[..len].copy_from_slice(&bytes);
                Ok(len)
            }
            KeyType::Public(_) => todo!(),
        }
    }
    fn verify_msg(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        use p256::ecdsa::signature::Verifier;

        let verifying_key = VerifyingKey::from_affine(self.public_key_point()).unwrap();
        let signature = p256::ecdsa::Signature::try_from(signature).unwrap();

        verifying_key
            .verify(&msg, &signature)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(())
    }
}

pub fn pbkdf2_hmac(pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) -> Result<(), Error> {
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(pass, salt, iter as u32, key);

    Ok(())
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<(), Error> {
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
        .expand(info, key)
        .map_err(|e| {
            error!("Error with hkdf_sha256 {:?}", e);
            Error::TLSStack
        })
}

// TODO: add tests and check against mbedtls and openssl
pub fn encrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
    data_len: usize,
) -> Result<usize, Error> {
    use ccm::aead::Aead;
    use ccm::{AeadInPlace, KeyInit};

    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = AesCcm::new(&key);
    // This is probably incorrect
    let mut buffer = data[0..data_len].to_vec();
    cipher.encrypt_in_place(&nonce, ad, &mut buffer)?;
    let len = buffer.len();
    data.clone_from_slice(&buffer[..]);

    Ok(len)
}

pub fn decrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
) -> Result<usize, Error> {
    use ccm::aead::Aead;
    use ccm::{AeadInPlace, KeyInit};

    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = AesCcm::new(&key);
    // This is probably incorrect
    let mut buffer = data.to_vec();
    cipher.decrypt_in_place(&nonce, ad, &mut buffer)?;
    let len = buffer.len();
    data[..len].copy_from_slice(&buffer[..]);

    Ok(len)
}
