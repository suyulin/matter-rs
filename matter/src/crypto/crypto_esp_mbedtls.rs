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

use std::convert::TryInto;

use hmac::Mac;
use log::error;
use esp_idf_sys::{{mbedtls_ecp_keypair}};

use crate::error::Error;

use super::CryptoKeyPair;

#[derive(Clone)]
pub struct Sha256 {}

impl Sha256 {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {})
    }

    pub fn update(&mut self, _data: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    pub fn finish(self, _digest: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }
}

type HmacSha256I = hmac::Hmac<sha2::Sha256>;

pub struct HmacSha256 {
    inner: HmacSha256I,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            inner: HmacSha256I::new_from_slice(key).map_err(|e| {
                error!("Error creating HmacSha256 {:?}", e);
                Error::TLSStack
            })?
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inner.update(data);
        Ok(())
    }

    pub fn finish(self, out: &mut [u8]) -> Result<(), Error> {
        let mut result = &self.inner.finalize().into_bytes()[..];
        assert!(result.len() == out.len(), "Buffers not equal");
        // TODO: efficient way of replacing the slice?
        out.clone_from_slice(result);
        Ok(())
    }
}

pub struct KeyPair {
    // TODO: this feels like an isolated feature such that
    // there might be a small enough crate that can do this.
    // Regardless, I'm still figuring out how to make esp_idf_sys::mbetdls*
    // work
    key: mbedtls_ecp_keypair,
}

impl KeyPair {
    pub fn new() -> Result<Self, Error> {
        unsafe {
            let mut ctx = esp_idf_sys::mbedtls_ctr_drbg_context::default();
            esp_idf_sys::mbedtls_ctr_drbg_init(&mut ctx as *mut _)
        }

        panic!("Incomplete implementation")

        // Ok(Self {})
    }

    pub fn new_from_components(_pub_key: &[u8], priv_key: &[u8]) -> Result<Self, Error> {
        error!("This API new_from_components should never get called");

        panic!()

        // Ok(Self {})
    }

    pub fn new_from_public(pub_key: &[u8]) -> Result<Self, Error> {
        error!("This API new_from_public should never get called");

        panic!()

        // Ok(Self {})
    }
}

impl CryptoKeyPair for KeyPair {
    fn get_private_key(&self, priv_key: &mut [u8]) -> Result<usize, Error> {
        error!("This API get_private_key should never get called");
        Err(Error::Invalid)
    }
    fn get_csr<'a>(&self, _out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        error!("This API get_csr should never get called");
        Err(Error::Invalid)
    }
    fn get_public_key(&self, _pub_key: &mut [u8]) -> Result<usize, Error> {
        error!("This API get_public_key should never get called");
        Err(Error::Invalid)
    }
    fn derive_secret(self, _peer_pub_key: &[u8], _secret: &mut [u8]) -> Result<usize, Error> {
        error!("This API derive_secret should never get called");
        Err(Error::Invalid)
    }
    fn sign_msg(&self, _msg: &[u8], _signature: &mut [u8]) -> Result<usize, Error> {
        error!("This API sign_msg should never get called");
        Err(Error::Invalid)
    }
    fn verify_msg(&self, _msg: &[u8], _signature: &[u8]) -> Result<(), Error> {
        error!("This API verify_msg should never get called");
        Err(Error::Invalid)
    }
}

pub fn pbkdf2_hmac(pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) -> Result<(), Error> {
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(pass, salt, iter as u32, key);

    Ok(())
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], key: &mut [u8]) -> Result<(), Error> {
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm).expand(info, key).map_err(|e| {
        error!("Error with hkdf_sha256 {:?}", e);
        Error::TLSStack
    })
}

pub fn encrypt_in_place(
    _key: &[u8],
    _nonce: &[u8],
    _ad: &[u8],
    _data: &mut [u8],
    _data_len: usize,
) -> Result<usize, Error> {
    error!("This API encrypt_in_place should never get called");
    Ok(0)
}

pub fn decrypt_in_place(
    _key: &[u8],
    _nonce: &[u8],
    _ad: &[u8],
    _data: &mut [u8],
) -> Result<usize, Error> {
    error!("This API decrypt_in_place should never get called");
    Ok(0)
}
