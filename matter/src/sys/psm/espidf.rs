
use std::{
    convert::TryInto,
    io::{Read, Write},
    sync::{Arc, Mutex, Once},
};

use esp_idf_svc::nvs::*;
use embedded_svc::storage::{RawStorage, StorageBase};

use crate::error::Error;

pub struct Psm {
    inner: EspNvs<NvsDefault>,
}

static mut G_PSM: Option<Arc<Mutex<Psm>>> = None;
static INIT: Once = Once::new();

impl Psm {
    fn new() -> Result<Self, Error> {
        let partition = EspDefaultNvsPartition::take().unwrap();
        let nvs = EspNvs::new(partition, "matter_psm", true).unwrap();

        Ok(Self {
            inner: nvs
        })
    }

    pub fn get() -> Result<Arc<Mutex<Self>>, Error> {
        unsafe {
            INIT.call_once(|| {
                G_PSM = Some(Arc::new(Mutex::new(Psm::new().unwrap())));
            });
            Ok(G_PSM.as_ref().ok_or(Error::Invalid)?.clone())
        }
    }

    pub fn set_kv_slice(&mut self, key: &str, val: &[u8]) -> Result<(), Error> {
        self.inner.set_raw(key, val).unwrap();
        Ok(())
    }

    pub fn get_kv_slice(&self, key: &str, val: &mut Vec<u8>) -> Result<usize, Error> {
        let result = self.inner.get_raw(key, val).unwrap();
        Ok(result.map(|r| {
            r.len()
        }).unwrap_or_default())
    }

    pub fn set_kv_u64(&mut self, key: &str, val: u64) -> Result<(), Error> {
        self.inner.set_raw(key, &val.to_le_bytes()).unwrap();
        Ok(())
    }

    pub fn get_kv_u64(&self, key: &str, val: &mut u64) -> Result<(), Error> {
        let mut bytes = [0u8; 8];
        let result = self.inner.get_raw(key, &mut bytes).unwrap();
        dbg!(result);
        *val = u64::from_le_bytes(bytes);
        Ok(())
    }

    pub fn rm(&mut self, key: &str) {
        self.inner.remove(key).unwrap();
    }
}
