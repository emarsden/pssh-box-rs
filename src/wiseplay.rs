//! Definitions for PSSH data in the WisePlay DRM system.
//
// WisePlay is a DRM system bu Huawei, supported by some of their devices (televisions,
// smartphones). It has the same system_id as "ChinaDRM". We only have WisePlay PSSH examples to
// test with.

use std::fmt;
use serde_json::Value;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use crate::ToBytes;


#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WisePlayPsshData {
    pub json: Value,
}

impl fmt::Debug for WisePlayPsshData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WisePlayPsshData<{}>", self.json)
    }
}

impl ToBytes for WisePlayPsshData {
    fn to_bytes(&self) -> Vec<u8> {
        self.json.to_string().into_bytes()
    }
}

pub fn parse_pssh_data(buf: &[u8]) -> Result<WisePlayPsshData> {
    let json = serde_json::from_slice(buf)?;
    Ok(WisePlayPsshData { json })
}
