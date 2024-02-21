//! Definitions for PSSH data in the Nagra DRM system.

use std::fmt;
use serde::{Serialize, Deserialize};
use base64::{engine, Engine};
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use tracing::warn;
use crate::ToBytes;

// "Normal" base64 is not suitable for Nagra.
const BASE64_URL_SAFE_FORGIVING:
  engine::general_purpose::GeneralPurpose =
  engine::general_purpose::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    engine::general_purpose::GeneralPurposeConfig::new()
      .with_decode_allow_trailing_bits(true)
      .with_decode_padding_mode(engine::DecodePaddingMode::Indifferent),
  );


#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NagraPsshData {
    pub content_id: String,
    pub key_id: String,
}

impl fmt::Debug for NagraPsshData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NagraPsshData<content_id: {}, key_id: {}>", self.content_id, self.key_id)
    }
}

impl ToBytes for NagraPsshData {
    fn to_bytes(&self) -> Vec<u8> {
        // make sure we serialize without any spaces
        let json = format!("{{\"contentId\":\"{}\",\"keyId\":\"{}\"}}",
                           self.content_id, self.key_id);
        BASE64_URL_SAFE_FORGIVING.encode(json).into_bytes()
    }
}

// The structure is similar to a JWT
pub fn parse_pssh_data(buf: &[u8]) -> Result<NagraPsshData> {
    let b64 = String::from_utf8(buf.to_vec())
        .context("decoding UTF-8")?;
    let json = BASE64_URL_SAFE_FORGIVING.decode(b64)
        .context("decoding base64")?;
    let parsed: Value = serde_json::from_slice(&json)
        .context("parsing as JSON")?;
    match parsed.as_object() {
        Some(map) => {
            if map.len() > 2 {
                let keys: Vec<_> = map.keys().collect();
                warn!("unknown key in Nagra PSSH data, {keys:?}");
            }
            let cid = map["contentId"].as_str()
                .context("extracting contentId")?;
            let kid = map["keyId"].as_str()
                .context("extracting keyId")?;
            Ok(NagraPsshData {
                content_id: String::from(cid),
                key_id: String::from(kid),
            })
        },
        None => Err(anyhow!("parsing as JSON")),
    }
}
