//! Definitions for PSSH data in the Widevine DRM system.
//
//
// Widevine PSSH data and licence messages use a protobuf encoding, which we decode using the Prost
// crate.

use std::fmt;
use prost::Message;
use crate::ToBytes;

// This file is generated by Prost in our build script
include!(concat!(env!("OUT_DIR"), "/widevine.rs"));

// include!("widevine-generated.rs");

impl ToBytes for WidevinePsshData {
    fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}


impl fmt::Debug for WidevinePsshData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut items = Vec::new();
        if let Some(a) = &self.algorithm {
            items.push(if *a == 0 { String::from("unencrypted") } else { String::from("Aesctr") });
        }
        if let Some(p) = &self.provider {
            items.push(format!("provider: {p}"));
        }
        if let Some(p) = &self.policy {
            if !p.is_empty() {
                items.push(format!("policy: {p}"));
            }
        }
        if let Some(cpi) = &self.crypto_period_index {
            items.push(format!("crypto_period_index: {cpi}"));
        }
        if let Some(gl) = &self.grouped_license {
            items.push(format!("grouped_licence: {}", hex::encode(gl)));
        }
        // In the 2016 version of the protobuf for WidevinePsshData, the protection_scheme field is
        // specified as a uint32. In 2018 versions there is a ProtectionScheme enum which specifies
        // values for the uint32.
        if let Some(ps) = &self.protection_scheme {
            let scheme = match widevine_pssh_data::ProtectionScheme::try_from(*ps) {
                Ok(s) => String::from(s.as_str_name()),
                Err(_) => format!("unknown ({ps})"),
            };
            items.push(format!("protection_scheme: {scheme}"));
        }
        for kid in &self.key_id {
            items.push(format!("keyid: {}", hex::encode(kid)));
        }
        if let Some(cid) = &self.content_id {
            items.push(format!("content_id: {}", hex::encode(cid)));
        }
        write!(f, "WidevinePsshData<{}>", items.join(", "))
    }
}