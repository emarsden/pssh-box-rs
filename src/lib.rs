//! Parsing and serialization support for pssh boxes, as used in DRM systems.
//!
//! This crate defines Rust data structures allowing you to store, parse and serialize Protection System
//! Specific Header (**PSSH**) boxes, which provide data for the initialization of a Digital Rights
//! Management (DRM) system. PSSH boxes are used:
//!
//! - in an MP4 box of type `pssh` in an MP4 fragment (CMAF/MP4/ISOBMFF containers)
//!
//! - in a `<cenc:pssh>` element in a DASH MPD manifest
//!
//! A PSSH box includes information for a single DRM system. This library supports the PSSH data formats
//! for the following DRM systems:
//!
//! - Widevine, owned by Google, widely used for DASH streaming
//! - PlayReady, owned by Microsoft, widely used for DASH streaming
//! - WisePlay, owned by Huawei
//! - Irdeto
//! - Marlin
//! - Nagra
//! - Common Encryption
//!
//! PSSH boxes contain (depending on the DRM system) information on the key_ID for which to obtain a
//! content key, the encryption scheme used (e.g. cenc, cbc1, cens or cbcs), the URL of the licence
//! server, and checksum data.


pub mod playready;
pub mod widevine;
pub mod irdeto;
pub mod nagra;
pub mod wiseplay;

use std::fmt;
use std::convert::TryFrom;
use std::io::{Cursor, Read, Write};
use hex_literal::hex;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use zerocopy::{FromZeroes, FromBytes};
use serde::{Serialize, Deserialize};
use prost::Message;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use anyhow::{Result, Context, anyhow};
use crate::widevine::WidevinePsshData;
use crate::playready::PlayReadyPsshData;
use crate::irdeto::IrdetoPsshData;
use crate::nagra::NagraPsshData;
use crate::wiseplay::WisePlayPsshData;


/// The version of this crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

/// Data in a PSSH box whose format is dependent on the DRM system used.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PsshData {
    Widevine(WidevinePsshData),
    PlayReady(PlayReadyPsshData),
    Irdeto(IrdetoPsshData),
    WisePlay(WisePlayPsshData),
    Nagra(NagraPsshData),
    Marlin(Vec<u8>),
    CommonEnc(Vec<u8>),
}

impl ToBytes for PsshData {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            PsshData::Widevine(wv) => wv.to_bytes(),
            PsshData::PlayReady(pr) => pr.to_bytes(),
            PsshData::Irdeto(ir) => ir.to_bytes(),
            PsshData::WisePlay(c) => c.to_bytes(),
            PsshData::Nagra(n) => n.to_bytes(),
            PsshData::Marlin(m) => m.to_vec(),
            PsshData::CommonEnc(c) => c.to_vec(),
        }
    }
}

/// The identifier for a DRM system.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, FromZeroes, FromBytes)]
pub struct DRMSystemId {
    id: [u8; 16],
}

impl TryFrom<&[u8]> for DRMSystemId {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(id) = value.try_into() {
            Ok(DRMSystemId { id })
        } else {
            Err(())
        }
    }
}

impl TryFrom<Vec<u8>> for DRMSystemId {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() == 16 {
            DRMSystemId::try_from(&value[0..16])
        } else {
            Err(())
        }
    }
}

impl TryFrom<&str> for DRMSystemId {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == 32 {
            if let Ok(id) = hex::decode(value) {
                return DRMSystemId::try_from(id);
            }
        }
        Err(())
    }
}

impl ToBytes for DRMSystemId {
    fn to_bytes(&self) -> Vec<u8> {
        self.id.into()
    }
}

impl fmt::Display for DRMSystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // See list at https://dashif.org/identifiers/content_protection/
        let family = if self.id == hex!("1077efecc0b24d02ace33c1e52e2fb4b") {
            "Common"
        } else if self.id == hex!("69f908af481646ea910ccd5dcccb0a3a") {
            "CENC"
        } else if self.id == hex!("edef8ba979d64acea3c827dcd51d21ed") {
            "Widevine"
        } else if self.id == hex!("9a04f07998404286ab92e65be0885f95") {
            "PlayReady"
        } else if self.id == hex!("6dd8b3c345f44a68bf3a64168d01a4a6") {
            "ABV"
        } else if self.id == hex!("f239e769efa348509c16a903c6932efb") {
            "Adobe Primetime"
        } else if self.id == hex!("616c7469636173742d50726f74656374") {
            "Alticast"
        } else if self.id == hex!("94ce86fb07ff4f43adb893d2fa968ca2") {
            "Apple FairPlay"
        } else if self.id == hex!("3ea8778f77424bf9b18be834b2acbd47") {
            "ClearKey AES-128"
        } else if self.id == hex!("be58615b19c4468488b3c8c57e99e957") {
            "ClearKey SAMPLE-AES"
        } else if self.id == hex!("e2719d58a985b3c9781ab030af78d30e") {
            "ClearKey DASH-IF"
        } else if self.id == hex!("45d481cb8fe049c0ada9ab2d2455b2f2") {
            "CoreTrust"
        } else if self.id == hex!("80a6be7e14484c379e70d5aebe04c8d2") {
            "Irdeto"
        } else if self.id == hex!("5e629af538da4063897797ffbd9902d4") {
            "Marlin"
        } else if self.id == hex!("adb41c242dbf4a6d958b4457c0d27b95") {
            "Nagra"
        } else if self.id == hex!("1f83e1e86ee94f0dba2f5ec4e3ed1a66") {
            "SecureMedia"
        } else if self.id == hex!("3d5e6d359b9a41e8b843dd3c6e72c42c") {
            // WisePlay (from Huawei) and ChinaDRM are apparently different DRM systems that are
            // identified by the same system id.
            "WisePlay-ChinaDRM"
        } else if self.id == hex!("793b79569f944946a94223e7ef7e44b4") {
            "VisionCrypt"
        } else {
            "Unknown"
        };
        let hex = hex::encode(self.id);
        write!(f, "{}/DRMSystemId<{}-{}-{}-{}>",
               family,
               &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..32])
    }
}

impl fmt::Debug for DRMSystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DRMSystemId<{}>", hex::encode(self.id))
    }
}

pub const COMMON_SYSTEM_ID: DRMSystemId = DRMSystemId { id: hex!("1077efecc0b24d02ace33c1e52e2fb4b") };
pub const CENC_SYSTEM_ID: DRMSystemId = DRMSystemId { id: hex!("69f908af481646ea910ccd5dcccb0a3a") };
pub const WIDEVINE_SYSTEM_ID: DRMSystemId = DRMSystemId { id: hex!("edef8ba979d64acea3c827dcd51d21ed") };
pub const PLAYREADY_SYSTEM_ID: DRMSystemId = DRMSystemId { id: hex!("9a04f07998404286ab92e65be0885f95") };
pub const IRDETO_SYSTEM_ID: DRMSystemId = DRMSystemId { id: hex!("80a6be7e14484c379e70d5aebe04c8d2") };
pub const MARLIN_SYSTEM_ID: DRMSystemId = DRMSystemId { id: hex!("5e629af538da4063897797ffbd9902d4") };
pub const NAGRA_SYSTEM_ID: DRMSystemId = DRMSystemId { id: hex!("adb41c242dbf4a6d958b4457c0d27b95") };
pub const WISEPLAY_SYSTEM_ID: DRMSystemId = DRMSystemId { id: hex!("3d5e6d359b9a41e8b843dd3c6e72c42c") };

/// The Content Key or default_KID.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, FromZeroes, FromBytes)]
pub struct DRMKeyId {
    id: [u8; 16],
}

impl TryFrom<&[u8]> for DRMKeyId {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(id) = value.try_into() {
            Ok(DRMKeyId { id })
        } else {
            Err(())
        }
    }
}

impl TryFrom<Vec<u8>> for DRMKeyId {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() == 16 {
            DRMKeyId::try_from(&value[0..16])
        } else {
            Err(())
        }
    }
}

impl TryFrom<&str> for DRMKeyId {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == 32 {
            if let Ok(id) = hex::decode(value) {
                return DRMKeyId::try_from(id);
            }
        }
        Err(())
    }
}

impl ToBytes for DRMKeyId {
    fn to_bytes(&self) -> Vec<u8> {
        self.id.into()
    }
}

impl fmt::Display for DRMKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // example: 72c3ed2c-7a5f-4aad-902f-cbef1efe89a9
        let hex = hex::encode(self.id);
        write!(f, "DRMKeyId<{}-{}-{}-{}>",
               &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..32])
    }
}

impl fmt::Debug for DRMKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DRMKeyId<{}>", hex::encode(self.id))
    }
}


/// A PSSH box, also called a ProtectionSystemSpecificHeaderBox in ISO 23001-7:2012.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PsshBox {
    pub version: u8,
    pub flags: u32,
    pub system_id: DRMSystemId,
    pub key_ids: Vec<DRMKeyId>,
    pub pssh_data: PsshData,
}

impl PsshBox {
    pub fn new_widevine() -> PsshBox {
        let empty = WidevinePsshData {
            provider: None,
            policy: Some(String::from("")),
            ..Default::default()
        };
        PsshBox {
            version: 1,
            flags: 0,
            system_id: WIDEVINE_SYSTEM_ID,
            key_ids: vec![],
            pssh_data: PsshData::Widevine(empty),
        }
    }

    pub fn new_playready() -> PsshBox {
        let empty = PlayReadyPsshData::new();
        PsshBox {
            version: 1,
            flags: 0,
            system_id: PLAYREADY_SYSTEM_ID,
            key_ids: vec![],
            pssh_data: PsshData::PlayReady(empty),
        }
    }

    pub fn add_key_id(&mut self, kid: DRMKeyId) {
        self.key_ids.push(kid);
    }

    pub fn to_base64(self) -> String {
        BASE64_STANDARD.encode(self.to_bytes())
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// This to_string() method provides the most compact representation possible on a single line; see
/// the pprint() function for a more verbose layout.
impl fmt::Display for PsshBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys = Vec::new();
        if self.version == 1 {
            for key in &self.key_ids {
                keys.push(hex::encode(key.id));
            }
        }
        let key_str = match keys.len() {
            0 => String::from(""),
            1 => format!("key_id: {}, ", keys[0]),
            _ => format!("key_ids: {}, ", keys.join(", ")),
        };
        match &self.pssh_data {
            PsshData::Widevine(wv) => {
                let mut items = Vec::new();
                let json = wv.to_json();
                if let Some(alg) = json.get("algorithm") {
                    if let Some(a) = alg.as_str() {
                        items.push(String::from(a));
                    }
                }
                // We are merging keys potentially present in the v1 PSSH box data with those
                // present in the Widevine PSSH data.
                if let Some(kav) = json.get("key_id") {
                    if let Some(ka) = kav.as_array() {
                        for kv in ka {
                            if let Some(k) = kv.as_str() {
                                keys.push(String::from(k));
                            }
                        }
                    }
                }
                if keys.len() == 1 {
                    items.push(format!("key_id: {}", keys[0]));
                }
                if keys.len() > 1 {
                    items.push(format!("key_ids: {}", keys.join(", ")));
                }
                for (k, v) in json.as_object().unwrap().iter() {
                    if k.ne("algorithm") && k.ne("key_id") {
                        items.push(format!("{k}: {v}"));
                    }
                }
                write!(f, "WidevinePSSH<{}>", items.join(", "))
            },
            PsshData::PlayReady(pr) => write!(f, "PlayReadyPSSH<{key_str}{pr:?}>"),
            PsshData::Irdeto(pd) => write!(f, "IrdetoPSSH<{key_str}{}>", pd.xml),
            PsshData::Marlin(pd) => write!(f, "  MarlinPSSH<{key_str}pssh data len {} octets>", pd.len()),
            PsshData::Nagra(pd) => write!(f, "NagraPSSH<{key_str}{pd:?}>"),
            PsshData::WisePlay(pd) => write!(f, "WisePlayPSSH<{key_str}{}>", pd.json),
            PsshData::CommonEnc(pd) => write!(f, "CommonPSSH<{key_str}pssh data len {} octets>", pd.len()),
        }
    }
}


impl ToBytes for PsshBox {
    #[allow(unused_must_use)]
    fn to_bytes(self: &PsshBox) -> Vec<u8> {
        let mut out = Vec::new();
        let pssh_data_bytes = self.pssh_data.to_bytes();
        let mut total_length: u32 = 4 // box size
            + 4     // BMFF box header 'pssh'
            + 4     // version+flags
            + 16    // system_id
            + 4     // pssh_data length
            + pssh_data_bytes.len() as u32;
        if self.version == 1 {
            total_length += 4 // key_id count
                + self.key_ids.len() as u32 * 16;
        }
        out.write_u32::<BigEndian>(total_length);
        out.write(b"pssh");
        let version_and_flags: u32 = self.flags ^ ((self.version as u32) << 24);
        out.write_u32::<BigEndian>(version_and_flags);
        out.write(&self.system_id.id);
        if self.version == 1 {
            out.write_u32::<BigEndian>(self.key_ids.len() as u32);
            for k in &self.key_ids {
                out.write(&k.id);
            }
        }
        out.write_u32::<BigEndian>(pssh_data_bytes.len() as u32);
        out.write(&pssh_data_bytes);
        out
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PsshBoxVec(Vec<PsshBox>);

impl PsshBoxVec {
    pub fn new() -> PsshBoxVec {
        PsshBoxVec(Vec::new())
    }

    pub fn add(&mut self, bx: PsshBox) {
        self.0.push(bx);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item=&PsshBox>{
        self.0.iter()
    }

    pub fn to_base64(self) -> String {
        let mut buf = Vec::new();
        for bx in self.0 {
            buf.append(&mut bx.to_bytes());
        }
        BASE64_STANDARD.encode(buf)
    }

    pub fn to_hex(self) -> String {
        let mut buf = Vec::new();
        for bx in self.0 {
            buf.append(&mut bx.to_bytes());
        }
        hex::encode(buf)
    }
}

impl Default for PsshBoxVec {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for PsshBoxVec {
    type Item = PsshBox;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl std::ops::Index<usize> for PsshBoxVec {
    type Output = PsshBox;

    fn index(&self, index: usize) -> &PsshBox {
        &self.0[index]
    }
}

impl fmt::Display for PsshBoxVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut items = Vec::new();
        for pssh in self.iter() {
            items.push(pssh.to_string());
        }
        // Print one PsshBox per line, without a trailing newline.
        write!(f, "{}", items.join("\n"))
    }
}

// Initialization Data is always one or more concatenated 'pssh' boxes. The CDM must be able to
// examine multiple 'pssh' boxes in the Initialization Data to find a 'pssh' box that it supports.

/// Parse one or more PSSH boxes from some initialization data encoded in base64 format.
pub fn from_base64(init_data: &str) -> Result<PsshBoxVec> {
    let buf = BASE64_STANDARD.decode(init_data)
        .context("decoding base64")?;
    from_bytes(&buf)
        .context("parsing the PSSH initialization data")
}

/// Parse one or more PSSH boxes from some initialization data encoded in hex format.
pub fn from_hex(init_data: &str) -> Result<PsshBoxVec> {
    let buf = hex::decode(init_data)
        .context("decoding hex")?;
    from_bytes(&buf)
        .context("parsing the PSSH initialization_data")
}

/// Parse a single PSSH box.
fn read_pssh_box(rdr: &mut Cursor<&[u8]>) -> Result<PsshBox> {
    let _size: u32 = rdr.read_u32::<BigEndian>()
        .context("reading pssh box size")?;
    let mut box_header = [0u8; 4];
    rdr.read_exact(&mut box_header)
        .context("reading box header")?;
    // the ISO BMFF box header
    if !box_header.eq(b"pssh") {
        return Err(anyhow!("expecting BMFF header"));
    }
    let version_and_flags: u32 = rdr.read_u32::<BigEndian>()
        .context("reading pssh version/flags")?;
    let version: u8 = (version_and_flags >> 24).try_into().unwrap();
    if version > 1 {
        return Err(anyhow!("unknown PSSH version {version}"));
    }
    let mut system_id_buf = [0u8; 16];
    rdr.read_exact(&mut system_id_buf)
        .context("reading system_id")?;
    let system_id = DRMSystemId { id: system_id_buf };
    let mut key_ids = Vec::new();
    if version == 1 {
        let mut kid_count = rdr.read_u32::<BigEndian>()
            .context("reading KID count")?;
        while kid_count > 0 {
            let mut key = [0u8; 16];
            rdr.read_exact(&mut key)
                .context("reading key_id")?;
            key_ids.push(DRMKeyId { id: key });
            kid_count -= 1;
        }
    }
    let pssh_data_len = rdr.read_u32::<BigEndian>()
        .context("reading pssh data length")?;
    let mut pssh_data = Vec::new();
    rdr.take(pssh_data_len.into()).read_to_end(&mut pssh_data)
        .context("extracting PSSH data")?;
    match system_id {
        WIDEVINE_SYSTEM_ID => {
            let wv_pssh_data = WidevinePsshData::decode(Cursor::new(pssh_data))
                .context("parsing Widevine PSSH data")?;
            Ok(PsshBox {
                version,
                flags: version_and_flags & 0xF,
                system_id,
                key_ids,
                pssh_data: PsshData::Widevine(wv_pssh_data),
            })
        },
        PLAYREADY_SYSTEM_ID => {
            let pr_pssh_data = playready::parse_pssh_data(&pssh_data)
                .context("parsing PlayReady PSSH data")?;
            Ok(PsshBox {
                version,
                flags: version_and_flags & 0xF,
                system_id,
                key_ids,
                pssh_data: PsshData::PlayReady(pr_pssh_data),
            })
        },
        IRDETO_SYSTEM_ID => {
            let ir_pssh_data = irdeto::parse_pssh_data(&pssh_data)
                .context("parsing Irdeto PSSH data")?;
            Ok(PsshBox {
                version,
                flags: version_and_flags & 0xF,
                system_id,
                key_ids,
                pssh_data: PsshData::Irdeto(ir_pssh_data),
            })
        },
        MARLIN_SYSTEM_ID => {
            Ok(PsshBox {
                version,
                flags: version_and_flags & 0xF,
                system_id,
                key_ids,
                pssh_data: PsshData::Marlin(pssh_data),
            })
        },
        NAGRA_SYSTEM_ID => {
            let pd = nagra::parse_pssh_data(&pssh_data)
                .context("parsing Nagra PSSH data")?;
            Ok(PsshBox {
                version,
                flags: version_and_flags & 0xF,
                system_id,
                key_ids,
                pssh_data: PsshData::Nagra(pd),
            })
        },
        WISEPLAY_SYSTEM_ID => {
            let cdrm_pssh_data = wiseplay::parse_pssh_data(&pssh_data)
                .context("parsing WisePlay PSSH data")?;
            Ok(PsshBox {
                version,
                flags: version_and_flags & 0xF,
                system_id,
                key_ids,
                pssh_data: PsshData::WisePlay(cdrm_pssh_data),
            })
        },
        COMMON_SYSTEM_ID => {
            Ok(PsshBox {
                version,
                flags: version_and_flags & 0xF,
                system_id,
                key_ids,
                pssh_data: PsshData::CommonEnc(pssh_data),
            })
        },
        _ => Err(anyhow!("can't parse this system_id type: {:?}", system_id)),
    }
}

/// Read one or more PSSH boxes from some initialization data provided as a slice of octets,
/// returning an error if any non-PSSH data is found in the slice or if the parsing fails.
pub fn from_bytes(init_data: &[u8]) -> Result<PsshBoxVec> {
    let total_len = init_data.len();
    let mut rdr = Cursor::new(init_data);
    let mut boxes = PsshBoxVec::new();
    while (rdr.position() as usize) < total_len - 1  {
        let bx = read_pssh_box(&mut rdr)?;
        boxes.add(bx);
    }
    Ok(boxes)
}

/// Read one or more PSSH boxes from a slice of octets, stopping (but not returning an error) when
/// non-PSSH data is found in the slice. An error is returned if the parsing fails.
pub fn from_buffer(init_data: &[u8]) -> Result<PsshBoxVec> {
    let total_len = init_data.len();
    let mut rdr = Cursor::new(init_data);
    let mut boxes = PsshBoxVec::new();
    while (rdr.position() as usize) < total_len - 1  {
        if let Ok(bx) = read_pssh_box(&mut rdr) {
            boxes.add(bx);
        } else {
            break;
        }
    }
    Ok(boxes)
}

/// Locate the positions of a PsshBox in a buffer, if present. Returns an iterator over start
/// positions for PSSH boxes in the buffer.
pub fn find_iter(buffer: &[u8]) -> impl Iterator<Item = usize> + '_ {
    use bstr::ByteSlice;

    buffer.find_iter(b"pssh")
        .filter(|offset| {
            if offset+24 > buffer.len() {
                return false;
            }
            let start = offset - 4;
            let mut rdr = Cursor::new(&buffer[start..]);
            let size: u32 = rdr.read_u32::<BigEndian>().unwrap();
            let end = start + size as usize;
            from_bytes(&buffer[start..end]).is_ok()
        })
        .map(|offset| offset - 4)
}

/// Multiline pretty printing of a PsshBox (verbose alternative to `to_string()` method).
pub fn pprint(pssh: &PsshBox) {
    println!("PSSH Box v{}", pssh.version);
    println!("  SystemID: {:?}", pssh.system_id);
    if pssh.version == 1 {
        for key in &pssh.key_ids {
            println!("  Key ID: {:?}", key);
        }
    }
    match &pssh.pssh_data {
        PsshData::Widevine(wv) => println!("  {wv:?}"),
        PsshData::PlayReady(pr) => println!("  {pr:?}"),
        PsshData::Irdeto(pd) => {
            println!("Irdeto XML: {}", pd.xml);
        },
        PsshData::Marlin(pd) => {
            println!("  Marlin PSSH data ({} octets)", pd.len());
            if !pd.is_empty() {
                println!("== Hexdump of pssh data ==");
                let mut hxbuf = Vec::new();
                hxdmp::hexdump(pd, &mut hxbuf).unwrap();
                println!("{}", String::from_utf8_lossy(&hxbuf));
            }
        },
        PsshData::Nagra(pd) => println!("  {pd:?}"),
        PsshData::WisePlay(pd) => {
            println!("  WisePlay JSON: {}", pd.json);
        },
        PsshData::CommonEnc(pd) => {
            println!("  Common PSSH data ({} octets)", pd.len());
            if !pd.is_empty() {
                println!("== Hexdump of pssh data ==");
                let mut hxbuf = Vec::new();
                hxdmp::hexdump(pd, &mut hxbuf).unwrap();
                println!("{}", String::from_utf8_lossy(&hxbuf));
            }
        },
    }
}
