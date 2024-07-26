//! Definitions for PSSH data in the PlayReady DRM system.

// PlayReady PSSH Data is a PlayReady Header Object, whose format is described at
// https://docs.microsoft.com/en-us/playready/specifications/playready-header-specification
//
// and
//
// https://download.microsoft.com/download/2/3/8/238F67D9-1B8B-48D3-AB83-9C00112268B2/PlayReady%20Header%20Object%202015-08-13-FINAL-CL.PDF


use std::fmt;
use std::io::{Read, Cursor};
use std::fmt::{Error, Write};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, skip_serializing_none};
use serde_with::base64::Base64;
use num_enum::TryFromPrimitive;
use tracing::trace;
use anyhow::{Result, Context, anyhow};
use crate::ToBytes;


struct Utf16Writer(Vec<u16>);

impl Write for Utf16Writer {
    fn write_str(&mut self, s: &str) -> Result<(), Error> {
        self.0.extend(s.encode_utf16());
        Ok(())
    }

    fn write_char(&mut self, c: char) -> Result<(), Error> {
        self.0.extend(c.encode_utf16(&mut [0; 2]).iter());
        Ok(())
    }
}

pub fn to_utf16(xml: &str) -> Vec<u16> {
    let mut writer = Utf16Writer(Vec::new());
    write!(writer, "{xml}")
        .expect("writing XML as UTF-16");
    writer.0
}

fn serialize_xmlns<S>(os: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    if let Some(s) = os {
        serializer.serialize_str(s)
    } else {
        serializer.serialize_str("http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader")
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlayReadyKid {
    #[serde(rename = "@value")]
    pub value: Option<String>,
    #[serde(rename = "@ALGID")]
    pub algid: Option<String>,
    #[serde_as(as = "Option<Base64>")]
    #[serde(rename = "@CHECKSUM")]
    pub checksum: Option<Vec<u8>>,
    #[serde_as(as = "Base64")]
    #[serde(rename = "$text")]
    pub content: Vec<u8>,
}

// Note that some fields overlap with the PlayReadyKid type, depending on whether we have a version
// 4.0.0.0 header or a 4.2.0.0 header.
#[skip_serializing_none]
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtectInfo {
    #[serde(rename = "KEYLEN")]
    pub keylen: Option<u32>,
    #[serde(rename = "ALGID")]
    pub algid: Option<String>,
    #[serde(rename = "KIDS")]
    pub kids: Vec<PlayReadyKid>,
}


#[serde_as]
#[skip_serializing_none]
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "WRMDATA")]
#[serde(default)]
pub struct WRMData {
    #[serde(rename = "KID")]
    pub kids: Vec<PlayReadyKid>,
    #[serde(rename = "PROTECTINFO")]
    pub protect_info: Option<ProtectInfo>,
    #[serde_as(as = "Option<Base64>")]
    #[serde(rename = "CHECKSUM")]
    pub checksum: Option<Vec<u8>>,
    /// URL for license acquisition WS
    #[serde(rename = "LA_URL")]
    pub la_url: Option<String>,
    /// URL for non-silent license acquisition web page
    #[serde(rename = "LUI_URL")]
    pub lui_url: Option<String>,
    /// base64-encoded guid
    #[serde(rename = "DS_ID")]
    pub ds_id: Option<String>,
    // These are not parsed via quick-xml, because they often contain invalid XML.
    #[serde(rename(serialize = "CUSTOMATTRIBUTES"))]
    pub custom_attributes: Option<String>,
    #[serde(rename = "DECRYPTORSETUP")]
    pub decryptor_setup: Option<String>,
}

#[skip_serializing_none]
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "WRMHEADER")]
#[serde(default)]
pub struct WRMHeader {
    #[serde(rename = "@xmlns", serialize_with="serialize_xmlns")]
    pub xmlns: Option<String>,
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "DATA")]
    pub data: WRMData,
}

impl ToBytes for WRMHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let xml = quick_xml::se::to_string(self)
            .expect("parsing WRMHeader XML");
        let mut out = Vec::<u8>::new();
        for u in to_utf16(&xml) {
            let _ = out.write_u16::<LittleEndian>(u);
        }
        out
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TryFromPrimitive)]
#[repr(u16)]
pub enum PlayReadyRecordType {
    #[default]
    RightsManagement = 1,
    Reserved = 2,
    EmbeddedLicenseStore = 3,
}

impl ToBytes for PlayReadyRecordType {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = buf.write_u16::<LittleEndian>(*self as u16);
        buf
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayReadyRecord {
    pub record_type: PlayReadyRecordType,
    pub record_value: WRMHeader,
}

impl PlayReadyRecord {
    pub fn new() -> PlayReadyRecord {
        let xml = "<WRMHEADER><DATA></DATA></WRMHEADER>";
        let mut rv: WRMHeader = quick_xml::de::from_str(xml).unwrap();
        rv.xmlns = Some(String::from("http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader"));
        rv.version = String::from("4.0.0.0");
        PlayReadyRecord {
            record_type: PlayReadyRecordType::RightsManagement,
            record_value: rv,
        }
    }
}

impl ToBytes for PlayReadyRecord {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.append(&mut self.record_type.to_bytes());
        let mut val_bytes = self.record_value.to_bytes();
        let _ = buf.write_u16::<LittleEndian>(val_bytes.len().try_into().unwrap());
        buf.append(&mut val_bytes);
        buf
    }
}

fn parse_playready_record(rdr: &mut Cursor<&[u8]>) -> Result<PlayReadyRecord> {
    let record_type = rdr.read_u16::<LittleEndian>()
        .context("reading record_type field")?;
    if record_type != 1 {
        return Err(anyhow!("can't parse PlayReady record of type {record_type}"));
    }
    let record_length = rdr.read_u16::<LittleEndian>()
        .context("reading record_length field")?;
    let mut wrmh_u8 = Vec::new();
    rdr.take(record_length.into()).read_to_end(&mut wrmh_u8)?;
    let wrmh_u16 = wrmh_u8
        .chunks(2)
        .map(|e| u16::from_le_bytes(e.try_into().unwrap()))
        .collect::<Vec<_>>();
    let mut xml = String::from_utf16(&wrmh_u16)
        .context("decoding UTF-16")?;
    // Extract a possible <CUSTOMATTRIBUTES>...</CUSTOMATTRIBUTES> in the input, because it tends
    // not to contain valid XML (undeclared namespaces, in particular) and makes the XML parsing
    // fail. We insert it as a string in the parsed struct.
    let mut custom_attributes: Option<String> = None;
    if let Some(start) =  xml.find("<CUSTOMATTRIBUTES") {
        if let Some(end) = xml.find("</CUSTOMATTRIBUTES>") {
            if end < start {
                return Err(anyhow!("invalid CUSTOMATTRIBUTES element"));
            }
            if let Some(subseq) = xml.get(start..end) {
                let ca_tag_end = subseq.find('>')
                    .context("finding end of CUSTOMATTRIBUTES element")?;
                let inner_start = ca_tag_end + 1;
                trace!("start = {}, inner_start = {}", start, inner_start);
                if let Some(inner) = subseq.get(inner_start..) {
                    custom_attributes = Some(String::from(inner));
                }
                xml.replace_range(start..end + 19, "");
            }
        }
    }
    let xd = &mut quick_xml::de::Deserializer::from_str(&xml);
    let mut wrm_header: WRMHeader = serde_path_to_error::deserialize(xd)
        .context("parsing PlayReady XML")?;
    wrm_header.data.custom_attributes = custom_attributes;
    Ok(PlayReadyRecord {
        record_type: PlayReadyRecordType::try_from(record_type)?,
        record_value: wrm_header,
    })
}

#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayReadyPsshData {
    pub record: Vec<PlayReadyRecord>,
}

impl PlayReadyPsshData {
    pub fn new() -> PlayReadyPsshData {
        let empty_record = PlayReadyRecord::new();
        let mut empty = PlayReadyPsshData::default();
        empty.record.push(empty_record);
        empty
    }
}

impl fmt::Debug for PlayReadyPsshData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut items = Vec::new();
        for r in &self.record {
            if r.record_type == PlayReadyRecordType::RightsManagement {
                let xml = quick_xml::se::to_string(&r.record_value)
                    .map_err(|_| fmt::Error)?;
                items.push(format!("RightsManagementRecord: {xml}"));
            } else {
                items.push(format!("{r:?}"));
            }
        }
        write!(f, "PlayReadyPsshData<{}>", items.join(", "))
    }
}


impl ToBytes for PlayReadyPsshData {
    #[allow(unused_must_use)]
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::<u8>::new();
        let mut records_buf = Vec::<u8>::new();
        for r in &self.record {
            trace!("Serializing playready, record of length {}", r.to_bytes().len());
            records_buf.append(&mut r.to_bytes());
        }
        let total_length: u32 = 4 + 2 + records_buf.len() as u32;
        buf.write_u32::<LittleEndian>(total_length).unwrap();
        buf.write_u16::<LittleEndian>(self.record.len().try_into().unwrap()).unwrap();
        buf.append(&mut records_buf);
        buf
    }
}

pub fn parse_pssh_data(buf: &[u8]) -> Result<PlayReadyPsshData> {
    let mut rdr = Cursor::new(buf);
    let blen = buf.len() as u32;
    let length = rdr.read_u32::<LittleEndian>()
        .context("reading pssh data length")?;
    if length != blen {
        return Err(anyhow!("header length {length} different from buffer length {blen}"));
    }
    let record_count = rdr.read_u16::<LittleEndian>()
        .context("reading pssh data record count")?;
    let mut records = Vec::new();
    for _ in 1..=record_count {
        records.push(parse_playready_record(&mut rdr)?);
    }
    Ok(PlayReadyPsshData {
        record: records,
    })
}
