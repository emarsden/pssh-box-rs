//! Definitions for PSSH data in the Irdeto DRM system.


use std::fmt;
use std::io::{Read, Cursor};
use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use crate::ToBytes;


#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrdetoPsshData {
    pub xml: String,
}

impl fmt::Debug for IrdetoPsshData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IrdetoPsshData<{}>", self.xml)
    }
}

impl ToBytes for IrdetoPsshData {
    fn to_bytes(&self) -> Vec<u8> {
        self.xml.clone().into_bytes()
    }
}


pub fn parse_pssh_data(buf: &[u8]) -> Result<IrdetoPsshData> {
    let mut rdr = Cursor::new(buf);
    let _ignore1 = rdr.read_u32::<LittleEndian>()?;
    let _ignore2 = rdr.read_u32::<LittleEndian>()?;
    let _ignore3 = rdr.read_u8()?;
    let mut utf8buf = Vec::new();
    let xmllen = (buf.len() - 9) as u64;
    rdr.take(xmllen).read_to_end(&mut utf8buf)?;
    let xml = String::from_utf8(utf8buf)?;
    Ok(IrdetoPsshData { xml })
}
