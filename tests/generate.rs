//! generate.rs -- tests for generating PSSH boxes


use base64::prelude::{Engine as _, BASE64_STANDARD};
use test_log::test;
use pssh_box::{pprint, from_bytes, from_base64, from_hex, ToBytes, PsshBox, PsshData, DRMKeyId};
use pssh_box::{WIDEVINE_SYSTEM_ID, PLAYREADY_SYSTEM_ID};


#[test]
fn test_roundtrip_widevine_bytes() {
    let mut pssh = PsshBox::new_widevine();
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    let kid = DRMKeyId::try_from("4444aaaa2222bbbb8888eeee7777cccc").unwrap();
    pssh.add_key_id(kid);
    if let PsshData::Widevine(ref mut pd) = pssh.pssh_data {
        pd.provider = Some(String::from("pssh-box-rs"));
        pd.content_id = Some(hex::encode("DEADBEAF").into());
        assert_eq!(pd.policy, None);
    }
    pprint(&pssh);
    let serialized = pssh.clone().to_bytes();
    let boxes = from_bytes(&serialized).unwrap();
    assert_eq!(boxes.len(), 1);
    let parsed = &boxes[0];
    assert_eq!(parsed.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(parsed.key_ids[0], kid);
    if let PsshData::Widevine(ref pd) = parsed.pssh_data {
        assert_eq!(pd.provider, Some(String::from("pssh-box-rs")));
        assert_eq!(pd.content_id, Some(hex::encode("DEADBEAF").into()));
        assert_eq!(pd.policy, None);
    }
}


#[test]
fn test_roundtrip_widevine_base64() {
    let mut pssh = PsshBox::new_widevine();
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    let kid = DRMKeyId::try_from("4444aaaa2222bbbb8888eeee7777cccc").unwrap();
    pssh.add_key_id(kid);
    if let PsshData::Widevine(ref mut pd) = pssh.pssh_data {
        pd.provider = Some(String::from("pssh-box-rs"));
        pd.content_id = Some(hex::encode("DEADBEAF").into());
    }
    pprint(&pssh);
    let b64 = pssh.clone().to_base64();
    let boxes = from_base64(&b64).unwrap();
    assert_eq!(boxes.len(), 1);
    let parsed = &boxes[0];
    assert_eq!(parsed.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(parsed.key_ids[0], kid);
    if let PsshData::Widevine(ref pd) = parsed.pssh_data {
        assert_eq!(pd.provider, Some(String::from("pssh-box-rs")));
        assert_eq!(pd.content_id, Some(hex::encode("DEADBEAF").into()));
    }
}


#[test]
fn test_roundtrip_widevine_hex() {
    let mut pssh = PsshBox::new_widevine();
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    let kid1 = DRMKeyId::try_from("4444aaaa2222bbbb8888eeee7777cccc").unwrap();
    pssh.add_key_id(kid1);
    let kid2 = DRMKeyId::try_from("AAAAaaaa222200008888dddd3333eeee").unwrap();
    pssh.add_key_id(kid2);
    if let PsshData::Widevine(ref mut pd) = pssh.pssh_data {
        pd.provider = Some(String::from("pssh-box-rs"));
        pd.content_id = Some(hex::encode("DEADBEAF").into());
    }
    pprint(&pssh);
    let hx = pssh.clone().to_hex();
    let boxes = from_hex(&hx).unwrap();
    assert_eq!(boxes.len(), 1);
    let parsed = &boxes[0];
    assert_eq!(parsed.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(parsed.key_ids[0], kid1);
    assert_eq!(parsed.key_ids[1], kid2);
    if let PsshData::Widevine(ref pd) = parsed.pssh_data {
        assert_eq!(pd.provider, Some(String::from("pssh-box-rs")));
        assert_eq!(pd.content_id, Some(hex::encode("DEADBEAF").into()));
    }
}


#[test]
fn test_roundtrip_playready_bytes() {
    let mut pssh = PsshBox::new_playready();
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    let kid1 = DRMKeyId::try_from("4444aaaa2222bbbb8888eeee7777cccc").unwrap();
    pssh.add_key_id(kid1);
    let kid2 = DRMKeyId::try_from("AAAAaaaa222200008888dddd3333eeee").unwrap();
    pssh.add_key_id(kid2);
    if let PsshData::PlayReady(ref mut pd) = pssh.pssh_data {
        let wrmh = &mut pd.record[0].record_value;
        wrmh.data.checksum = Some(BASE64_STANDARD.decode("7zDsYfDVHUY=").unwrap());
        wrmh.data.lui_url = Some(String::from("http://www.example.com/"));
    }
    pprint(&pssh);
    let serialized = pssh.to_bytes();
    let boxes = from_bytes(&serialized).unwrap();
    let parsed = &boxes[0];
    assert_eq!(parsed.system_id, PLAYREADY_SYSTEM_ID);
    assert_eq!(parsed.key_ids[0], kid1);
    assert_eq!(parsed.key_ids[1], kid2);
    println!("PlayReady> {pssh:?}");
    if let PsshData::PlayReady(ref pd) = parsed.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("7zDsYfDVHUY=").unwrap()));
    }
}


#[test]
fn test_roundtrip_playready_base64() {
    let mut pssh = PsshBox::new_playready();
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    let kid1 = DRMKeyId::try_from("4444aaaa2222bbbb8888eeee7777cccc").unwrap();
    pssh.add_key_id(kid1);
    let kid2 = DRMKeyId::try_from("AAAAaaaa222200008888dddd3333eeee").unwrap();
    pssh.add_key_id(kid2);
    if let PsshData::PlayReady(ref mut pd) = pssh.pssh_data {
        let wrmh = &mut pd.record[0].record_value;
        wrmh.data.checksum = Some(BASE64_STANDARD.decode("7zDsYfDVHUY=").unwrap());
        wrmh.data.lui_url = Some(String::from("http://www.example.com/"));
    }
    pprint(&pssh);
    let serialized = pssh.clone().to_base64();
    let boxes = from_base64(&serialized).unwrap();
    let parsed = &boxes[0];
    assert_eq!(parsed.system_id, PLAYREADY_SYSTEM_ID);
    assert_eq!(parsed.key_ids[0], kid1);
    assert_eq!(parsed.key_ids[1], kid2);
    println!("PlayReady> {pssh:?}");
    if let PsshData::PlayReady(ref pd) = parsed.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("7zDsYfDVHUY=").unwrap()));
        assert_eq!(wrmh.data.lui_url, Some(String::from("http://www.example.com/")));
    }
}
