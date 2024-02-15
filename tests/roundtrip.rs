// Test roundtripping (parsing and serializing)
//
//   cargo test --test roundtrip -- --show-output

use test_log::test;
use pretty_assertions::assert_eq;
use pssh_box::{from_base64, ToBytes, from_bytes, PsshData};
use pssh_box::{WIDEVINE_SYSTEM_ID, PLAYREADY_SYSTEM_ID};


#[test]
fn test_roundtrip_widevine() {
    let boxes = from_base64("AAAAR3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACcIARIBMBoNd2lkZXZpbmVfdGVzdCIKMjAxNV90ZWFycyoFQVVESU8=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    println!("PARSED> {pssh:?}");
    let octets = pssh.to_bytes();
    let reflected_boxes = from_bytes(&octets).unwrap();
    assert_eq!(reflected_boxes.len(), 1);
    let reflected = &reflected_boxes[0];
    println!("REFLECTED> {reflected:?}");
    assert_eq!(pssh.version, reflected.version);
    assert_eq!(reflected.system_id, WIDEVINE_SYSTEM_ID);
    if let PsshData::Widevine(ref pd1) = pssh.pssh_data {
        if let PsshData::Widevine(ref pd2) = reflected.pssh_data {
            assert_eq!(pd1.content_id, pd2.content_id);
            assert_eq!(pd1.provider, pd2.provider);
            assert_eq!(pd1.key_id, pd2.key_id);
        }
    }
}



#[test]
fn test_roundtrip_playready() {
    let boxes = from_base64("AAACJnBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAAgYGAgAAAQABAPwBPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgBNAGwAUwBKAFYAMwBhAFkAUgBTAE4ASABWAG0AVgBIAEsAVABnAGoAUQBRAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+AFUARwBOAFYAQgBTAHUAZwAzADgAcwA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    println!("PARSED> {pssh:?}");
    let octets = pssh.to_bytes();
    let reflected_boxes = from_bytes(&octets).unwrap();
    assert_eq!(reflected_boxes.len(), 1);
    let reflected = &reflected_boxes[0];
    println!("REFLECTED> {reflected:?}");
    assert_eq!(pssh.version, reflected.version);
    assert_eq!(reflected.system_id, PLAYREADY_SYSTEM_ID);
    if let PsshData::PlayReady(ref pd1) = pssh.pssh_data {
        if let PsshData::PlayReady(ref pd2) = reflected.pssh_data {
            let wrmh1 = &pd1.record[0].record_value;
            let wrmh2 = &pd2.record[0].record_value;
            assert_eq!(wrmh1.data.checksum, wrmh2.data.checksum);
            assert_eq!(wrmh1.data.kids[0].content, wrmh2.data.kids[0].content);
        }
    }
}

