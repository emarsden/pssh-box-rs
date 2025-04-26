/// Tests for the serialization functionality

use test_log::test;
use pssh_box::{from_base64, DRMKeyId, DRMSystemId};
use pssh_box::{WIDEVINE_SYSTEM_ID, COMMON_SYSTEM_ID};


#[test]
fn test_serialization_systemid() {
    assert_eq!(COMMON_SYSTEM_ID, DRMSystemId::try_from("1077efecc0b24d02ace33c1e52e2fb4b").unwrap());
    assert_eq!(WIDEVINE_SYSTEM_ID, DRMSystemId::try_from("edef8ba979d64acea3c827dcd51d21ed").unwrap());
    assert_eq!(WIDEVINE_SYSTEM_ID, DRMSystemId::try_from("EDEF8BA979D64ACEA3C827DCD51D21ED").unwrap());

    let wvs = WIDEVINE_SYSTEM_ID.to_string();
    assert!(wvs.contains("Widevine"));
    assert!(wvs.contains("DRMSystemId"));
    assert!(wvs.contains("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"));
}

#[test]
fn test_serialization_drmkeyid() {
    assert_eq!("DRMKeyId<72c3ed2c-7a5f-4aad-902f-cbef1efe89a9>",
               DRMKeyId::try_from("72c3ed2c7a5f4aad902fcbef1efe89a9").unwrap().to_string());

    assert_eq!("DRMKeyId<72c3ed2c-7a5f-4aad-902f-cbef1efe89a9>",
               DRMKeyId::try_from("72c3ed2c-7a5f-4aad-902f-cbef1efe89a9").unwrap().to_string());
}

#[test]
fn test_serialization_pssh() {
    let b64 = "AAAAOHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABgSEAAWNwaftdGsPEdH4BMi5MJI49yVmwY=";
    let boxes = from_base64(b64).unwrap();
    let bxs = boxes.to_string();
    assert!(bxs.contains("WidevinePSSH"));
    assert!(bxs.contains("001637069fb5d1ac3c4747e01322e4c2"));
    assert!(bxs.contains("CENC"));
    assert_eq!(boxes.clone().to_base64(), b64);
    assert_eq!(boxes.to_hex(),
               "000000387073736800000000edef8ba979d64acea3c827dcd51d21ed000000181210001637069fb5d1ac3c4747e01322e4c248e3dc959b06");
}


#[test]
fn test_serialization_psshdata() {
    let b64 = "AAAAOHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABgSEAAWNwaftdGsPEdH4BMi5MJI49yVmwY=";
    let boxes = from_base64(b64).unwrap();
    let box_psshdata = &boxes[0].pssh_data;
    let serialized = box_psshdata.to_string();
    assert!(serialized.contains("WidevinePSSHData"));
    assert!(serialized.contains("001637069fb5d1ac3c4747e01322e4c2"));
    assert!(serialized.contains("CENC"));
    assert!(serialized.contains("protection_scheme"));

    // A Widevine v1 PSSH box
    let boxes = from_base64("AAAAinBzc2gBAAAA7e+LqXnWSs6jyCfc1R0h7QAAAAMBABjPrw1FrZKp3Uaklub1AQFA6rnmTx2Vc6TOTwKt2wEC6NEQrkqOnj8BE9GY8RcAAAA2EhABABjPrw1FrZKp3Uaklub1EhABAUDqueZPHZVzpM5PAq3bEhABAujREK5Kjp4/ARPRmPEX")
        .unwrap();
    let box_psshdata = &boxes[0].pssh_data;
    let serialized = box_psshdata.to_string();
    assert!(serialized.contains("WidevinePSSHData"));
    assert!(serialized.contains("010018cfaf0d45ad92a9dd46a496e6f5"));
    assert!(serialized.contains("010140eab9e64f1d9573a4ce4f02addb"));
    assert!(serialized.contains("0102e8d110ae4a8e9e3f0113d198f117"));

    // A PlayReady PSSH box
    let boxes = from_base64("AAACJnBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAAgYGAgAAAQABAPwBPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgBNAGwAUwBKAFYAMwBhAFkAUgBTAE4ASABWAG0AVgBIAEsAVABnAGoAUQBRAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+AFUARwBOAFYAQgBTAHUAZwAzADgAcwA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    let box_psshdata = &boxes[0].pssh_data;
    let serialized = box_psshdata.to_string();
    assert!(serialized.contains("PlayReadyPSSHData"));
    assert!(serialized.contains("UGNVBSug38s="));
    assert!(serialized.contains("MlSJV3aYRSNHVmVHKTgjQQ=="));
    assert!(serialized.contains("AESCTR"));
}


