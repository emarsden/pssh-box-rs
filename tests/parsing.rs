/// Tests for PSSH box parsing

use base64::prelude::{Engine as _, BASE64_STANDARD};
use test_log::test;
use pssh_box::{from_base64, from_hex, from_bytes, from_buffer, find_iter, pprint};
use pssh_box::{PsshData, DRMKeyId};
use pssh_box::{
    WIDEVINE_SYSTEM_ID,
    PLAYREADY_SYSTEM_ID,
    COMMON_SYSTEM_ID,
    IRDETO_SYSTEM_ID,
    WISEPLAY_SYSTEM_ID,
    MARLIN_SYSTEM_ID,
    NAGRA_SYSTEM_ID,
    FAIRPLAYNFLX_SYSTEM_ID};


#[test]
fn test_parsing_widevine_v0() {
    let boxes = from_base64("AAAAR3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACcIARIBMBoNd2lkZXZpbmVfdGVzdCIKMjAxNV90ZWFycyoFQVVESU8=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.flags, 0);
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert!(pd.provider.clone().is_some_and(|p| p.eq("widevine_test")));
        assert_eq!(pd.content_id, Some(hex::decode("323031355f7465617273").unwrap()));
    }
    // check the PartialEq implementation
    assert!(boxes[0] == boxes[0]);
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAOHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABgSEAAWNwaftdGsPEdH4BMi5MJI49yVmwY=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert_eq!(pd.key_id[0], hex::decode("001637069fb5d1ac3c4747e01322e4c2").unwrap());
    }
    assert!(boxes[0] == boxes[0]);

    let boxes = from_base64("AAAAOnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABoIARIQt1vS7XqCQEOkj9mf8WoEESIENDc2Nw==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert_eq!(pd.key_id[0], hex::decode("b75bd2ed7a824043a48fd99ff16a0411").unwrap());
    }
    assert!(boxes[0] == boxes[0]);

    let boxes = from_base64("AAAAQ3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACMIARIQRc7BRWnQbPdkXpj/3TelrhoKaW50ZXJ0cnVzdCIBKg==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert!(pd.provider.clone().is_some_and(|p| p.eq("intertrust")));
        assert_eq!(pd.key_id[0], hex::decode("45cec14569d06cf7645e98ffdd37a5ae").unwrap());
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAoXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAIEIARIQKeEoCifIPZGWInj0Hhjc5hoIY2FzdGxhYnMiWGV5SmhjM05sZEVsa0lqb2lPRFE1WldJMk1qYzVORFkwTVRaaU1EZGpNemxrWkdRMU5UazFNVEJtTTJFaUxDSjJZWEpwWVc1MFNXUWlPaUpoZG10bGVTSjkyB2RlZmF1bHQ=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert!(pd.provider.clone().is_some_and(|p| p.eq("castlabs")));
        assert_eq!(pd.key_id[0], hex::decode("29e1280a27c83d91962278f41e18dce6").unwrap());
        assert_eq!(pd.content_id, Some(hex::decode("65794a6863334e6c64456c6b496a6f694f4451355a5749324d6a63354e4459304d545a694d44646a4d7a6c6b5a4751314e546b314d54426d4d3245694c434a3259584a7059573530535751694f694a68646d746c65534a39").unwrap()));
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAZ3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAEcSEKqL5HpT2ymw4FM7KEUKHLsaA3NmciIkYWE4YmU0N2EtNTNkYi0yOWIwLWUwNTMtM2IyODQ1MGExY2JiKgJTREjj3JWbBg==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert!(pd.provider.clone().is_some_and(|p| p.eq("sfr")));
        assert_eq!(pd.key_id[0], hex::decode("aa8be47a53db29b0e0533b28450a1cbb").unwrap());
        assert_eq!(pd.content_id, Some(hex::decode("61613862653437612d353364622d323962302d653035332d336232383435306131636262").unwrap()));
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAWHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADgIARIQwJbQbFg0QpKbCITZyoPU8SIgdUM4NUFGMlJ6VjdyNXJ0ZG82QkNtcEtCNFBkd2RWbUM4AQ==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    pprint(&pssh);
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(pssh.version, 0);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert_eq!(pd.crypto_period_index, Some(1));
        assert_eq!(pd.key_id[0], hex::decode("c096d06c583442929b0884d9ca83d4f1").unwrap());
        assert_eq!(pd.content_id, Some(hex::decode("75433835414632527a563772357274646f3642436d704b423450647764566d43").unwrap()));
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAU3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADMIARIQ//Y9s82cGtnaeOe0vPYOJxoNYW1hem9udHZjcmltZSIIdGFtX3Rlc3QqAlNEMgA=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(pssh.version, 0);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert!(pd.provider.clone().is_some_and(|p| p.eq("amazontvcrime")));
        assert_eq!(pd.key_id[0], hex::decode("fff63db3cd9c1ad9da78e7b4bcf60e27").unwrap());
        assert_eq!(pd.content_id, Some(hex::decode("74616d5f74657374").unwrap()));
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAbHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAEwSEA/M6FMNXeIEO8NRh6i8CqMaJDNlNjkwMGE1LTI4MDMtNGZkZS1hN2YxLTg0OWU5YWVkNTc1MCIMQ0lEOjE2Mjc5MDY0SOPclZsG")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(pssh.version, 0);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert!(pd.provider.clone().is_some_and(|p| p.eq("3e6900a5-2803-4fde-a7f1-849e9aed5750")));
        assert_eq!(pd.key_id[0], hex::decode("0fcce8530d5de2043bc35187a8bc0aa3").unwrap());
        assert_eq!(pd.content_id, Some(hex::decode("4349443a3136323739303634").unwrap()));
    }
}


#[test]
fn test_parsing_widevine_v1() {
    use pssh_box::widevine::widevine_pssh_data::ProtectionScheme;

    let boxes = from_base64("AAAAjHBzc2gBAAAA7e+LqXnWSs6jyCfc1R0h7QAAAAGEDVzJ+kUjqDFkRRxhWyBqAAAAWCJQbVZVVnEzUE4tTWZKamxyU2MtRG1DTDViMWktMzQ1MDQ5NjZfMzQ1MDQ5NjdfMzQ1MDQ5NjhfMzQ1MDQ5NzFfMzQ1MDQ5NzJfMzQ1MDQ5NzNI49yVmwY=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.version, 1);
    assert_eq!(pssh.flags, 0);
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("840d5cc9fa4523a83164451c615b206a").unwrap());
    println!("Widevine-v1> {pssh:?}");
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, Some(hex::decode("6d5655567133504e2d4d664a6a6c7253632d446d434c356231692d33343530343936365f33343530343936375f33343530343936385f33343530343937315f33343530343937325f3334353034393733").unwrap()));
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAUnBzc2gBAAAA7e+LqXnWSs6jyCfc1R0h7QAAAAGGfI12cOq156oQVxgwrT2MAAAAHiIWRVZNQkNQTFVTRUxJRkVIRFkyMDIzTUjj3JWbBg==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.version, 1);
    assert_eq!(pssh.flags, 0);
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("867c8d7670eab5e7aa10571830ad3d8c").unwrap());
    println!("Widevine-v1> {pssh:?}");
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, Some(hex::decode("45564d4243504c5553454c494645484459323032334d").unwrap()));
    }
    assert!(boxes.contains(&boxes[0]));

    // an example with multiple key_ids
    let boxes = from_base64("AAAAxnBzc2gBAAAA7e+LqXnWSs6jyCfc1R0h7QAAAAINw+xPdoNUi4HnPGTlguE2FEe37S9mVyu9EwbOfPNhDQAAAIISEBRHt+0vZlcrvRMGznzzYQ0SEFrGoR6qL17Vv2aMQByBNMoSEG7hNRbI51h7rp9+zT6Zom4SEPnsEqYaJl1Hj4MzTjp40scSEA3D7E92g1SLgec8ZOWC4TYaDXdpZGV2aW5lX3Rlc3QiEXVuaWZpZWQtc3RyZWFtaW5nSOPclZsG")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("0dc3ec4f7683548b81e73c64e582e136").unwrap());
    assert_eq!(pssh.key_ids[1], DRMKeyId::try_from("1447b7ed2f66572bbd1306ce7cf3610d").unwrap());
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, Some(hex::decode("756e69666965642d73747265616d696e67").unwrap()));
        assert_eq!(pd.provider, Some(String::from("widevine_test")));
        assert_eq!(pd.key_id.len(), 5);
        assert_eq!(pd.key_id[1], hex::decode("5ac6a11eaa2f5ed5bf668c401c8134ca").unwrap());
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAjHBzc2gBAAAA7e+LqXnWSs6jyCfc1R0h7QAAAAGEDVzJ+kUjqDFkRRxhWyBqAAAAWCJQbVZVVnEzUE4tTWZKamxyU2MtRG1DTDViMWktMzQ1MDQ5NjZfMzQ1MDQ5NjdfMzQ1MDQ5NjhfMzQ1MDQ5NzFfMzQ1MDQ5NzJfMzQ1MDQ5NzNI49yVmwY=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("840d5cc9fa4523a83164451c615b206a").unwrap());
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, Some(hex::decode("6d5655567133504e2d4d664a6a6c7253632d446d434c356231692d33343530343936365f33343530343936375f33343530343936385f33343530343937315f33343530343937325f3334353034393733").unwrap()));
        assert_eq!(pd.provider, None);
        assert_eq!(ProtectionScheme::try_from(pd.protection_scheme.unwrap()).unwrap(),
                   ProtectionScheme::from_str_name("CENC").unwrap());
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAinBzc2gBAAAA7e+LqXnWSs6jyCfc1R0h7QAAAAMBABjPrw1FrZKp3Uaklub1AQFA6rnmTx2Vc6TOTwKt2wEC6NEQrkqOnj8BE9GY8RcAAAA2EhABABjPrw1FrZKp3Uaklub1EhABAUDqueZPHZVzpM5PAq3bEhABAujREK5Kjp4/ARPRmPEX")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(pssh.key_ids.len(), 3);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("010018cfaf0d45ad92a9dd46a496e6f5").unwrap());
    assert!(boxes.contains(&boxes[0]));
}


#[test]
fn test_parsing_playready_v0() {
    let boxes = from_base64("AAACxHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAAqSkAgAAAQABAJoCPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgB4AG8AeQB1AHYAMgBhAEUAcQA2ADQASwBqAFAAUgBEAHQANgBTAHcAQwBBAD0APQA8AC8ASwBJAEQAPgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAGQAcgBtAC4AcgBlAGQAZQBmAGkAbgBlAC4AcABsAC8AUABsAGEAeQBSAGUAYQBkAHkALwByAGkAZwBoAHQAcwBtAGEAbgBhAGcAZQByAC4AYQBzAG0AeAA/AHQAeQBwAGUAPQBkAGEAcwBoADwALwBMAEEAXwBVAFIATAA+ADwAQwBIAEUAQwBLAFMAVQBNAD4ALwA4AEkANABYAGEAUAB0ADIASgA4AD0APAAvAEMASABFAEMASwBTAFUATQA+ADwALwBEAEEAVABBAD4APAAvAFcAUgBNAEgARQBBAEQARQBSAD4A")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    // println!("PLAYREADY> {pssh:?}");
    assert_eq!(pssh.flags, 0);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("/8I4XaPt2J8=").unwrap()));
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAADMnBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAAxISAwAAAQABAAgDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgBxADAAcQAwAGgAKwAyAG0AZQAwADIAVABMAFIAVgBaAGcAdgBOADEAVQBRAD0APQA8AC8ASwBJAEQAPgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAGwAaQBjAC4AZAByAG0AdABvAGQAYQB5AC4AYwBvAG0ALwBsAGkAYwBlAG4AcwBlAC0AcAByAG8AeAB5AC0AaABlAGEAZABlAHIAYQB1AHQAaAAvAGQAcgBtAHQAbwBkAGEAeQAvAFIAaQBnAGgAdABzAE0AYQBuAGEAZwBlAHIALgBhAHMAbQB4ADwALwBMAEEAXwBVAFIATAA+ADwATABVAEkAXwBVAFIATAA+AGgAdAB0AHAAcwA6AC8ALwBwAGwAYQB5AHIAZQBhAGQAeQAuAGMAbwBtADwALwBMAFUASQBfAFUAUgBMAD4APABDAEgARQBDAEsAUwBVAE0APgByAGUASwAvAHoATQAyAGoAOABwAHcAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APAAvAEQAQQBUAEEAPgA8AC8AVwBSAE0ASABFAEEARABFAFIAPgA=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    // println!("PLAYREADY> {pssh:?}");
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("reK/zM2j8pw=").unwrap()));
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAACJnBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAAgYGAgAAAQABAPwBPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgBNAGwAUwBKAFYAMwBhAFkAUgBTAE4ASABWAG0AVgBIAEsAVABnAGoAUQBRAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+AFUARwBOAFYAQgBTAHUAZwAzADgAcwA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("PLAYREADY> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("UGNVBSug38s=").unwrap()));
        assert_eq!(wrmh.data.kids[0].content, BASE64_STANDARD.decode("MlSJV3aYRSNHVmVHKTgjQQ==").unwrap());
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAACyHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAAqioAgAAAQABAJ4CPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgByAHAAcQBVAGUARgBWAEUAcgBlAHMAbQBHADcAYgA4AGMAMABOADEAUwBnAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+ACsARgBvAHEAWgBIADYASwB5ADQAVQA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAHAAbABhAHkAcgBlAGEAZAB5AC0AYwBvAHIAZQAuAHQAdgBuAG8AdwAuAGQAZQAvAHAAbABhAHkAcgBlAGEAZAB5AC8AYQBwAGkALwBSAGkAZwBoAHQAcwBNAGEAbgBhAGcAZQByAC4AYQBzAG0AeAA8AC8ATABBAF8AVQBSAEwAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    // println!("PLAYREADY> {pssh:?}");
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("+FoqZH6Ky4U=").unwrap()));
        assert_eq!(wrmh.data.kids[0].content, BASE64_STANDARD.decode("rpqUeFVEresmG7b8c0N1Sg==").unwrap());
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAACrnBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAAo6OAgAAAQABAIQCPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgA5AGYAMABpAEMAZgBwAHEAbwBFAEcASQBZAFYAMABiAHkARQB5AHMAWQBBAD0APQA8AC8ASwBJAEQAPgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcAA6AC8ALwBmAGEAbABzAGUAPAAvAEwAQQBfAFUAUgBMAD4APABEAFMAXwBJAEQAPgBWAGwAUgA3AEkAZABzAEkASgBFAHUAUgBkADAANgBMAGEAcQBzADIAagB3AD0APQA8AC8ARABTAF8ASQBEAD4APABDAEgARQBDAEsAUwBVAE0APgBkAG8AOABRAGQAZgBjAFIAQwA0AFEAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APAAvAEQAQQBUAEEAPgA8AC8AVwBSAE0ASABFAEEARABFAFIAPgA=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    // println!("PLAYREADY> {pssh:?}");
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("do8QdfcRC4Q=").unwrap()));
        assert_eq!(wrmh.data.kids[0].content, BASE64_STANDARD.decode("9f0iCfpqoEGIYV0byEysYA==").unwrap());
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAADwHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA6CgAwAAAQABAJYDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgAwAGsAQgBHAFcANQBrAHUATQBVAHEAOABOAE8ATgBjAC8AWABEAGMAVwBBAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+ADcATQB2AG4AbgBuAFUAdABhAGkAOAA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAHYAZABoADkAOQBzADYAcwAuAGEAbgB5AGMAYQBzAHQALgBuAGEAZwByAGEALgBjAG8AbQAvAFYARABIADkAOQBTADYAUwAvAHAAcgBsAHMALwBjAG8AbgB0AGUAbgB0AGwAaQBjAGUAbgBzAGUAcwBlAHIAdgBpAGMAZQAvAHYAMQAvAGwAaQBjAGUAbgBzAGUAcwA8AC8ATABBAF8AVQBSAEwAPgA8AEMAVQBTAFQATwBNAEEAVABUAFIASQBCAFUAVABFAFMAPgA8AG4AdgA6AEMAbwBuAHQAZQBuAHQASQBkACAAeABtAGwAbgBzADoAbgB2AD0AIgB1AHIAbgA6AHMAYwBoAGUAbQBhAC0AcwBzAHAALQBuAGEAZwByAGEALQBjAG8AbQAiAD4ANQA3ADEAMgA8AC8AbgB2ADoAQwBvAG4AdABlAG4AdABJAGQAPgA8AC8AQwBVAFMAVABPAE0AQQBUAFQAUgBJAEIAVQBUAEUAUwA+ADwALwBEAEEAVABBAD4APAAvAFcAUgBNAEgARQBBAEQARQBSAD4A")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("7MvnnnUtai8=").unwrap()));
        assert!(wrmh.data.la_url.as_ref().is_some_and(|u| u.contains("anycast.nagra.com")));
        assert!(wrmh.data.custom_attributes.as_ref().is_some_and(|ca| ca.contains("nv:ContentId")));
        assert!(wrmh.data.custom_attributes.as_ref().is_some_and(|ca| ca.contains("5712")));
    }

    let boxes = from_base64("AAAD0nBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA7KyAwAAAQABAKgDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgByAG8ASABWAE8ATQBWAGoAMwBFAHkAMQAwADIAbwBWAFgAYwB2AGUASABBAD0APQA8AC8ASwBJAEQAPgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcAA6AC8ALwBkAHIAbQAuAGMAYQBuAGEAbAAtAHAAbAB1AHMALgBjAG8AbQAvADwALwBMAEEAXwBVAFIATAA+ADwATABVAEkAXwBVAFIATAA+AGgAdAB0AHAAOgAvAC8AZAByAG0ALgBjAGEAbgBhAGwALQBwAGwAdQBzAC4AYwBvAG0ALwA8AC8ATABVAEkAXwBVAFIATAA+ADwARABTAF8ASQBEAD4AeQBZAEkAUABEAEIAYwBhADEAawBtAE0AZgBMADYAMABJAHMAZgBnAEEAUQA9AD0APAAvAEQAUwBfAEkARAA+ADwAQwBVAFMAVABPAE0AQQBUAFQAUgBJAEIAVQBUAEUAUwAgAHgAbQBsAG4AcwA9ACIAIgA+ADwAZQBuAGMAcgB5AHAAdABpAG8AbgByAGUAZgA+ADEANwAxADEAMQAxADkANgAzADcAPAAvAGUAbgBjAHIAeQBwAHQAaQBvAG4AcgBlAGYAPgA8AC8AQwBVAFMAVABPAE0AQQBUAFQAUgBJAEIAVQBUAEUAUwA+ADwAQwBIAEUAQwBLAFMAVQBNAD4AWQBnAGcAUABzAGEAbABTAHEASgB3AD0APAAvAEMASABFAEMASwBTAFUATQA+ADwALwBEAEEAVABBAD4APAAvAFcAUgBNAEgARQBBAEQARQBSAD4A")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("YggPsalSqJw=").unwrap()));
        assert!(wrmh.data.la_url.as_ref().is_some_and(|u| u.contains("drm.canal-plus.com")));
        assert!(wrmh.data.lui_url.as_ref().is_some_and(|u| u.contains("drm.canal-plus.com")));
        assert!(wrmh.data.custom_attributes.as_ref().is_some_and(|ca| ca.contains("<encryptionref>")));
        assert!(wrmh.data.custom_attributes.as_ref().is_some_and(|ca| ca.contains("1711119637")));
    }

    let boxes = from_base64("AAAD4nBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA8LCAwAAAQABALgDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgBQAHoAVwAzAHoAWQBMAHEAMQBFAG0AYgBpAGYANABJAGMASQBLAG4ATgBBAD0APQA8AC8ASwBJAEQAPgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcAA6AC8ALwBwAHIALQBrAGUAeQBvAHMALgBsAGkAYwBlAG4AcwBlAGsAZQB5AHMAZQByAHYAZQByAC4AYwBvAG0ALwBjAG8AcgBlAC8AcgBpAGcAaAB0AHMAbQBhAG4AYQBnAGUAcgAuAGEAcwBtAHgAPAAvAEwAQQBfAFUAUgBMAD4APABEAFMAXwBJAEQAPgBWAGwAUgA3AEkAZABzAEkASgBFAHUAUgBkADAANgBMAGEAcQBzADIAagB3AD0APQA8AC8ARABTAF8ASQBEAD4APABDAFUAUwBUAE8ATQBBAFQAVABSAEkAQgBVAFQARQBTACAAeABtAGwAbgBzAD0AIgAiAD4APABDAEkARAA+AFAAegBXADMAegBZAEwAcQAxAEUAbQBiAGkAZgA0AEkAYwBJAEsAbgBOAEEAPQA9ADwALwBDAEkARAA+ADwARABSAE0AVABZAFAARQA+AHMAbQBvAG8AdABoADwALwBEAFIATQBUAFkAUABFAD4APAAvAEMAVQBTAFQATwBNAEEAVABUAFIASQBCAFUAVABFAFMAPgA8AEMASABFAEMASwBTAFUATQA+AGgAVABWAGgAWAA5AEgANwBnAEsAMAA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("PLAYREADY###> {pssh:?}");
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("hTVhX9H7gK0=").unwrap()));
        assert!(wrmh.data.la_url.as_ref().is_some_and(|u| u.contains("pr-keyos.licensekeyserver.com")));
        assert!(wrmh.data.custom_attributes.as_ref().is_some_and(|ca| ca.contains("<CID>PzW3zYLq1Embif4IcIKnNA==</CID>")));
        assert!(wrmh.data.custom_attributes.as_ref().is_some_and(|ca| ca.contains("<DRMTYPE>smooth</DRMTYPE>")));
    }
}



#[test]
fn test_parsing_playready_v1() {
    let boxes = from_base64("AAADrHBzc2gBAAAAmgTweZhAQoarkuZb4IhflQAAAAGEDVzJ+kUjqDFkRRxhWyBqAAADeHgDAAABAAEAbgM8AFcAUgBNAEgARQBBAEQARQBSACAAeABtAGwAbgBzAD0AIgBoAHQAdABwADoALwAvAHMAYwBoAGUAbQBhAHMALgBtAGkAYwByAG8AcwBvAGYAdAAuAGMAbwBtAC8ARABSAE0ALwAyADAAMAA3AC8AMAAzAC8AUABsAGEAeQBSAGUAYQBkAHkASABlAGEAZABlAHIAIgAgAHYAZQByAHMAaQBvAG4APQAiADQALgAwAC4AMAAuADAAIgA+ADwARABBAFQAQQA+ADwAUABSAE8AVABFAEMAVABJAE4ARgBPAD4APABLAEUAWQBMAEUATgA+ADEANgA8AC8ASwBFAFkATABFAE4APgA8AEEATABHAEkARAA+AEEARQBTAEMAVABSADwALwBBAEwARwBJAEQAPgA8AC8AUABSAE8AVABFAEMAVABJAE4ARgBPAD4APABLAEkARAA+AHkAVgB3AE4AaABFAFgANgBxAEMATQB4AFoARQBVAGMAWQBWAHMAZwBhAGcAPQA9ADwALwBLAEkARAA+ADwATABBAF8AVQBSAEwAPgBoAHQAdABwAHMAOgAvAC8AcABsAGEAeQByAGUAYQBkAHkALQBsAGkAYwBlAG4AcwBlAC4AdgB1AGQAcgBtAC4AdABlAGMAaAAvAHIAaQBnAGgAdABzAG0AYQBuAGEAZwBlAHIALgBhAHMAbQB4ADwALwBMAEEAXwBVAFIATAA+ADwATABVAEkAXwBVAFIATAA+AGgAdAB0AHAAcwA6AC8ALwBwAGwAYQB5AHIAZQBhAGQAeQAtAGwAaQBjAGUAbgBzAGUALgB2AHUAZAByAG0ALgB0AGUAYwBoAC8AcgBpAGcAaAB0AHMAbQBhAG4AYQBnAGUAcgAuAGEAcwBtAHgAPAAvAEwAVQBJAF8AVQBSAEwAPgA8AEQAUwBfAEkARAA+AGcAdwBJAEMASQA4AHkAZgBJAFUARwBmADQAUgAvADUAcQBPAFcAdQBxAGcAPQA9ADwALwBEAFMAXwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+ADcAegBEAHMAWQBmAEQAVgBIAFUAWQA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("840d5cc9fa4523a83164451c615b206a").unwrap());
    println!("PLAYREADY-v1> {pssh:?}");
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("7zDsYfDVHUY=").unwrap()));
        assert!(wrmh.data.lui_url.as_ref().is_some_and(|s| s.contains("playready-license.vudrm.tech")));
    }
    assert!(boxes.contains(&boxes[0]));

    // FIXME this one has version 4.2.0.0 and a kid inside <KIDS><KID> ...</KID></KIDS>
    let boxes = from_base64("AAAFyHBzc2gBAAAAmgTweZhAQoarkuZb4IhflQAAAAPoLxhMOqpXtKzoYGteP+utCHvPxvelVxa4QGqm66M2ng1rQCONoV51r2h1xRTFm2MAAAV0dAUAAAEAAQBqBTwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADIALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAFMAPgA8AEsASQBEACAAQQBMAEcASQBEAD0AIgBBAEUAUwBDAFQAUgAiACAAQwBIAEUAQwBLAFMAVQBNAD0AIgArAE4AVgA5AC8AOABqAGIAZgByAHcAPQAiACAAVgBBAEwAVQBFAD0AIgBUAEIAZwB2ADYASwBvADYAdABGAGUAcwA2AEcAQgByAFgAagAvAHIAcgBRAD0APQAiAD4APAAvAEsASQBEAD4APABLAEkARAAgAEEATABHAEkARAA9ACIAQQBFAFMAQwBUAFIAIgAgAEMASABFAEMASwBTAFUATQA9ACIAWgAxADAAaQBPAFkAWQB6AEgAMwBrAD0AIgAgAFYAQQBMAFUARQA9ACIAeABzADkANwBDAEsAWAAzAEYAbABlADQAUQBHAHEAbQA2ADYATQAyAG4AZwA9AD0AIgA+ADwALwBLAEkARAA+ADwASwBJAEQAIABBAEwARwBJAEQAPQAiAEEARQBTAEMAVABSACIAIABDAEgARQBDAEsAUwBVAE0APQAiAE8ARQB1AE0AeQBEAGUAUQAxAHMAOAA9ACIAIABWAEEATABVAEUAPQAiAEkAMABCAHIARABhAEcATgBkAFYANgB2AGEASABYAEYARgBNAFcAYgBZAHcAPQA9ACIAPgA8AC8ASwBJAEQAPgA8AC8ASwBJAEQAUwA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAHQAZQBzAHQALgBwAGwAYQB5AHIAZQBhAGQAeQAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBzAGUAcgB2AGkAYwBlAC8AcgBpAGcAaAB0AHMAbQBhAG4AYQBnAGUAcgAuAGEAcwBtAHgAPwBjAGYAZwA9ACgAawBpAGQAOgBUAEIAZwB2ADYASwBvADYAdABGAGUAcwA2AEcAQgByAFgAagAvAHIAcgBRAD0APQAsAGMAbwBuAHQAZQBuAHQAawBlAHkAOgB3AHYAcgAyAGIAaQBoAFMAegBFAHgASwBkAFIAOABLAEsAcABRAGYAMgB3AD0APQApACwAKABrAGkAZAA6AHgAcwA5ADcAQwBLAFgAMwBGAGwAZQA0AFEARwBxAG0ANgA2AE0AMgBuAGcAPQA9ACwAYwBvAG4AdABlAG4AdABrAGUAeQA6AGcAbwBIAE8AagBiAGsASQBOAHAAZgBaAGQAdwAyAEgAMgA1AFkAbwBOAFEAPQA9ACkALAAoAGsAaQBkADoASQAwAEIAcgBEAGEARwBOAGQAVgA2AHYAYQBIAFgARgBGAE0AVwBiAFkAdwA9AD0ALABjAG8AbgB0AGUAbgB0AGsAZQB5ADoAVwBDADEAcgBjAFcARQBiADQARQB5AEkANABpAHEAcQBFAEUAUQBlAEwAQQA9AD0AKQA8AC8ATABBAF8AVQBSAEwAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==").unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    assert!(boxes.contains(&boxes[0]));
}


#[test]
fn test_parsing_nagra() {
    let boxes = from_base64("AAAAinBzc2gAAAAArbQcJC2/Sm2Vi0RXwNJ7lQAAAGpleUpqYjI1MFpXNTBTV1FpT2lKSGIyNWxJR2x1SUhSb1pTQjNhVzVrSWl3aWEyVjVTV1FpT2lJNU1XRXhaVFEwTnkwMk9EUmlMVFJoWTJVdFlqWmpaUzAwTURFeE5qQm1NRGRtTURFaWZR")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("NAGRA> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.system_id, NAGRA_SYSTEM_ID);
    if let PsshData::Nagra(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, "Gone in the wind");
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAjHBzc2gAAAAArbQcJC2/Sm2Vi0RXwNJ7lQAAAGxleUpqYjI1MFpXNTBTV1FpT2lJeE56RXhNVEU1TmpNM1h6RTJOREl3SWl3aWEyVjVTV1FpT2lJd05qSXlNamt5WkMxaVltTXhMVFF6WVRRdE9XVmxOQzFpTmpJNFl6ZzJZVFprTm1VaWZRPT0=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("NAGRA> {pssh:?}");
    assert_eq!(pssh.system_id, NAGRA_SYSTEM_ID);
    if let PsshData::Nagra(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, "1711119637_16420");
        assert_eq!(pd.key_id, "0622292d-bbc1-43a4-9ee4-b628c86a6d6e");
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAjHBzc2gAAAAArbQcJC2/Sm2Vi0RXwNJ7lQAAAGxleUpqYjI1MFpXNTBTV1FpT2lJeE9URXdOREV5TURZeVh6RTJOREl3SWl3aWEyVjVTV1FpT2lKaE4yTmxPVE5sT0MwMk9HVXhMVFE0TnpjdFltUmhOQzB6WlROaU9XWmpaV05sTnpFaWZRPT0=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("NAGRA> {pssh:?}");
    assert_eq!(pssh.system_id, NAGRA_SYSTEM_ID);
    if let PsshData::Nagra(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, "1910412062_16420");
    }

    let boxes = from_base64("AAAAgnBzc2gAAAAArbQcJC2/Sm2Vi0RXwNJ7lQAAAGJleUpqYjI1MFpXNTBTV1FpT2lKbU5EUXpZamRoTkdJd0lpd2lhMlY1U1dRaU9pSmlabUZsT0dOak5pMDRORFkyTFdGbFlXSXRNR0U0WXkxbU5EUXpZamRoTkdJd01EZ2lmUQ==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("NAGRA> {pssh:?}");
    assert_eq!(pssh.system_id, NAGRA_SYSTEM_ID);
    if let PsshData::Nagra(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, "f443b7a4b0");
        assert_eq!(pd.key_id, "bfae8cc6-8466-aeab-0a8c-f443b7a4b008");
    }

    let boxes = from_base64("AAAAg3Bzc2gAAAAArbQcJC2/Sm2Vi0RXwNJ7lQAAAGNleUpqYjI1MFpXNTBTV1FpT2lKRFQwNVVSVTVVU1VReU1DSXNJbXRsZVVsa0lqb2lZVFkyT1dVeFpHVXROekl3TnkwMFpURmpMVGsxT0dNdFlXUTVOamxpT0RNNE5qQmlJbjA=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("NAGRA> {pssh:?}");
    assert_eq!(pssh.system_id, NAGRA_SYSTEM_ID);
    if let PsshData::Nagra(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, "CONTENTID20");
    }

    let boxes = from_base64("AAAAfHBzc2gAAAAArbQcJC2/Sm2Vi0RXwNJ7lQAAAFxleUpqYjI1MFpXNTBTV1FpT2lKdVpYY3hNRFlpTENKclpYbEpaQ0k2SWpFeE1UQXdNVEV4TFRJeU1qSXRNek16TXkwME5EUTBMVEF3TURBd01EQXdNREF3TmlKOQ==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("NAGRA> {pssh:?}");
    assert_eq!(pssh.system_id, NAGRA_SYSTEM_ID);
    if let PsshData::Nagra(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, "new106");
        assert_eq!(pd.key_id, "11100111-2222-3333-4444-000000000006");
    }

    let boxes = from_base64("AAAAfHBzc2gAAAAArbQcJC2/Sm2Vi0RXwNJ7lQAAAFxleUpqYjI1MFpXNTBTV1FpT2lKRFZWQXdNRE1pTENKclpYbEpaQ0k2SW1Ga01UVXlOMk0wTFdKalpUUXROR1ZpTXkwNE5qQTFMVE5pTVRka016aGxObVF4TnlKOQ==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("NAGRA> {pssh:?}");
    assert_eq!(pssh.system_id, NAGRA_SYSTEM_ID);
    if let PsshData::Nagra(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, "CUP003");
        assert_eq!(pd.key_id, "ad1527c4-bce4-4eb3-8605-3b17d38e6d17");
    }

    let boxes = from_base64("AAAAfHBzc2gAAAAArbQcJC2/Sm2Vi0RXwNJ7lQAAAFxleUpqYjI1MFpXNTBTV1FpT2lKRFZWQXdNVEVpTENKclpYbEpaQ0k2SWpsaU56QmpNV05tTFdFd01ERXROR0poWXkwNE1UUmxMVE01TmprMU5XVm1OR000WmlKOQ==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, NAGRA_SYSTEM_ID);
    if let PsshData::Nagra(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, "CUP011");
        assert_eq!(pd.key_id, "9b70c1cf-a001-4bac-814e-396955ef4c8f");
    }
}


#[test]
fn test_parsing_marlin() {
    let boxes = from_base64("AAAAKHBzc2gAAAAAXmKa9TjaQGOJd5f/vZkC1AAAAAgAAAAIbWFybA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("MARLIN> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.system_id, MARLIN_SYSTEM_ID);
    assert!(boxes[0] == boxes[0]);
    assert!(boxes.contains(&boxes[0]));
}


#[test]
fn test_parsing_irdeto() {
    let boxes = from_base64("AAABcnBzc2gAAAAAgKa+fhRITDeecNWuvgTI0gAAAVIBAAABTQABAUk8Q0NBUk1IRUFERVIgdmVyc2lvbj0iMS4wIj4KICA8REFUQT4KICAgIDxQUk9URUNUSU5GTz4KICAgICAgPEtJRCB2YWx1ZT0iWXpZNFkyRmxZbVl0TmpZNE5DMWhZbUZsTFRCaE9HTXRaalEwTTJJM1lUUmlNREE0Ii8+CiAgICA8L1BST1RFQ1RJTkZPPgogICAgPENDSVNfVVJMPmh0dHA6Ly8xNzIuMTYuOC4xMDc8L0NDSVNfVVJMPgogICAgPEVDTT5nVUJIUXdBQS8wZ0VLb0ErQWdQbmdrSkpRM0xTYUoyMlg0ZDFmU0wzS2NnWHpIZU1xelF0YzBmUkFCMVRJNGErNkhhWmhpRjk3VEkwSlBRZitNTnZLbVRTclV5ZWlUMllHNWc9PC9FQ00+CiAgPC9EQVRBPgo8L0NDQVJNSEVBREVSPg==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("Irdeto> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.system_id, IRDETO_SYSTEM_ID);
    if let PsshData::Irdeto(ref pd) = pssh.pssh_data {
        assert!(pd.xml.contains("<CCARMHEADER"));
        assert!(pd.xml.contains("YzY4Y2FlYmYtNjY4NC1hYmFlLTBhOGMtZjQ0M2I3YTRiMDA4"));
        assert!(pd.xml.contains("CCIS_URL"));
    }
    assert!(boxes.contains(&boxes[0]));
}

// DRM system from Huawei, which shares the same systemid as ChinaDRM.
#[test]
fn test_parsing_wiseplay() {
    let boxes = from_base64("AAAAn3Bzc2gAAAAAPV5tNZuaQei4Q908bnLELAAAAH97InZlcnNpb24iOiJWMS4wIiwia2lkcyI6WyJtWkNpWm9ENVBnbWxXcjgxcHcyQVpRPT0iXSwiY29udGVudElEIjoiZXlKaGMzTmxkRWxrSWpvaWRIWnRaV1JwWVMweU1ETXhPRFUyTnlKOSIsImVuc2NoZW1hIjoiY2VuYyJ9")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("WisePlay> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.system_id, WISEPLAY_SYSTEM_ID);
    if let PsshData::WisePlay(ref pd) = pssh.pssh_data {
        assert!(pd.json["enschema"].eq("cenc"));
        assert!(pd.json["contentID"].eq("eyJhc3NldElkIjoidHZtZWRpYS0yMDMxODU2NyJ9"));
        assert!(pd.json["kids"][0].eq("mZCiZoD5PgmlWr81pw2AZQ=="));
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAn3Bzc2gAAAAAPV5tNZuaQei4Q908bnLELAAAAH97InZlcnNpb24iOiJWMS4wIiwia2lkcyI6WyJiSUVCeXBtV05DaTlZSTIwbnBFdjBnPT0iXSwiY29udGVudElEIjoiZXlKaGMzTmxkRWxrSWpvaWRIWnRaV1JwWVMweU1EVXlNamN3TWlKOSIsImVuc2NoZW1hIjoiY2JjcyJ9")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("WisePlay> {pssh:?}");
    assert_eq!(pssh.system_id, WISEPLAY_SYSTEM_ID);
    if let PsshData::WisePlay(ref pd) = pssh.pssh_data {
        assert!(pd.json["enschema"].eq("cbcs"));
        assert!(pd.json["contentID"].eq("eyJhc3NldElkIjoidHZtZWRpYS0yMDUyMjcwMiJ9"));
        assert!(pd.json["kids"][0].eq("bIEBypmWNCi9YI20npEv0g=="));
    }
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAAq3Bzc2gAAAAAPV5tNZuaQei4Q908bnLELAAAAIt7ImNvbnRlbnRJRCI6IlpETnNUamhvWlVSVVZtMDJNVFJFY1d0S2NWcDBaejA5IiwiZW5zY2hlbWEiOiJDRU5DIiwia2lkcyI6WyJOemMzT1RSa1pqSXhOemd6TkdRMU9XSmhaRGM0TUdWaE9UQTVZVGs1WWpZPSJdLCJ2ZXJzaW9uIjoiVjEuMCJ9")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("WisePlay> {pssh:?}");
    assert_eq!(pssh.system_id, WISEPLAY_SYSTEM_ID);
    if let PsshData::WisePlay(ref pd) = pssh.pssh_data {
        assert!(pd.json["enschema"].eq("CENC"));
        assert!(pd.json["contentID"].eq("ZDNsTjhoZURUVm02MTREcWtKcVp0Zz09"));
        assert!(pd.json["kids"][0].eq("Nzc3OTRkZjIxNzgzNGQ1OWJhZDc4MGVhOTA5YTk5YjY="));
    }
    assert!(boxes.contains(&boxes[0]));
}

#[test]
fn test_parsing_commonenc_v1() {
    let boxes = from_base64("AAAANHBzc2gBAAAAEHfv7MCyTQKs4zweUuL7SwAAAAEJIv31avpBoIhhXRvITKxgAAAAAA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("COMMON> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.version, 1);
    assert_eq!(pssh.system_id, COMMON_SYSTEM_ID);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("0922fdf56afa41a088615d1bc84cac60").unwrap());
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAANHBzc2gBAAAAEHfv7MCyTQKs4zweUuL7SwAAAAFDIVZ4EjQSNBI0EjQSNBI0AAAAAA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.version, 1);
    println!("COMMON> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.system_id, COMMON_SYSTEM_ID);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("43215678123412341234123412341234").unwrap());
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAANHBzc2gBAAAAEHfv7MCyTQKs4zweUuL7SwAAAAEGIiktu8FDpJ7ktijIam1uAAAAAA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("COMMON> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.system_id, COMMON_SYSTEM_ID);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("0622292dbbc143a49ee4b628c86a6d6e").unwrap());
    assert!(boxes.contains(&boxes[0]));

    let boxes = from_base64("AAAANHBzc2gBAAAAEHfv7MCyTQKs4zweUuL7SwAAAAE41YGuY8VM3LXTahVdy94cAAAAAA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("COMMON> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.system_id, COMMON_SYSTEM_ID);
    assert_eq!(pssh.key_ids[0], DRMKeyId::try_from("38d581ae63c54cdcb5d36a155dcbde1c").unwrap());

    let boxes = from_base64("AAABJHBzc2gBAAAAEHfv7MCyTQKs4zweUuL7SwAAABAFo6CpeLw88YLCEc18zO70BaOgqXi8PPGCwhHNfMzu9QWjoKl4vDzxgsIRzXzM7vYFo6CpeLw88YLCEc18zO73AAAAAAAAAAAAAAAAAAAAAHsidiI6IjIiLCJmaWQiOiJoXzExMDBoemdkMDAxNDZhIiwicGwiOiJleUp3YVdRaU9pSm9YekV4TURCb2VtZGtNREF4TkRaaElpd2laR1ZzYVhabGNubGZkSGx3WlNJNkluTjBJbjAiLCJzdmlkIjoiZGlnaXRhbCIsImNzIjoiZGQxMTQzMjcyOTU4ODZmNjYxYmYxZDBiNWExZjE3YjQifQAAAAAAAAAAAAAAAAAAAAAAAA==")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.version, 1);
    assert_eq!(pssh.system_id, COMMON_SYSTEM_ID);
    assert_eq!(pssh.key_ids.len(), 16);

    let boxes = from_base64("AAAA5HBzc2gBAAAAEHfv7MCyTQKs4zweUuL7SwAAAAxxLsEybBg/rpWDi6wC+5ejAAAAAAAAAAAAAAAAAAAAAHsidiI6IjIiLCJmaWQiOiJodW50YTAwMzA1Iiwic3ZpZCI6ImRpZ2l0YWwiLCJwbCI6ImV5SndhV1FpT2lKb2RXNTBZVEF3TXpBMUlpd2laR1ZzYVhabGNubGZkSGx3WlNJNkluTjBJbjAiLCJjcyI6IjhiYjMyNDMzZTYxYzQ4OGRiZDc2YmFlZjkwNWYwMWRhIn0AAAAAAAAAAAAAAAAAAAAA")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    assert_eq!(pssh.version, 1);
    assert_eq!(pssh.system_id, COMMON_SYSTEM_ID);
    assert_eq!(pssh.key_ids.len(), 12);
    let wanted = DRMKeyId::try_from("68756e74613030333035222c22737669").unwrap();
    assert!(pssh.key_ids.iter()
            .find(|k| **k == wanted)
            .is_some());
}

// The FairPlay DRM system has very little public information available nor sample PSSH boxes. This
// is a sample PSSH from the FairPlay PSSH system as used by Netflix.
#[test]
fn test_parsing_fairplay() {
    let boxes = from_hex("00000020707373680000000029701FE43CC74A348C5BAE90C7439A4700000000")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh = &boxes[0];
    println!("FairPlay> {pssh:?}");
    pprint(&pssh);
    assert_eq!(pssh.version, 0);
    assert_eq!(pssh.system_id, FAIRPLAYNFLX_SYSTEM_ID);
    assert!(boxes.contains(&boxes[0]));
}


#[test]
fn test_parsing_multisystem() {
    let boxes = from_base64("AAAAQHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACAiGFlPVVRVQkU6NTM5ZjEyZjRhM2IzMTczYkjj3JWbBgAAAvRwc3NoAAAAAJoE8HmYQEKGq5LmW+CIX5UAAALU1AIAAAEAAQDKAjwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADAALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsARQBZAEwARQBOAD4AMQA2ADwALwBLAEUAWQBMAEUATgA+ADwAQQBMAEcASQBEAD4AQQBFAFMAQwBUAFIAPAAvAEEATABHAEkARAA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAD4AdwB3AFQASwA0AFMAbwBkAEYAVgArAFgAMQAwAHYAYQBjAFMAQgBFAEcAUQA9AD0APAAvAEsASQBEAD4APABDAEgARQBDAEsAUwBVAE0APgA1AGsASgArADcANgBDAHEAYQB0AHMAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APABMAEEAXwBVAFIATAA+AGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHkAbwB1AHQAdQBiAGUALgBjAG8AbQAvAGEAcABpAC8AZAByAG0ALwBwAGwAYQB5AHIAZQBhAGQAeQA/AHMAbwB1AHIAYwBlAD0AWQBPAFUAVABVAEIARQAmAGEAbQBwADsAdgBpAGQAZQBvAF8AaQBkAD0ANQAzADkAZgAxADIAZgA0AGEAMwBiADMAMQA3ADMAYgA8AC8ATABBAF8AVQBSAEwAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    assert_eq!(boxes.len(), 2);
    let wv_pssh = &boxes[0];
    assert_eq!(wv_pssh.system_id, WIDEVINE_SYSTEM_ID);
    if let PsshData::Widevine(ref pd) = wv_pssh.pssh_data {
        assert_eq!(pd.content_id, Some(hex::decode("594f55545542453a35333966313266346133623331373362").unwrap()));
    }
    assert!(boxes.contains(&boxes[0]));
    assert!(boxes.contains(&boxes[1]));

    let pr_pssh = &boxes[1];
    assert_eq!(pr_pssh.system_id, PLAYREADY_SYSTEM_ID);
    if let PsshData::PlayReady(ref pd) = pr_pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("5kJ+76Cqats=").unwrap()));
        assert!(wrmh.data.la_url.as_ref().is_some_and(|s| s.contains("youtube.com")));
    }

    let boxes = from_base64("AAAAQHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACAiGFlPVVRVQkU6NTM5ZjEyZjRhM2IzMTczYkjj3JWbBgAAAvRwc3NoAAAAAJoE8HmYQEKGq5LmW+CIX5UAAALU1AIAAAEAAQDKAjwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADAALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsARQBZAEwARQBOAD4AMQA2ADwALwBLAEUAWQBMAEUATgA+ADwAQQBMAEcASQBEAD4AQQBFAFMAQwBUAFIAPAAvAEEATABHAEkARAA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAD4AdwB3AFQASwA0AFMAbwBkAEYAVgArAFgAMQAwAHYAYQBjAFMAQgBFAEcAUQA9AD0APAAvAEsASQBEAD4APABDAEgARQBDAEsAUwBVAE0APgA1AGsASgArADcANgBDAHEAYQB0AHMAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APABMAEEAXwBVAFIATAA+AGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHkAbwB1AHQAdQBiAGUALgBjAG8AbQAvAGEAcABpAC8AZAByAG0ALwBwAGwAYQB5AHIAZQBhAGQAeQA/AHMAbwB1AHIAYwBlAD0AWQBPAFUAVABVAEIARQAmAGEAbQBwADsAdgBpAGQAZQBvAF8AaQBkAD0ANQAzADkAZgAxADIAZgA0AGEAMwBiADMAMQA3ADMAYgA8AC8ATABBAF8AVQBSAEwAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    assert_eq!(boxes.len(), 2);
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    println!("PLAYREADY-v1(1)> {pssh:?}");
    assert_eq!(pssh.flags, 0);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, Some(hex::decode("594f55545542453a35333966313266346133623331373362").unwrap()));
    }
    let pssh = &boxes[1];
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    println!("PLAYREADY-v1(2)> {pssh:?}");
    assert_eq!(pssh.flags, 0);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("5kJ+76Cqats=").unwrap()));
        assert!(wrmh.data.la_url.as_ref().is_some_and(|s| s.contains("youtube.com")));
    }
}


#[test]
fn test_parsing_concatenated_erroneous() {
    assert!(from_base64("AAAAQHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACAiGFlPVVRVQkU6ZDVlMjNlZDMzMWZjNjFiN0jj3JWbBgAAAvRwc3NoAAAAAJoE8HmYQEKGq5LmW+CIX5UAAALU1AIAAAEAAQDKAjwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADAALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsARQBZAEwARQBOAD4AMQA2ADwALwBLAEUAWQBMAEUATgA+ADwAQQBMAEcASQBEAD4AQQBFAFMAQwBUAFIAPAAvAEEATABHAEkARAA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAD4AaQBRAGMAeAA3AHEAMQBoAEIARgBTAG4AUQBjAHQAOAB2AEwAKwBPAFYAQQA9AD0APAAvAEsASQBEAD4APABDAEgARQBDAEsAUwBVAE0APgBoAHUAZgBGAFMAdQBSAFoAQgBqAHMAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APABMAEEAXwBVAFIATAA+AGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHkAbwB1AHQAdQBiAGUALgBjAG8AbQAvAGEAcABpAC8AZAByAG0ALwBwAGwAYQB5AHIAZQBhAGQAeQA/AHMAbwB1AHIAYwBlAD0AWQBPAFUAVABVAEIARQAmAGEAbQBwADsAdgBpAGQAZQBvAF8AaQBkAD0AZAA1AGUAMgAzAGUAZAAzADMAMQBmAGMANgAxAGIANwA8AC8ATABBA").is_err());
}


#[test]
fn test_parsing_erroneous() {
    assert!(from_base64("bXlfcHNzaA==").is_err());
}


#[test]
fn test_find_iter() {
    let init = reqwest::blocking::get("https://m.dtv.fi/dash/dasherh264v3/drm/a1/i.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let positions: Vec<usize> = find_iter(&init).collect();
    for pos in positions {
        let boxes = from_buffer(&init[pos..]).unwrap();
        println!("Find> at octet {pos} found pssh {boxes:?}");
    }

    let buf = BASE64_STANDARD.decode("AAAAQHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACAiGFlPVVRVQkU6NTM5ZjEyZjRhM2IzMTczYkjj3JWbBgAAAvRwc3NoAAAAAJoE8HmYQEKGq5LmW+CIX5UAAALU1AIAAAEAAQDKAjwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADAALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsARQBZAEwARQBOAD4AMQA2ADwALwBLAEUAWQBMAEUATgA+ADwAQQBMAEcASQBEAD4AQQBFAFMAQwBUAFIAPAAvAEEATABHAEkARAA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAD4AdwB3AFQASwA0AFMAbwBkAEYAVgArAFgAMQAwAHYAYQBjAFMAQgBFAEcAUQA9AD0APAAvAEsASQBEAD4APABDAEgARQBDAEsAUwBVAE0APgA1AGsASgArADcANgBDAHEAYQB0AHMAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APABMAEEAXwBVAFIATAA+AGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHkAbwB1AHQAdQBiAGUALgBjAG8AbQAvAGEAcABpAC8AZAByAG0ALwBwAGwAYQB5AHIAZQBhAGQAeQA/AHMAbwB1AHIAYwBlAD0AWQBPAFUAVABVAEIARQAmAGEAbQBwADsAdgBpAGQAZQBvAF8AaQBkAD0ANQAzADkAZgAxADIAZgA0AGEAMwBiADMAMQA3ADMAYgA8AC8ATABBAF8AVQBSAEwAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    let positions: Vec<usize> = find_iter(&buf).collect();
    println!("Find> positions {positions:?}");
    assert_eq!(positions.len(), 2);
    let boxes = from_bytes(&buf).unwrap();
    let pssh = &boxes[0];
    assert_eq!(pssh.system_id, WIDEVINE_SYSTEM_ID);
    println!("PLAYREADY-v1(1)> {pssh:?}");
    assert_eq!(pssh.flags, 0);
    if let PsshData::Widevine(ref pd) = pssh.pssh_data {
        assert_eq!(pd.content_id, Some(hex::decode("594f55545542453a35333966313266346133623331373362").unwrap()));
    }
    let pssh = &boxes[1];
    assert_eq!(pssh.system_id, PLAYREADY_SYSTEM_ID);
    println!("PLAYREADY-v1(2)> {pssh:?}");
    assert_eq!(pssh.flags, 0);
    if let PsshData::PlayReady(ref pd) = pssh.pssh_data {
        let wrmh = &pd.record[0].record_value;
        assert_eq!(wrmh.data.checksum, Some(BASE64_STANDARD.decode("5kJ+76Cqats=").unwrap()));
        assert!(wrmh.data.la_url.as_ref().is_some_and(|s| s.contains("youtube.com")));
    }
    assert!(boxes.contains(&boxes[0]));
    assert!(boxes.contains(&boxes[1]));
}


#[test]
fn test_partialeq() {
    let boxes = from_base64("AAAAR3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACcIARIBMBoNd2lkZXZpbmVfdGVzdCIKMjAxNV90ZWFycyoFQVVESU8=")
        .unwrap();
    assert_eq!(boxes.len(), 1);
    let pssh1 = boxes[0].clone();
    let mut pssh2 = pssh1.clone();
    assert!(pssh1 == pssh2);
    assert!(boxes.contains(&pssh1));
    if let PsshData::Widevine(ref mut pd) = pssh2.pssh_data {
        pd.provider = Some(String::from("new_provider"));
    }
    assert!(pssh1 != pssh2);
    assert!(!boxes.contains(&pssh2));
}
