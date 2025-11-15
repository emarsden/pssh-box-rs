//! Tests for finding PSSH box in binary buffers

use std::env;
use std::io::Cursor;
use std::fs::File;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use test_log::test;
use pssh_box::{from_bytes, from_buffer, find_iter, find_boxes_buffer, find_boxes_stream, pprint};
use pssh_box::{PsshBox, PsshData};
use pssh_box::{WIDEVINE_SYSTEM_ID, PLAYREADY_SYSTEM_ID, COMMON_SYSTEM_ID};


#[test]
fn test_find_iter() {
    let init = reqwest::blocking::get("https://bitmovin-a.akamaihd.net/content/art-of-motion_drm/video/180_250000/cenc_dash/init.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let positions: Vec<usize> = find_iter(&init).collect();
    assert!(!positions.is_empty());
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
fn test_find_boxes_buffer() {
    let init = reqwest::blocking::get("https://bitmovin-a.akamaihd.net/content/art-of-motion_drm/video/180_250000/cenc_dash/init.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let boxes: Vec<PsshBox> = find_boxes_buffer(&init)
        .collect();
    assert!(boxes.len() > 0);
    for bx in boxes {
        println!("find_boxes_buffer: found box {bx:?}");
    }

    let init = reqwest::blocking::get("https://github.com/abema/go-mp4/raw/88b57925242fd634eea92da8a24e78d11bee030a/testdata/sample_init.encv.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let boxes: Vec<PsshBox> = find_boxes_buffer(&init)
        .collect();
    assert!(boxes.len() == 1);
    for bx in boxes {
        println!("find_boxes_stream: found box {bx:?}");
    }

    // https://mpeggroup.github.io/FileFormatConformance/files/published/isobmff/18_pssh_v2.mp4
    //
    // This wierd test file contains two PSSH boxes that we don't currently detect. One is a
    // PlayReady box which seems to have an invalid header length (MP4Box.js is able to parse it,
    // but it's perhaps implementing less error checking than this library). The second uses a
    // "GPAC" SystemID which we don't currently recognize and which doesn't seem to be officially
    // recognized.
    let init = reqwest::blocking::get("https://github.com/dukesook/FileFormatConformance/raw/refs/heads/main/data/file_features/published/isobmff/18_pssh_v2.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let boxes: Vec<PsshBox> = find_boxes_buffer(&init)
        .collect();
    assert!(boxes.is_empty());

    let buf = BASE64_STANDARD.decode("AAAAQHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACAiGFlPVVRVQkU6NTM5ZjEyZjRhM2IzMTczYkjj3JWbBgAAAvRwc3NoAAAAAJoE8HmYQEKGq5LmW+CIX5UAAALU1AIAAAEAAQDKAjwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADAALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsARQBZAEwARQBOAD4AMQA2ADwALwBLAEUAWQBMAEUATgA+ADwAQQBMAEcASQBEAD4AQQBFAFMAQwBUAFIAPAAvAEEATABHAEkARAA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAD4AdwB3AFQASwA0AFMAbwBkAEYAVgArAFgAMQAwAHYAYQBjAFMAQgBFAEcAUQA9AD0APAAvAEsASQBEAD4APABDAEgARQBDAEsAUwBVAE0APgA1AGsASgArADcANgBDAHEAYQB0AHMAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APABMAEEAXwBVAFIATAA+AGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHkAbwB1AHQAdQBiAGUALgBjAG8AbQAvAGEAcABpAC8AZAByAG0ALwBwAGwAYQB5AHIAZQBhAGQAeQA/AHMAbwB1AHIAYwBlAD0AWQBPAFUAVABVAEIARQAmAGEAbQBwADsAdgBpAGQAZQBvAF8AaQBkAD0ANQAzADkAZgAxADIAZgA0AGEAMwBiADMAMQA3ADMAYgA8AC8ATABBAF8AVQBSAEwAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    let boxes: Vec<PsshBox> = find_boxes_buffer(&buf)
        .collect();
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
    assert!(boxes.contains(&boxes[0]));
    assert!(boxes.contains(&boxes[1]));
}


#[test]
fn test_find_boxes_stream() {
    let init = reqwest::blocking::get("https://bitmovin-a.akamaihd.net/content/art-of-motion_drm/video/180_250000/cenc_dash/init.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let stream = Cursor::new(init.clone());
    let boxes: Vec<PsshBox> = find_boxes_stream(stream)
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() > 0);
    for bx in boxes {
        println!("find_boxes_stream: found box {bx:?}");
    }

    let init = reqwest::blocking::get("https://github.com/abema/go-mp4/raw/88b57925242fd634eea92da8a24e78d11bee030a/testdata/sample_init.encv.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let stream = Cursor::new(init.clone());
    let boxes: Vec<PsshBox> = find_boxes_stream(stream)
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() == 1);
    for bx in boxes {
        println!("find_boxes_stream: found box {bx:?}");
    }

    // Test fragment published at https://learn.microsoft.com/en-us/playready/advanced/testcontent/playready-2x-test-content
    let init = reqwest::blocking::get("https://test.playready.microsoft.com/media/profficialsite/tearsofsteel_4k.ism/QualityLevels(128003)/Fragments(aac_UND_2_128=i,format=mpd-time-csf)")
        .unwrap()
        .bytes()
        .unwrap();
    let boxes: Vec<PsshBox> = find_boxes_stream(Cursor::new(init.clone()))
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() == 1);

    let init = reqwest::blocking::get("https://cdn.class101.net/videos/447d9e6d-3dae-4d3b-b7e1-c1a3f541168e/cmaf/video/avc1/1/init.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let boxes: Vec<PsshBox> = find_boxes_stream(Cursor::new(init.clone()))
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() == 3);


    // https://mpeggroup.github.io/FileFormatConformance/files/published/isobmff/18_pssh_v2.mp4
    //
    // This wierd test file contains two PSSH boxes that we don't currently detect. One is a
    // PlayReady box which seems to have an invalid header length (MP4Box.js is able to parse it,
    // but it's perhaps implementing less error checking than this library). The second uses a
    // "GPAC" SystemID which we don't currently recognize and which doesn't seem to be officially
    // recognized.
    let init = reqwest::blocking::get("https://github.com/dukesook/FileFormatConformance/raw/refs/heads/main/data/file_features/published/isobmff/18_pssh_v2.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let stream = Cursor::new(init.clone());
    let boxes: Vec<PsshBox> = find_boxes_stream(stream)
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.is_empty());

    let buf = BASE64_STANDARD.decode("AAAAQHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACAiGFlPVVRVQkU6NTM5ZjEyZjRhM2IzMTczYkjj3JWbBgAAAvRwc3NoAAAAAJoE8HmYQEKGq5LmW+CIX5UAAALU1AIAAAEAAQDKAjwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADAALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsARQBZAEwARQBOAD4AMQA2ADwALwBLAEUAWQBMAEUATgA+ADwAQQBMAEcASQBEAD4AQQBFAFMAQwBUAFIAPAAvAEEATABHAEkARAA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAD4AdwB3AFQASwA0AFMAbwBkAEYAVgArAFgAMQAwAHYAYQBjAFMAQgBFAEcAUQA9AD0APAAvAEsASQBEAD4APABDAEgARQBDAEsAUwBVAE0APgA1AGsASgArADcANgBDAHEAYQB0AHMAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APABMAEEAXwBVAFIATAA+AGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHkAbwB1AHQAdQBiAGUALgBjAG8AbQAvAGEAcABpAC8AZAByAG0ALwBwAGwAYQB5AHIAZQBhAGQAeQA/AHMAbwB1AHIAYwBlAD0AWQBPAFUAVABVAEIARQAmAGEAbQBwADsAdgBpAGQAZQBvAF8AaQBkAD0ANQAzADkAZgAxADIAZgA0AGEAMwBiADMAMQA3ADMAYgA8AC8ATABBAF8AVQBSAEwAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    let stream = Cursor::new(buf.clone());
    let boxes: Vec<PsshBox> = find_boxes_stream(stream)
        .map(|bx| bx.unwrap())
        .collect();
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
    assert!(boxes.contains(&boxes[0]));
    assert!(boxes.contains(&boxes[1]));
}



#[test]
fn test_find_boxes_stream_large() {
    if env::var("CI").is_ok() {
        return;
    }

    // This test content published at https://learn.microsoft.com/en-us/playready/advanced/testcontent/playready-3x-test-content
    let octets = reqwest::blocking::get("https://test.playready.microsoft.com/media/profficialsite/tearsofsteel_1080p_60s_24fps.6000kbps.1920x1080.h264-8b.2ch.128kbps.aac.avsep.cenc.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let stream = Cursor::new(octets.clone());
    let boxes: Vec<PsshBox> = find_boxes_stream(stream)
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() == 1);
    assert_eq!(boxes[0].system_id, PLAYREADY_SYSTEM_ID);

    let init = reqwest::blocking::get("https://cdn.bitmovin.com/content/assets/art-of-motion_drm/video/1080_4800000/cenc_dash/init.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let stream = Cursor::new(init.clone());
    let boxes: Vec<PsshBox> = find_boxes_stream(stream)
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() == 2);


    // From https://github.com/chromium/chromium/tree/master/media/test/data
    let init = reqwest::blocking::get("https://github.com/chromium/chromium/raw/refs/heads/master/media/test/data/bear-1280x720-a_frag-cenc.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let stream = Cursor::new(init.clone());
    let boxes: Vec<PsshBox> = find_boxes_stream(stream)
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() == 3);

    let init = reqwest::blocking::get("https://github.com/chromium/chromium/raw/refs/heads/master/media/test/data/bear-640x360-v_frag-cenc-key_rotation.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let boxes: Vec<PsshBox> = find_boxes_stream(Cursor::new(init.clone()))
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() == 18);

    let init = reqwest::blocking::get("https://raw.githubusercontent.com/chromium/chromium/refs/heads/master/media/test/data/bear-640x360-v_frag-cbcs.mp4")
        .unwrap()
        .bytes()
        .unwrap();
    let boxes: Vec<PsshBox> = find_boxes_stream(Cursor::new(init.clone()))
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() == 2);

    let init = reqwest::blocking::get("https://github.com/chromium/chromium/raw/refs/heads/main/media/test/data/bear-320x240-v-vp9_profile2_subsample_cenc-v.mp4")
                                                .unwrap()
        .bytes()
        .unwrap();
    let boxes: Vec<PsshBox> = find_boxes_stream(Cursor::new(init.clone()))
        .map(|bx| bx.unwrap())
        .collect();
    assert!(boxes.len() == 2);
    assert_eq!(boxes[0].system_id, COMMON_SYSTEM_ID);
    assert_eq!(boxes[1].system_id, WIDEVINE_SYSTEM_ID);

}


#[ignore]
#[test]
fn test_find_boxes_stream_dcv() {
    // A large test DMM DCV file. This test is disabled because we don't know of a source of redistributable DMM files.
    let path = "/tmp/test.dcv";
    let dcv = File::open(path).expect("opening test DCV file");
    let boxes: Vec<PsshBox> = find_boxes_stream(dcv)
        .map(|bx| bx.unwrap())
        .collect();
    for bx in boxes {
        pprint(&bx);
    }
}


// Test that find_iter doesn't panic with corrupted size field
#[test]
fn test_find_iter_with_corrupted_size() {
    let mut buffer = Vec::new();

    // Size field (4 bytes) - set to a very large value that exceeds buffer length
    buffer.extend_from_slice(&u32::to_be_bytes(0xFFFFFFFF));
    buffer.extend_from_slice(b"pssh");
    buffer.extend_from_slice(&[0u8; 100]);

    // This should not panic - it should simply filter out the invalid box
    let positions: Vec<usize> = find_iter(&buffer).collect();
    assert_eq!(positions.len(), 0);

    // Test with a size that's larger than buffer but not maximum
    let mut buffer2 = Vec::new();
    buffer2.extend_from_slice(&u32::to_be_bytes(1000)); // Size larger than actual buffer
    buffer2.extend_from_slice(b"pssh");
    buffer2.extend_from_slice(&[0u8; 100]);

    let positions2: Vec<usize> = find_iter(&buffer2).collect();
    assert_eq!(positions2.len(), 0);
}


// Test streaming function with valid PSSH boxes
#[test]
fn test_find_boxes_streaming() {
    let buf = BASE64_STANDARD.decode("AAAAQHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACAiGFlPVVRVQkU6NTM5ZjEyZjRhM2IzMTczYkjj3JWbBgAAAvRwc3NoAAAAAJoE8HmYQEKGq5LmW+CIX5UAAALU1AIAAAEAAQDKAjwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADAALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsARQBZAEwARQBOAD4AMQA2ADwALwBLAEUAWQBMAEUATgA+ADwAQQBMAEcASQBEAD4AQQBFAFMAQwBUAFIAPAAvAEEATABHAEkARAA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAD4AdwB3AFQASwA0AFMAbwBkAEYAVgArAFgAMQAwAHYAYQBjAFMAQgBFAEcAUQA9AD0APAAvAEsASQBEAD4APABDAEgARQBDAEsAUwBVAE0APgA1AGsASgArADcANgBDAHEAYQB0AHMAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APABMAEEAXwBVAFIATAA+AGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHkAbwB1AHQAdQBiAGUALgBjAG8AbQAvAGEAcABpAC8AZAByAG0ALwBwAGwAYQB5AHIAZQBhAGQAeQA/AHMAbwB1AHIAYwBlAD0AWQBPAFUAVABVAEIARQAmAGEAbQBwADsAdgBpAGQAZQBvAF8AaQBkAD0ANQAzADkAZgAxADIAZgA0AGEAMwBiADMAMQA3ADMAYgA8AC8ATABBAF8AVQBSAEwAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==")
        .unwrap();
    let reader = Cursor::new(&buf);
    let boxes: Vec<PsshBox> = find_boxes_stream(reader)
        .map(|bx| bx.unwrap())
        .collect();
    assert_eq!(boxes.len(), 2);
    assert_eq!(boxes[0].system_id, WIDEVINE_SYSTEM_ID);
    assert_eq!(boxes[1].system_id, PLAYREADY_SYSTEM_ID);

    // Test with corrupted size that exceeds buffer
    let mut corrupted_buf = Vec::new();
    corrupted_buf.extend_from_slice(&u32::to_be_bytes(0xFFFFFFFF));
    corrupted_buf.extend_from_slice(b"pssh");
    corrupted_buf.extend_from_slice(&[0u8; 100]);
    let reader2 = Cursor::new(&corrupted_buf);
    let boxes2: Vec<PsshBox> = find_boxes_stream(reader2)
        .map(|bx| bx.unwrap())
        .collect();
    assert_eq!(boxes2.len(), 0);
}


#[test]
fn test_no_stack_overflow_with_large_input() {
    // Create a large buffer to test that we don't get stack overflow
    let mut data = Vec::new();
    let pssh_bytes = BASE64_STANDARD.decode("AAAAQHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACAiGFlPVVRVQkU6NTM5ZjEyZjRhM2IzMTczYkjj3JWbBg==").unwrap();
    data.extend_from_slice(&pssh_bytes);

    // Add 5MB of zeros to force multiple iterations through the read buffer
    data.extend_from_slice(&vec![0u8; 5 * 1024 * 1024]);
    let stream = Cursor::new(data);

    // This should complete without stack overflow
    let boxes: Vec<_> = find_boxes_stream(stream)
        .collect::<Vec<_>>();
    assert!(boxes.len() > 0, "Should find at least one PSSH box");
}

#[test]
fn test_multiple_iterations_no_stack_overflow() {
    // Test that we can process multiple MB of data without stack overflow
    let mut data = Vec::new();

    // Create 10MB of data with no PSSH boxes to force many iterations
    data.extend_from_slice(&vec![0xFFu8; 10 * 1024 * 1024]);
    let stream = Cursor::new(data);
    let boxes: Vec<_> = find_boxes_stream(stream)
        .collect::<Vec<_>>();
    assert_eq!(boxes.len(), 0, "Should not find any PSSH boxes in random data");
}
