//! Decode a PSSH provided in Base64 or hex format on the commandline
//
// The utility can be used to parse a single PSSH box or multiple concatenated PSSH boxes, or Widevine or Playread PSSHData. The input
// can be encoded in hex or in base64.
//
// To run this from the checked out source of the pssh-box crate:
//
//    cargo run --example decode-pssh -- "AAAAOnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABoIARIQt1vS7XqCQEOkj9mf8WoEESIENDc2Nw=="
//
// Alternative test using shaka-packager (via docker container) to parse a PSSH box:
//
//    podman run --rm docker.io/google/shaka-packager:latest pssh-box.py --from-base64 <base64>
//
// and to parse only pssh data:
//
//   podman run --rm docker.io/google/shaka-packager:latest pssh-box.py --system-id edef8ba979d64acea3c827dcd51d21ed --pssh-data <base64>
//


use std::io::Cursor;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use anyhow::{Result, Context};
use clap::{Arg, ArgAction};
use pssh_box::{from_base64, from_hex, pprint, PsshData};
use pssh_box::widevine::WidevinePsshData;
use prost::Message;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::prelude::*;
use tracing::Level;


fn main() -> Result<()> {
    // Logs of level >= INFO go to stdout, otherwise (warnings and errors) to stderr.
    let stderr = std::io::stderr.with_max_level(Level::WARN);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .map_writer(move |w| stderr.or_else(w))
        .compact()
        .with_target(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .expect("initializing logging");
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    tracing::trace!("Initialized");
    
    let clap = clap::Command::new("decode-pssh")
        .about("Parse DRM initialization data (a PSSH box).")
        .version(clap::crate_version!())
        .arg(Arg::new("hex")
             .long("hex")
             .num_args(0)
             .action(ArgAction::SetTrue)
             .help("Decode from hexadecimal (Base16) format"))
        .arg(Arg::new("base64")
             .long("base64")
             .num_args(0)
             .action(ArgAction::SetTrue)
             .help("Decode from Base64 format"))
        .arg(Arg::new("parse-widevine-data")
             .long("parse-widevine-data")
             .num_args(0)
             .action(ArgAction::SetTrue)
             .help("Decode Widevine PSSH data only"))
        .arg(Arg::new("parse-playready-data")
             .long("parse-playready-data")
             .num_args(0)
             .action(ArgAction::SetTrue)
             .help("Decode PlayReady PSSH data only"))
        .arg(Arg::new("pssh")
             .value_name("PSSH")
             .required(true)
             .num_args(1)
             .index(1)
             .help("The PSSH box to decode."));
    let matches = clap.get_matches();
    let data = matches.get_one::<String>("pssh").unwrap();
    if matches.get_flag("parse-widevine-data") {
        let buf = BASE64_STANDARD.decode(data)
            .context("decoding base64")?;
        let pssh_data = WidevinePsshData::decode(Cursor::new(buf))
            .context("parsing Widevine PSSH data")?;
        let wvpssh = PsshData::Widevine(pssh_data.clone());
        println!("{wvpssh}");
        return Ok(());
    }
    if matches.get_flag("parse-playready-data") {
        let buf = BASE64_STANDARD.decode(data)
            .context("decoding base64")?;
        let pssh_data = pssh_box::playready::parse_pssh_data(&buf)
            .context("parsing PlayReady PSSH data")?;
        println!("PlayReady PSSH data: {pssh_data:?}");
        return Ok(());
    }
    let boxes = if matches.get_flag("hex") {
        from_hex(data)
            .context("parsing the PSSH as hex")?
    } else {
        from_base64(data)
            .context("parsing the PSSH as base64")?
    };
    if boxes.len() > 1 {
        println!("Binary data contains {} PSSH boxes", boxes.len());
    }
    for bx in boxes {
        pprint(&bx);
    }
    Ok(())
}

