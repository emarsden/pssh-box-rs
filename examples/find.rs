//! find.rs

// This example illustrates the use of the find_boxes_stream() function, which searches for PSSH
// boxes in a stream of octets, in a lazy manner. It can for example be used to find PSSH boxes in
// an MP4 media file. In theory, we should parse the MP4 container data to identify the MP4 boxes
// which are likely to contain the PSSH data (either a MOOV box or a MOOF box). Here we simply look
// for the fingerprint of a PSSH box in the binary octet stream, and check that the following data
// is indeed a valid PSSH box.


use std::fs::File;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;
use anyhow::{Result};
use clap::Arg;
use pssh_box::{PsshBox, find_boxes_stream};


#[tokio::main]
async fn main() -> Result<()> {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info,reqwest=warn"))
        .unwrap();
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
    let clap = clap::Command::new("find-pssh-boxes")
        .about("Find PSSH boxes in an MP4 container.")
        .version(clap::crate_version!())
        .arg(Arg::new("filename")
             .value_name("FILE")
             .required(true)
             .num_args(1)
             .index(1)
             .help("The name of the file to scan."));
    let matches = clap.get_matches();
    let file = matches.get_one::<String>("filename").unwrap();
    let stream = File::open(file).expect("opening input file");
    let boxes: Vec<PsshBox> = find_boxes_stream(stream)
        .map(|bx| bx.unwrap())
        .collect();
    for bx in boxes {
        println!("PSSH box {bx:?}");
    }
    Ok(())
}
