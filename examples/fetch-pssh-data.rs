//! Decode PSSH initialization data located in an MP4 container
//
//
// Fetch an initialization segment from a DASH stream that uses ContentProtection (DRM) and display
// the content of any DRM initialization data (PSSH boxes) it may contain.
//
// Initialization data for a DRM system can be included in the DASH MPD manifest (a <cenc:pssh>
// element inside a ContentProtection element) and/or in an MP4 box of type pssh inside the
// initialization segment for a stream. The DASH IF specifications recommend that initialization
// data be included in the MPD manifest, for "operational agility", but some streaming services
// prefer to include it only in the MP4 segments.
//
// This commandline utility will download an initialization segment from an URL specified on the
// commandline. You can use a file:// URL if you have already downloaded the segment (may be useful
// if the web server requires authorization). It will print all PSSH boxes found at the beginning of
// the file.
//
// Implementation detail: in principle, we should decode the fragmented MP4 stream to look for a box
// of type 'pssh'. You can do this using the mp4dump utility. In practice, given the relatively low
// maturity of MP4 decoding crates, it's easier simply to scan the binary for the signature of a
// PSSH box, which is what we do here.
//
// Usage:
//
//     cargo run --example fetch-pssh-data https://m.dtv.fi/dash/dasherh264v3/drm/a1/i.mp4

use std::time::Duration;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;
use anyhow::{Result, Context};
use clap::Arg;
use pssh_box::{find_iter, from_buffer, pprint};


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
    let clap = clap::Command::new("fetch-pssh-data")
        .about("Parse DRM initialization data (a PSSH box) in an MP4 container.")
        .version(clap::crate_version!())
        .arg(Arg::new("url")
             .value_name("URL")
             .required(true)
             .num_args(1)
             .index(1)
             .help("The URL of the MP4 initialization segment."));
    let matches = clap.get_matches();
    let url = matches.get_one::<String>("url").unwrap();
    let client = reqwest::Client::builder()
        .timeout(Duration::new(30, 0))
        .build()
        .context("creating HTTP client")?;
    let req = client.get(url)
        .header("Accept", "video/*");
    if let Ok(mut resp) = req.send().await {
        // We download progressively to avoid filling RAM with a large MP4 file.
        let mut chunk_counter = 0;
        let mut segment_first_bytes = Vec::<u8>::new();
        while let Ok(Some(chunk)) = resp.chunk().await {
            segment_first_bytes.append(&mut chunk.to_vec());
            chunk_counter += 1;
            if chunk_counter > 20 {
                break;
            }
        }
        let positions: Vec<usize> = find_iter(&segment_first_bytes).collect();
        for pos in positions {
            let boxes = from_buffer(&segment_first_bytes[pos..]).unwrap();
            for bx in boxes {
                pprint(&bx);
            }
        }
    }
    Ok(())
}

