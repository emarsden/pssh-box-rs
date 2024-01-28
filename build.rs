// Compile the protobuf headers for WidevinePsshData

use std::io::Result;

fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    // We want to provide our own Debug fmt implementation for this type
    config.skip_debug(["WidevinePsshData"])
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .extern_path(
             ".google.protobuf.Any",
             "::prost_wkt_types::Any"
         )
        .extern_path(
            ".google.protobuf.Timestamp",
            "::prost_wkt_types::Timestamp"
        )
        .extern_path(
            ".google.protobuf.Value",
            "::prost_wkt_types::Value"
        )
        .compile_protos(&["src/widevine_pssh_data.proto"], &["src/"])?;
    Ok(())
}
