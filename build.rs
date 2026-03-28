//! Compile the protobuf headers for WidevinePsshData
//
// There are three supported methods to compile the .proto interface definition files, selected
// using the following crate options:
//
// - `protox`: use the `protox` crate (implemented fully in Rust)
//
// - `vendored-protoc`: use the `protobuf-src` crate to build a vendored version of the protobuf
//   compiler at compile time and use that. This requires a sufficiently recent C++ compiler and cmake
//   support, and tends to be rather unreliable (in particular, the abseil-cpp component of protobuf
//   often causes build failures on any mildly unusual platform).
//
// - no features: use the `protoc` binary natively installed on the build host


use std::io::Result;

fn main() -> Result<()> {
    #[cfg(feature = "vendored-protoc")]
    std::env::set_var("PROTOC", protobuf_src::protoc());

    let mut config = prost_build::Config::new();
    // We want to provide our own Debug fmt implementation for this type
    config.skip_debug(["WidevinePsshData"])
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .extern_path(
             ".google.protobuf.Any",
             "::prost_wkt_types::Any")
        .extern_path(
            ".google.protobuf.Timestamp",
            "::prost_wkt_types::Timestamp")
        .extern_path(
            ".google.protobuf.Value",
            "::prost_wkt_types::Value");

    #[cfg(feature = "protox")]
    {
        let file_descriptors = protox::compile(["src/widevine_pssh_data.proto"], &["src/"])
            .expect("compiling protobuf with protox crate");
        config.compile_fds(file_descriptors)
            .expect("compiling protox-generated protobuf descriptors");
    }
    #[cfg(not(feature = "protox"))]
    config.compile_protos(&["src/widevine_pssh_data.proto"], &["src/"])?;

    Ok(())
}
