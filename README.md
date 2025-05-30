# pssh-box

This crate defines Rust data structures allowing you to store, parse and serialize Protection System
Specific Header (**PSSH**) boxes, which provide data for the initialization of a Digital Rights
Management (DRM) system.

[![Crates.io](https://img.shields.io/crates/v/pssh-box)](https://crates.io/crates/pssh-box)
[![Released API docs](https://docs.rs/pssh-box/badge.svg)](https://docs.rs/pssh-box/)
[![CI](https://github.com/emarsden/pssh-box-rs/workflows/build/badge.svg)](https://github.com/emarsden/pssh-box-rs/actions/workflows/ci.yml)
[![Dependency status](https://deps.rs/repo/github/emarsden/pssh-box-rs/status.svg)](https://deps.rs/repo/github/emarsden/pssh-box-rs)
[![Recent crates.io downloads](https://img.shields.io/crates/dr/pssh-box?label=crates.io%20recent%20downloads)](https://img.shields.io/crates/dr/pssh-box?label=crates.io%20recent%20downloads)
[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)


PSSH boxes are used:

- in an MP4 box of type `pssh` in an MP4 fragment (CMAF/MP4/ISOBMFF containers)

- in a `<cenc:pssh>` element in a DASH MPD manifest

- in DRM initialization data passed to the Encrypted Media Extension of a web browser

- in an EXT-X-SESSION-KEY field of an m3u8 playlist.

A PSSH box includes information for a single DRM system. This library supports the PSSH data formats
for the following DRM systems:

- Widevine, owned by Google, widely used for DASH streaming
- PlayReady, owned by Microsoft, widely used for DASH streaming
- WisePlay, owned by Huawei
- Irdeto
- Marlin
- Nagra
- The unofficial variant of Apple FairPlay that is used for DASH-like streaming by Netflix
- Common Encryption

PSSH boxes contain (depending on the DRM system) information on the key_ID for which to obtain a
content key, the encryption scheme used (e.g. cenc, cbc1, cens or cbcs), the URL of the licence
server, and checksum data.


## Features

This crate provides the following functionality:

- **parse PSSH boxes** from binary buffers (as found in an MP4 fragment), or from a base64-encoded
  string (as found in a `<cenc:pssh>` element in an MPD manifest), or from a hex-encoded string.
   
- **scan** a binary buffer for the location of a PSSH box, using the function `find_iter`.

- pretty print a PSSH, using function `pprint`.

- serialize a PSSH box to binary, base64 or hexadecimal (base 16) formats, using methods
  `to_bytes()`, `to_base64()` and `to_hex()` on a `PsshBox` struct.

A **commandline utility** for decoding PSSH boxes and PSSH data in various formats is available in
`example/decode-pssh.rs`. 

If you wish to use this functionality in web applications, you may be interested in the
[pssh-box-wasm](https://github.com/emarsden/pssh-box-wasm/) library, which provides functionality
for using this code as WebAssembly.


## Usage

```
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
```


## Build

The protoc compiler is used during the build process to translate the protobuf interface definition
for Widevine PSSH data into Rust structs. This happens in the `build.rs` file. The default
configuration uses a **prebuilt protobuf compiler**, which must be locally installed (from Debian
package `protobuf-compiler`, for example).

As an alternative if the `vendored-protoc` feature is enabled, the `protobuf-src` crate is used to
build a vendored version of the protoc compiler. This requires a working C++ compiler and cmake
support, and tends to be rather unreliable (in particular, the abseil-cpp component of protobuf
often causes build failures on any mildly unusual platform). To build on Windows, the simplest
solution seems to be the UCRT64 environment of [MSYS2](https://www.msys2.org/); see our GitHub
continuous integration workflow for one recipe that works.


## License

This project is licensed under the MIT license. For more information, see the `LICENSE` file.
