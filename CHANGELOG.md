# Changelog

## [0.1.4] - 2024-02-21

- Add support for the FairPlay DRM system, and in particular the mystery FairPlay PSSH boxes that
  are reported to be used by Netflix for DASH-like streaming.

- Add support for UUID-style strings in `DRMKeyId::try_from(&str)`.


## [0.1.3] - 2024-02-14

- New example `fetch-pssh-data`, a commandline utility which fetches an initialization segment from
  a DASH stream that uses ContentProtection (DRM) and displays the content of any DRM initialization
  data (PSSH boxes) it may contain.

- Release builds optimize for space.


## [0.1.2] - 2024-02-05

- Add feature `vendored-protoc` to pull in the `protobuf-src` crate. With this feature, which
  defaults to being enabled, the protobuf compiler is built from C sources at build time, instead of
  using a locally installed protoc compiler. This is intended to make it easier for users of our
  crate (it turns out to be very difficult to ensure that protoc is installed on build machines when
  using Github actions such as the upload-rust-binary-action, which depends on cross-rs running in a
  container).


## [0.1.1] - 2024-02-04

- Add a compact `to_string()` method on `PsshBox` and `PsshBoxVec`.

- Add a `to_string()` method on `DRMSystemId` and `DRMKeyId`, in addition to the more basic Debug
  printer.

- Add a `to_json()` method on `WidevinePsshData`.
