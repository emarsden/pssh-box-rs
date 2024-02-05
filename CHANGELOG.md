# Changelog

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
