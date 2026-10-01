#!/usr/bin/env bash
# Keep build and product-path queries on the same SwiftPM backend. New Xcode
# toolchains default to swiftbuild, but an implicit --show-bin-path can still
# report the older native layout. Older Swift versions keep their default.
NOCTWEAVE_SWIFT_BUILD_FLAGS=(--disable-automatic-resolution)
if [[ "$(swift build --help)" == *swiftbuild* ]]; then
  NOCTWEAVE_SWIFT_BUILD_FLAGS+=(--build-system swiftbuild)
fi
