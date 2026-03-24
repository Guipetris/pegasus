#!/bin/bash -eu

cd $SRC/pegasus/fuzz

# Build all fuzz targets with cargo-fuzz / libfuzzer
cargo +nightly fuzz build

# Copy built fuzz targets to $OUT
for target in fuzz_envelope_deser fuzz_certification_profile fuzz_extract_package_path; do
    cp ../target/x86_64-unknown-linux-gnu/release/$target $OUT/ 2>/dev/null || \
    cp ./target/x86_64-unknown-linux-gnu/release/$target $OUT/ 2>/dev/null || true
done
