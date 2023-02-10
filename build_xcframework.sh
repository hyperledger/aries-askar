#!/bin/sh

set -e

targets=("aarch64-apple-ios" "aarch64-apple-ios-sim" "x86_64-apple-ios")

for target in "${targets[@]}"; do
  rustup target add $target
  cargo build --release --no-default-features --features mobile --target $target
done

lipo -create target/aarch64-apple-ios-sim/release/libaries_askar.a target/x86_64-apple-ios/release/libaries_askar.a -output target/simulator_fat.a

rm -rf target/tmp/include
mkdir -p target/tmp/include
cp include/*.h target/tmp/include
cp include/module.modulemap target/tmp/include

rm -rf target/AskarFramework.xcframework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libaries_askar.a \
  -headers target/tmp/include \
  -library target/simulator_fat.a \
  -headers target/tmp/include \
  -output target/AskarFramework.xcframework

rm target/simulator_fat.a
rm -f target/AskarFramework.xcframework.zip
zip -rq target/AskarFramework.xcframework.zip target/AskarFramework.xcframework
shasum -a 256 target/AskarFramework.xcframework.zip | sed 's/ .*//'
