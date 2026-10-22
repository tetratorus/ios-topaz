#!/bin/sh
# Builds and ad-hoc signs topazd for arm64 iOS 16 with the Xcode 15.4 iPhoneOS SDK.
set -e
cd "$(dirname "$0")"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode-15.4.app/Contents/Developer}"

xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc -O2 \
	-Wall -Wextra -Wno-unused-parameter \
	-framework Foundation -framework MobileCoreServices \
	topazd.m -o topazd
xcrun strip -x topazd
codesign -f -s - -i org.sweet.topazd --entitlements ents.plist topazd
plutil -lint ents.plist org.sweet.topazd.plist

file topazd
xcrun otool -l topazd | grep -A4 LC_BUILD_VERSION
xcrun otool -L topazd
codesign -dv --entitlements - topazd
