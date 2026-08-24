#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_ROOT="${NOCTWEAVE_NATIVE_TEST_CACHE_DIR:-$ROOT_DIR/.build-caches/native-app-tests}"
DEVELOPER_ROOT="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
SELECTION="${1:-all}"

mkdir -p "$CACHE_ROOT/clang"

sign_to_run_locally=(
  CODE_SIGNING_ALLOWED=YES
  CODE_SIGNING_REQUIRED=YES
  CODE_SIGN_STYLE=Manual
  CODE_SIGN_IDENTITY=-
  DEVELOPMENT_TEAM=
)

run_relay_tests() {
  local run_id
  run_id="r$(date -u +%Y%m%d%H%M%S)-$$"
  echo "Running the native relay tests with volatile XCTest secrets and test bundle $run_id..."
  env \
    DEVELOPER_DIR="$DEVELOPER_ROOT" \
    CLANG_MODULE_CACHE_PATH="$CACHE_ROOT/clang" \
    xcodebuild \
      -project "$ROOT_DIR/Noctweave Relay/Noctweave Relay.xcodeproj" \
      -scheme "Noctweave Relay" \
      -configuration Debug \
      -destination 'platform=macOS' \
      -derivedDataPath "$CACHE_ROOT/relay" \
      "PRODUCT_BUNDLE_IDENTIFIER=org.noctweave.localtest.\$(TARGET_NAME:rfc1034identifier).$run_id" \
      'SWIFT_ACTIVE_COMPILATION_CONDITIONS=$(inherited) NOCTWEAVE_XCTEST_VOLATILE_KEYCHAIN' \
      "${sign_to_run_locally[@]}" \
      test
}

select_ios_test_device() {
  if [[ -n "${NOCTWEAVE_IOS_TEST_DEVICE_ID:-}" ]]; then
    printf '%s\n' "$NOCTWEAVE_IOS_TEST_DEVICE_ID"
    return
  fi

  local simulator_line simulator_id
  simulator_line="$(xcrun simctl list devices available | awk '/^[[:space:]]+iPhone / { print; exit }')"
  simulator_id="$(sed -E 's/.*\(([0-9A-Fa-f-]{36})\).*/\1/' <<<"$simulator_line")"
  if [[ ! "$simulator_id" =~ ^[0-9A-Fa-f-]{36}$ ]]; then
    echo "No existing iPhone simulator is available." >&2
    echo "Set NOCTWEAVE_IOS_TEST_DEVICE_ID to an existing simulator UUID." >&2
    return 1
  fi
  printf '%s\n' "$simulator_id"
}

run_client_tests() {
  local simulator_id
  simulator_id="$(select_ios_test_device)"
  echo "Running the native client UI tests in existing iPhone simulator $simulator_id..."
  env \
    DEVELOPER_DIR="$DEVELOPER_ROOT" \
    CLANG_MODULE_CACHE_PATH="$CACHE_ROOT/clang" \
    xcodebuild \
      -project "$ROOT_DIR/Noctweave Messaging Client/Noctweave Messaging Client.xcodeproj" \
      -scheme NoctweaveUITests_iOS \
      -configuration Debug \
      -destination "platform=iOS Simulator,id=$simulator_id" \
      -derivedDataPath "$CACHE_ROOT/client-ios" \
      "${sign_to_run_locally[@]}" \
      test
}

case "$SELECTION" in
  all)
    run_relay_tests
    run_client_tests
    ;;
  relay)
    run_relay_tests
    ;;
  client)
    run_client_tests
    ;;
  *)
    echo "Usage: $0 [all|relay|client]" >&2
    exit 64
    ;;
esac

echo "Native app tests complete. No developer signing identity was used."
