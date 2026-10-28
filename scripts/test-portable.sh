#!/bin/bash
set -euo pipefail

TARGET=${1:?Usage: scripts/test-portable.sh RUST-TARGET}

if [[ "$TARGET" == aarch64-pc-windows-msvc ]]; then
  # The native Windows ARM64 test runner uses a smaller default worker stack.
  export RUST_MIN_STACK=16777216
fi

# These tests require pinned Apple SAP images in the developer's private local
# cache. The images are not distributable CI fixtures; run the complete suite
# on a host with the checked cache when validating those guest paths.
asset_tests=(
  store_backend::tests::guest_decodes_json_response_with_foundation_values
  store_backend::tests::loads_bag_once_and_uses_current_purchase_url
  store_backend::tests::malformed_guest_plist_returns_framework_value_instead_of_bridge_failure
  store_download_product::tests::ent_download_request_matches_pinned_store_guest
  store_download_product::tests::volume_request_matches_pinned_store_guest
  store_login::tests::native_login_matches_pinned_guest_request
  store_login::tests::signs_and_saves_login_through_pinned_store_backend
  store_owned::tests::fetches_purchase_history_through_pinned_store_backend
  store_owned::tests::native_purchase_history_matches_pinned_store_requests
  store_purchase::tests::buys_free_app_through_pinned_store_backend
  store_purchase::tests::native_purchase_matches_pinned_store_wire_request
  store_runtime::tests::encodes_free_purchase_with_pinned_apple_code
  store_runtime::tests::executes_free_purchase_with_pinned_apple_code
  store_runtime::tests::executes_signed_authentication_with_pinned_apple_code
  store_runtime::tests::frozen_bag_keeps_binary_data_and_date_objects
  store_runtime::tests::preserves_purchase_failure_response_for_appstore_error_handling
  store_runtime::tests::signed_authentication_follows_pinned_login_redirect
  store_runtime::tests::signed_authentication_rejects_redirect_outside_login_endpoint
  store_runtime::tests::signs_raw_purchase_history_request_with_pinned_apple_code
  store_runtime::tests::swift_continuation_semaphore_and_group_run_pending_http_callbacks
)

skip_args=()
for test_name in "${asset_tests[@]}"; do
  skip_args+=(--skip "$test_name")
done
cargo +stable test --locked --target "$TARGET" --all-targets --quiet -- "${skip_args[@]}"
