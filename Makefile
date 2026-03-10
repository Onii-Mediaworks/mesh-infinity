SHELL := bash

ROOT_DIR      := $(CURDIR)
FRONTEND_DIR  := $(ROOT_DIR)/frontend
PLATFORMS_DIR := $(ROOT_DIR)/platforms
BUILD_DIR     := $(ROOT_DIR)/build
APPLE_PROJECT := $(PLATFORMS_DIR)/apple/Runner.xcodeproj

# App identity comes from the Rust project (Cargo.toml / pubspec.yaml).
APP_NAME         := $(shell awk -F'"' '/^name/{print $$2; exit}' Cargo.toml | sed 's/[-[:space:]]//g')
APP_VERSION      := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | cut -d+ -f1)
APP_BUILD_NUMBER := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | awk -F+ '{print ($$2 == "" ? "1" : $$2)}')

.PHONY: clean macos-debug macos-release

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -rf "$(BUILD_DIR)/intermediates"

# ── macOS ─────────────────────────────────────────────────────────────────────
#
# Layout under build/intermediates/macos/<profile>/:
#   src/       — working copy of frontend/ (Flutter writes its build/ here)
#   frontend/  — final XCFrameworks (flutter build --output target)
#   backend/   — Rust lipo output
#
# Shared:
#   build/intermediates/macos/backend/   — cargo target dir (manages triples internally)
#   build/intermediates/macos/xcode/     — xcodebuild derived data
#   build/intermediates/apple/flutter/   — xcconfig (path baked into Xcode project)
#   build/output/macos/<profile>/        — final DMG

macos-debug macos-release: macos-%:
	@set -euo pipefail; \
	profile="$*"; \
	cfg="Debug"; [[ "$$profile" == "release" ]] && cfg="Release"; \
	cargo_flags=""; [[ "$$profile" == "release" ]] && cargo_flags="--release"; \
	rust_subdir="debug"; [[ "$$profile" == "release" ]] && rust_subdir="release"; \
	src_dir="$(BUILD_DIR)/intermediates/macos/$$profile/src"; \
	fw_dir="$(BUILD_DIR)/intermediates/macos/$$profile/frontend"; \
	rust_out="$(BUILD_DIR)/intermediates/macos/$$profile/backend"; \
	rust_target="$(BUILD_DIR)/intermediates/macos/backend"; \
	\
	mkdir -p \
	  "$$src_dir" \
	  "$$fw_dir" \
	  "$$rust_out" \
	  "$$rust_target" \
	  "$(BUILD_DIR)/intermediates/macos/xcode" \
	  "$(BUILD_DIR)/intermediates/apple/flutter" \
	  "$(BUILD_DIR)/output/macos/$$profile"; \
	\
	rsync -a --delete \
	  --exclude=build/ \
	  --exclude=.dart_tool/ \
	  --exclude=.flutter-plugins \
	  --exclude=.flutter-plugins-dependencies \
	  "$(FRONTEND_DIR)/" "$$src_dir/"; \
	mkdir -p "$$src_dir/macos"; \
	\
	flutter config --enable-macos-desktop; \
	( cd "$$src_dir" && flutter pub get ); \
	flutter_mode_flags="--$$profile"; \
	[[ "$$profile" != "debug"   ]] && flutter_mode_flags="$$flutter_mode_flags --no-debug"; \
	[[ "$$profile" != "profile" ]] && flutter_mode_flags="$$flutter_mode_flags --no-profile"; \
	[[ "$$profile" != "release" ]] && flutter_mode_flags="$$flutter_mode_flags --no-release"; \
	( cd "$$src_dir" && flutter build macos-framework $$flutter_mode_flags \
	    --output "$$fw_dir" ); \
	\
	flutter_root="$$(flutter --version --machine | jq -r .flutterRoot)"; \
	printf "%s\n" \
	  "FLUTTER_ROOT=$$flutter_root" \
	  "FLUTTER_APPLICATION_PATH=$$src_dir" \
	  "FLUTTER_FRAMEWORK_BASE=$(BUILD_DIR)/intermediates/macos" \
	  "FLUTTER_TARGET=lib/main.dart" \
	  "FLUTTER_BUILD_DIR=build" \
	  "FLUTTER_BUILD_NAME=$(APP_VERSION)" \
	  "FLUTTER_BUILD_NUMBER=$(APP_BUILD_NUMBER)" \
	  > "$(BUILD_DIR)/intermediates/apple/flutter/Flutter-Generated.xcconfig"; \
	printf "%s\n" \
	  "$$fw_dir/FlutterMacOS.xcframework/macos-arm64_x86_64/FlutterMacOS.framework/FlutterMacOS" \
	  "$$fw_dir/App.xcframework/macos-arm64_x86_64/App.framework/App" \
	  > "$(BUILD_DIR)/intermediates/apple/flutter/FlutterInputs.xcfilelist"; \
	printf "%s\n" \
	  "$(BUILD_DIR)/intermediates/macos/xcode/Build/Products/$$cfg/Runner.app/Contents/Frameworks/FlutterMacOS.framework/FlutterMacOS" \
	  "$(BUILD_DIR)/intermediates/macos/xcode/Build/Products/$$cfg/Runner.app/Contents/Frameworks/App.framework/App" \
	  > "$(BUILD_DIR)/intermediates/apple/flutter/FlutterOutputs.xcfilelist"; \
	\
	CARGO_TARGET_DIR="$$rust_target" \
	  cargo build -p mesh-infinity --target aarch64-apple-darwin $$cargo_flags; \
	CARGO_TARGET_DIR="$$rust_target" \
	  cargo build -p mesh-infinity --target x86_64-apple-darwin $$cargo_flags; \
	lipo -create \
	  "$$rust_target/aarch64-apple-darwin/$$rust_subdir/libmesh_infinity.dylib" \
	  "$$rust_target/x86_64-apple-darwin/$$rust_subdir/libmesh_infinity.dylib" \
	  -output "$$rust_out/libmesh_infinity.dylib"; \
	\
	xcodebuild \
	  -project "$(APPLE_PROJECT)" \
	  -scheme Runner \
	  -configuration "$$cfg" \
	  -derivedDataPath "$(BUILD_DIR)/intermediates/macos/xcode" \
	  ARCHS="arm64 x86_64" \
	  ONLY_ACTIVE_ARCH=NO \
	  CODE_SIGNING_ALLOWED=NO \
	  CODE_SIGNING_REQUIRED=NO \
	  CODE_SIGN_IDENTITY="" \
	  build; \
	\
	app_src="$(BUILD_DIR)/intermediates/macos/xcode/Build/Products/$$cfg/$(APP_NAME).app"; \
	dmg_stage="$(BUILD_DIR)/intermediates/macos/$$profile/dmg-stage"; \
	rm -rf "$$dmg_stage"; \
	mkdir "$$dmg_stage"; \
	cp -R "$$app_src" "$$dmg_stage/"; \
	ln -s /Applications "$$dmg_stage/Applications"; \
	hdiutil create \
	  -volname "$(APP_NAME)" \
	  -srcfolder "$$dmg_stage" \
	  -ov -format UDZO \
	  "$(BUILD_DIR)/output/macos/$$profile/$(APP_NAME)-$(APP_VERSION)-$$profile.dmg"; \
	rm -rf "$$dmg_stage"; \
	echo "Output: $(BUILD_DIR)/output/macos/$$profile/$(APP_NAME)-$(APP_VERSION)-$$profile.dmg"
