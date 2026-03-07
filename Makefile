SHELL := /bin/bash

ROOT_DIR              := $(CURDIR)
FRONTEND_DIR          := $(ROOT_DIR)/frontend
PLATFORMS_DIR         := $(ROOT_DIR)/platforms
BUILD_DIR             := $(ROOT_DIR)/build
FLUTTER_INTERMEDIATE_DIR := $(BUILD_DIR)/intermediates/flutter
RUST_INTERMEDIATE_DIR    := $(BUILD_DIR)/intermediates/rust
APPLE_PROJECT         := $(PLATFORMS_DIR)/apple/Runner.xcodeproj
APP_VERSION           := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | cut -d+ -f1)
APP_BUILD_NUMBER      := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | awk -F+ '{print ($$2 == "" ? "1" : $$2)}')

OS       ?=
PROFILE  ?= release
UNSIGNED ?= 1

.PHONY: help guard-os guard-profile setup-build clean \
        build build-debug build-release build-both \
        android android-release ios ios-both \
        macos macos-both linux linux-release windows windows-release

help:
	@echo "Mesh Infinity build (GNU make)"
	@echo ""
	@echo "Usage:"
	@echo "  make build OS=<platform> [PROFILE=debug|release] [UNSIGNED=1|0]"
	@echo "  make build-debug    OS=<platform>"
	@echo "  make build-release  OS=<platform>"
	@echo "  make build-both     OS=<platform>"
	@echo ""
	@echo "Convenience targets:"
	@echo "  android / android-release"
	@echo "  ios / ios-both"
	@echo "  macos / macos-both"
	@echo "  linux / linux-release"
	@echo "  windows / windows-release"
	@echo ""
	@echo "Platforms: android  ios  macos  linux  windows"
	@echo ""
	@echo "Android requires cargo-ndk: cargo install cargo-ndk --locked"

# ── Guards ────────────────────────────────────────────────────────────────────

guard-os:
	@if [[ -z "$(OS)" ]]; then \
	  echo "ERROR: OS is required (android|ios|macos|linux|windows)"; exit 1; \
	fi; \
	IFS=',' read -ra _oses <<< "$(OS)"; \
	for _os in "$${_oses[@]}"; do \
	  _os="$$(echo "$$_os" | tr -d '[:space:]')"; \
	  if [[ "$$_os" != "android" && "$$_os" != "ios" && "$$_os" != "macos" && \
	        "$$_os" != "linux"   && "$$_os" != "windows" ]]; then \
	    echo "ERROR: unknown platform '$$_os' — must be android|ios|macos|linux|windows"; exit 1; \
	  fi; \
	done

guard-profile:
	@if [[ "$(PROFILE)" != "debug" && "$(PROFILE)" != "release" ]]; then \
	  echo "ERROR: PROFILE must be 'debug' or 'release' (got '$(PROFILE)')"; exit 1; \
	fi

# ── Setup / Clean ─────────────────────────────────────────────────────────────

setup-build:
	@mkdir -p "$(BUILD_DIR)/output" \
	           "$(FLUTTER_INTERMEDIATE_DIR)" \
	           "$(RUST_INTERMEDIATE_DIR)" \
	           "$(BUILD_DIR)/logs"

clean:
	rm -rf "$(BUILD_DIR)"

# ── Main build target ─────────────────────────────────────────────────────────

build: guard-os guard-profile setup-build
	@set -euo pipefail; \
	\
	IFS=',' read -ra _oses <<< "$(OS)"; \
	if [[ "$${#_oses[@]}" -gt 1 ]]; then \
	  for _os in "$${_oses[@]}"; do \
	    _os="$$(echo "$$_os" | tr -d '[:space:]')"; \
	    $(MAKE) build OS="$$_os" PROFILE="$(PROFILE)" UNSIGNED="$(UNSIGNED)"; \
	  done; \
	  exit 0; \
	fi; \
	\
	rustup_cargo="$$(rustup which cargo 2>/dev/null || command -v cargo)"; \
	rustup_rustc="$$(rustup which rustc  2>/dev/null || command -v rustc)"; \
	cargo_flags=""; \
	flutter_flags="--debug"; \
	rust_subdir="debug"; \
	if [[ "$(PROFILE)" == "release" ]]; then \
	  cargo_flags="--release"; \
	  flutter_flags="--release"; \
	  rust_subdir="release"; \
	fi; \
	\
	if [[ "$(OS)" == "ios" || "$(OS)" == "macos" ]]; then \
	  if [[ -f "$(PLATFORMS_DIR)/apple/policy.env" ]]; then \
	    source "$(PLATFORMS_DIR)/apple/policy.env"; \
	  fi; \
	  ephemeral_dir="$(BUILD_DIR)/intermediates/apple/flutter"; \
	  mkdir -p "$$ephemeral_dir"; \
	  if [[ ! -f "$$ephemeral_dir/Flutter-Generated.xcconfig" ]]; then \
	    flutter_root="$$(flutter --version --machine \
	      | ruby -rjson -e 'puts JSON.parse(STDIN.read)["flutterRoot"]')"; \
	    printf '%s\n' \
	      "FLUTTER_ROOT=$$flutter_root" \
	      "FLUTTER_APPLICATION_PATH=$(FRONTEND_DIR)" \
	      "COCOAPODS_PARALLEL_CODE_SIGN=true" \
	      "FLUTTER_TARGET=lib/main.dart" \
	      "FLUTTER_BUILD_DIR=build" \
	      "FLUTTER_BUILD_NAME=$(APP_VERSION)" \
	      "FLUTTER_BUILD_NUMBER=$(APP_BUILD_NUMBER)" \
	      "DART_DEFINES=" \
	      "DART_OBFUSCATION=false" \
	      "TRACK_WIDGET_CREATION=true" \
	      "TREE_SHAKE_ICONS=false" \
	      "PACKAGE_CONFIG=$(FRONTEND_DIR)/.dart_tool/package_config.json" \
	      > "$$ephemeral_dir/Flutter-Generated.xcconfig"; \
	  fi; \
	  : > "$$ephemeral_dir/FlutterInputs.xcfilelist"; \
	  : > "$$ephemeral_dir/FlutterOutputs.xcfilelist"; \
	  touch "$$ephemeral_dir/tripwire"; \
	  cd "$(FRONTEND_DIR)"; flutter pub get; cd "$(ROOT_DIR)"; \
	fi; \
	\
	if [[ "$(OS)" == "ios" ]]; then \
	  RUSTC="$$rustup_rustc" \
	  IPHONEOS_DEPLOYMENT_TARGET="$${APPLE_IOS_DEPLOYMENT_TARGET:-13.0}" \
	  CARGO_TARGET_DIR="$(RUST_INTERMEDIATE_DIR)" \
	    "$$rustup_cargo" build -p mesh-infinity --target aarch64-apple-ios $$cargo_flags; \
	  RUSTC="$$rustup_rustc" \
	  IPHONEOS_DEPLOYMENT_TARGET="$${APPLE_IOS_DEPLOYMENT_TARGET:-13.0}" \
	  CARGO_TARGET_DIR="$(RUST_INTERMEDIATE_DIR)" \
	    "$$rustup_cargo" build -p mesh-infinity --target x86_64-apple-ios $$cargo_flags || true; \
	elif [[ "$(OS)" != "android" ]]; then \
	  RUSTC="$$rustup_rustc" CARGO_TARGET_DIR="$(RUST_INTERMEDIATE_DIR)" \
	    "$$rustup_cargo" build -p mesh-infinity $$cargo_flags; \
	fi; \
	\
	if [[ "$(UNSIGNED)" == "1" ]]; then export MESH_UNSIGNED=1; fi; \
	out_ts="$$(date +%Y%m%d-%H%M%S)"; \
	out_dir="$(BUILD_DIR)/output/$$out_ts/$(OS)"; \
	mkdir -p "$$out_dir"; \
	\
	case "$(OS)" in \
	  linux) \
	    cd "$(FRONTEND_DIR)"; \
	    flutter config --enable-linux-desktop; \
	    flutter pub get; \
	    flutter build linux $$flutter_flags; \
	    bundle_dir="$(FRONTEND_DIR)/build/linux/x64/$$rust_subdir/bundle"; \
	    mkdir -p "$$bundle_dir/lib"; \
	    cp "$(RUST_INTERMEDIATE_DIR)/$$rust_subdir/libmesh_infinity.so" \
	       "$$bundle_dir/lib/"; \
	    tar czf "$$out_dir/meshinfinity-$(APP_VERSION)-$(PROFILE).tar.gz" \
	      -C "$$bundle_dir" .; \
	    echo "Output: $$out_dir/meshinfinity-$(APP_VERSION)-$(PROFILE).tar.gz" ;; \
	  windows) \
	    cd "$(FRONTEND_DIR)"; \
	    flutter config --enable-windows-desktop; \
	    flutter pub get; \
	    flutter build windows $$flutter_flags; \
	    win_subdir="Debug"; \
	    [[ "$(PROFILE)" == "release" ]] && win_subdir="Release"; \
	    runner_dir="$(FRONTEND_DIR)/build/windows/x64/runner/$$win_subdir"; \
	    cp "$(RUST_INTERMEDIATE_DIR)/$$rust_subdir/mesh_infinity.dll" \
	       "$$runner_dir/"; \
	    dst_dir="$$out_dir/meshinfinity-$(APP_VERSION)-$(PROFILE)"; \
	    cp -r "$$runner_dir" "$$dst_dir"; \
	    echo "Output: $$dst_dir" ;; \
	  macos) \
	    cfg_name="Debug"; \
	    [[ "$(PROFILE)" == "release" ]] && cfg_name="Release"; \
	    xcodebuild \
	      -project "$(APPLE_PROJECT)" \
	      -scheme Runner \
	      -configuration "$$cfg_name" \
	      -derivedDataPath "$(BUILD_DIR)/intermediates/apple/macos" \
	      CODE_SIGNING_ALLOWED=NO \
	      CODE_SIGNING_REQUIRED=NO \
	      CODE_SIGN_IDENTITY="" \
	      build; \
	    app_src="$(BUILD_DIR)/intermediates/apple/macos/Build/Products/$$cfg_name/meshinfinity.app"; \
	    app_dst="$$out_dir/meshinfinity-$(APP_VERSION)-$(PROFILE).app"; \
	    rm -rf "$$app_dst"; \
	    cp -R "$$app_src" "$$app_dst"; \
	    echo "Output: $$app_dst" ;; \
	  ios) \
	    cfg_name="Debug"; \
	    [[ "$(PROFILE)" == "release" ]] && cfg_name="Release"; \
	    export_method="debugging"; \
	    [[ "$(PROFILE)" == "release" && "$(UNSIGNED)" != "1" ]] && export_method="app-store"; \
	    archive_dir="$(BUILD_DIR)/intermediates/apple/ios"; \
	    archive_path="$$archive_dir/RunnerIOS.xcarchive"; \
	    export_plist="$$archive_dir/ExportOptions-$(PROFILE).plist"; \
	    mkdir -p "$$archive_dir"; \
	    printf '%s\n' \
	      '<?xml version="1.0" encoding="UTF-8"?>' \
	      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
	      '<plist version="1.0"><dict>' \
	      '  <key>method</key>' \
	      "  <string>$$export_method</string>" \
	      '  <key>signingStyle</key><string>automatic</string>' \
	      '  <key>stripSwiftSymbols</key><true/>' \
	      '  <key>compileBitcode</key><false/>' \
	      '</dict></plist>' > "$$export_plist"; \
	    xcodebuild \
	      -project "$(APPLE_PROJECT)" \
	      -scheme RunnerIOS \
	      -configuration "$$cfg_name" \
	      -destination 'generic/platform=iOS' \
	      -archivePath "$$archive_path" \
	      -derivedDataPath "$$archive_dir" \
	      -allowProvisioningUpdates \
	      -allowProvisioningDeviceRegistration \
	      archive; \
	    xcodebuild \
	      -exportArchive \
	      -archivePath "$$archive_path" \
	      -exportPath "$$out_dir" \
	      -exportOptionsPlist "$$export_plist" \
	      -allowProvisioningUpdates; \
	    ipa_src="$$out_dir/MeshInfinity.ipa"; \
	    ipa_dst="$$out_dir/meshinfinity-$(APP_VERSION)-$(PROFILE).ipa"; \
	    [[ -f "$$ipa_src" ]] && mv -f "$$ipa_src" "$$ipa_dst"; \
	    echo "Output: $$ipa_dst" ;; \
	  android) \
	    if ! command -v cargo-ndk &>/dev/null; then \
	      echo "ERROR: cargo-ndk not found — install with: cargo install cargo-ndk --locked"; \
	      exit 1; \
	    fi; \
	    mkdir -p "$(FRONTEND_DIR)/android/app/src/main/jniLibs"; \
	    cargo ndk \
	      -t armeabi-v7a -t arm64-v8a -t x86_64 \
	      -o "$(FRONTEND_DIR)/android/app/src/main/jniLibs" \
	      build -p mesh-infinity $$cargo_flags; \
	    cd "$(FRONTEND_DIR)"; \
	    flutter pub get; \
	    flutter build apk $$flutter_flags; \
	    apk_src="$(FRONTEND_DIR)/build/app/outputs/flutter-apk/app-$(PROFILE).apk"; \
	    cp "$$apk_src" "$$out_dir/meshinfinity-$(APP_VERSION)-$(PROFILE).apk"; \
	    echo "Output: $$out_dir/meshinfinity-$(APP_VERSION)-$(PROFILE).apk" ;; \
	esac

# ── Shorthand build targets ───────────────────────────────────────────────────

build-debug:
	@$(MAKE) build OS="$(OS)" PROFILE=debug UNSIGNED="$(UNSIGNED)"

build-release:
	@$(MAKE) build OS="$(OS)" PROFILE=release UNSIGNED="$(UNSIGNED)"

build-both:
	@for _p in debug release; do \
	  $(MAKE) build OS="$(OS)" PROFILE="$$_p" UNSIGNED="$(UNSIGNED)"; \
	done

# Platform convenience shorthands

android:
	@$(MAKE) build OS=android PROFILE=debug

android-release:
	@$(MAKE) build OS=android PROFILE=release

ios:
	@$(MAKE) build OS=ios PROFILE=debug UNSIGNED=1

ios-both:
	@$(MAKE) build-both OS=ios UNSIGNED=1

macos:
	@$(MAKE) build OS=macos PROFILE=debug UNSIGNED=1

macos-both:
	@$(MAKE) build-both OS=macos UNSIGNED=1

linux:
	@$(MAKE) build OS=linux PROFILE=debug

linux-release:
	@$(MAKE) build OS=linux PROFILE=release

windows:
	@$(MAKE) build OS=windows PROFILE=debug

windows-release:
	@$(MAKE) build OS=windows PROFILE=release
