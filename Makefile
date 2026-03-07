# Use bare 'bash' (resolved via PATH) so this works on Linux, macOS, and
# Windows (Git Bash) without needing an absolute path.
SHELL := bash

ROOT_DIR              := $(CURDIR)
FRONTEND_DIR          := $(ROOT_DIR)/frontend
PLATFORMS_DIR         := $(ROOT_DIR)/platforms
BUILD_DIR             := $(ROOT_DIR)/build
FLUTTER_INTERMEDIATE_DIR := $(BUILD_DIR)/intermediates/flutter
RUST_INTERMEDIATE_DIR    := $(BUILD_DIR)/intermediates/rust
APPLE_PROJECT         := $(PLATFORMS_DIR)/apple/Runner.xcodeproj
# App identity comes from the Rust project — Flutter is just the UI layer.
APP_NAME         := $(shell awk -F'"' '/^name/{print $$2; exit}' Cargo.toml | tr -d '-[:space:]')
APP_VERSION      := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | cut -d+ -f1)
APP_BUILD_NUMBER := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | awk -F+ '{print ($$2 == "" ? "1" : $$2)}')
# Flutter names its Linux runner binary after pubspec `name` — internal detail only.
FLUTTER_RUNNER_BIN := $(shell awk -F': ' '/^name:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | tr -d '[:space:]')

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
	@echo "Linux packages require:"
	@echo "  fpm:          gem install fpm"
	@echo "  .rpm output:  apt install rpm"
	@echo "  .AppImage:    apt install libfuse2 + download appimagetool to PATH"

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
	elif [[ "$(OS)" == "macos" ]]; then \
	  RUSTC="$$rustup_rustc" CARGO_TARGET_DIR="$(RUST_INTERMEDIATE_DIR)" \
	    "$$rustup_cargo" build -p mesh-infinity --target aarch64-apple-darwin $$cargo_flags; \
	  RUSTC="$$rustup_rustc" CARGO_TARGET_DIR="$(RUST_INTERMEDIATE_DIR)" \
	    "$$rustup_cargo" build -p mesh-infinity --target x86_64-apple-darwin $$cargo_flags; \
	  mkdir -p "$(RUST_INTERMEDIATE_DIR)/$$rust_subdir"; \
	  lipo -create \
	    "$(RUST_INTERMEDIATE_DIR)/aarch64-apple-darwin/$$rust_subdir/libmesh_infinity.dylib" \
	    "$(RUST_INTERMEDIATE_DIR)/x86_64-apple-darwin/$$rust_subdir/libmesh_infinity.dylib" \
	    -output "$(RUST_INTERMEDIATE_DIR)/$$rust_subdir/libmesh_infinity.dylib"; \
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
	    if [[ ! -d "$(FRONTEND_DIR)/linux" ]]; then \
	      flutter create --platforms=linux . ; \
	    fi; \
	    flutter pub get; \
	    flutter build linux $$flutter_flags; \
	    bundle_dir="$(FRONTEND_DIR)/build/linux/x64/$$rust_subdir/bundle"; \
	    mkdir -p "$$bundle_dir/lib"; \
	    cp "$(RUST_INTERMEDIATE_DIR)/$$rust_subdir/libmesh_infinity.so" \
	       "$$bundle_dir/lib/"; \
	    tar czf "$$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).tar.gz" \
	      -C "$$bundle_dir" .; \
	    echo "Output: $$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).tar.gz"; \
	    launcher_dir="$(BUILD_DIR)/intermediates/linux-launcher"; \
	    mkdir -p "$$launcher_dir"; \
	    printf '#!/bin/sh\nexec /opt/$(APP_NAME)/$(FLUTTER_RUNNER_BIN) "$$@"\n' \
	      > "$$launcher_dir/$(APP_NAME)"; \
	    chmod +x "$$launcher_dir/$(APP_NAME)"; \
	    rpm_ver="$$(echo '$(APP_VERSION)' | tr '-' '_')"; \
	    fpm -s dir -t deb \
	      -n $(APP_NAME) \
	      -v "$(APP_VERSION)" \
	      --iteration "$(APP_BUILD_NUMBER)" \
	      --architecture amd64 \
	      --description "Decentralised mesh networking" \
	      -p "$$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).deb" \
	      "$$bundle_dir/=/opt/$(APP_NAME)" \
	      "$$launcher_dir/$(APP_NAME)=/usr/bin/$(APP_NAME)"; \
	    echo "Output: $$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).deb"; \
	    fpm -s dir -t rpm \
	      -n $(APP_NAME) \
	      -v "$$rpm_ver" \
	      --iteration "$(APP_BUILD_NUMBER)" \
	      --architecture x86_64 \
	      --description "Decentralised mesh networking" \
	      -p "$$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).rpm" \
	      "$$bundle_dir/=/opt/$(APP_NAME)" \
	      "$$launcher_dir/$(APP_NAME)=/usr/bin/$(APP_NAME)"; \
	    echo "Output: $$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).rpm"; \
	    appdir="$(BUILD_DIR)/intermediates/linux-appdir"; \
	    rm -rf "$$appdir"; \
	    mkdir -p "$$appdir/usr/bin" "$$appdir/usr/lib"; \
	    cp "$$bundle_dir/$(FLUTTER_RUNNER_BIN)" "$$appdir/usr/bin/$(APP_NAME)"; \
	    cp -r "$$bundle_dir/data" "$$appdir/usr/bin/data"; \
	    cp "$$bundle_dir/lib/"*.so "$$appdir/usr/lib/"; \
	    cp "$(PLATFORMS_DIR)/apple/Runner/Assets.xcassets/AppIcon.appiconset/app_icon_256.png" \
	       "$$appdir/$(APP_NAME).png"; \
	    printf '[Desktop Entry]\nName=Mesh Infinity\nExec=$(APP_NAME)\nIcon=$(APP_NAME)\nType=Application\nCategories=Network;\n' \
	      > "$$appdir/$(APP_NAME).desktop"; \
	    printf '#!/bin/sh\nexport LD_LIBRARY_PATH="$$APPDIR/usr/lib:$$LD_LIBRARY_PATH"\nexec "$$APPDIR/usr/bin/$(APP_NAME)" "$$@"\n' \
	      > "$$appdir/AppRun"; \
	    chmod +x "$$appdir/AppRun"; \
	    ARCH=x86_64 appimagetool "$$appdir" \
	      "$$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).AppImage"; \
	    echo "Output: $$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).AppImage" ;; \
	  windows) \
	    cd "$(FRONTEND_DIR)"; \
	    flutter config --enable-windows-desktop; \
	    if [[ ! -d "$(FRONTEND_DIR)/windows" ]]; then \
	      flutter create --platforms=windows . ; \
	    fi; \
	    flutter pub get; \
	    flutter build windows $$flutter_flags; \
	    win_subdir="Debug"; \
	    [[ "$(PROFILE)" == "release" ]] && win_subdir="Release"; \
	    runner_dir="$(FRONTEND_DIR)/build/windows/x64/runner/$$win_subdir"; \
	    cp "$(RUST_INTERMEDIATE_DIR)/$$rust_subdir/mesh_infinity.dll" \
	       "$$runner_dir/"; \
	    dst_dir="$$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE)"; \
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
	      ARCHS="arm64 x86_64" \
	      ONLY_ACTIVE_ARCH=NO \
	      build; \
	    app_src="$(BUILD_DIR)/intermediates/apple/macos/Build/Products/$$cfg_name/$(APP_NAME).app"; \
	    app_dst="$$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).app"; \
	    rm -rf "$$app_dst"; \
	    cp -R "$$app_src" "$$app_dst"; \
	    echo "Output: $$app_dst" ;; \
	  ios) \
	    cfg_name="Debug"; \
	    [[ "$(PROFILE)" == "release" ]] && cfg_name="Release"; \
	    ios_derived="$(BUILD_DIR)/intermediates/apple/ios"; \
	    mkdir -p "$$ios_derived"; \
	    if [[ "$(UNSIGNED)" == "1" ]]; then \
	      xcodebuild \
	        -project "$(APPLE_PROJECT)" \
	        -scheme RunnerIOS \
	        -configuration "$$cfg_name" \
	        -destination 'generic/platform=iOS' \
	        -derivedDataPath "$$ios_derived" \
	        CODE_SIGNING_ALLOWED=NO \
	        CODE_SIGNING_REQUIRED=NO \
	        CODE_SIGN_IDENTITY="" \
	        PROVISIONING_PROFILE_SPECIFIER="" \
	        build; \
	      app_src="$$ios_derived/Build/Products/$$cfg_name-iphoneos/RunnerIOS.app"; \
	      ipa_payload="$$ios_derived/IPAPayload"; \
	      ipa_dst="$$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).ipa"; \
	      rm -rf "$$ipa_payload"; \
	      mkdir -p "$$ipa_payload/Payload"; \
	      cp -R "$$app_src" "$$ipa_payload/Payload/"; \
	      cd "$$ipa_payload" && zip -qr "$$ipa_dst" Payload/ && cd "$(ROOT_DIR)"; \
	      rm -rf "$$ipa_payload"; \
	      echo "Output: $$ipa_dst"; \
	    else \
	      export_method="debugging"; \
	      [[ "$(PROFILE)" == "release" ]] && export_method="app-store"; \
	      archive_path="$$ios_derived/RunnerIOS.xcarchive"; \
	      export_plist="$$ios_derived/ExportOptions-$(PROFILE).plist"; \
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
	        -derivedDataPath "$$ios_derived" \
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
	      ipa_dst="$$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).ipa"; \
	      [[ -f "$$ipa_src" ]] && mv -f "$$ipa_src" "$$ipa_dst"; \
	      echo "Output: $$ipa_dst"; \
	    fi ;; \
	  android) \
	    if ! command -v cargo-ndk &>/dev/null; then \
	      echo "ERROR: cargo-ndk not found — install with: cargo install cargo-ndk --locked"; \
	      exit 1; \
	    fi; \
	    if [[ ! -d "$(FRONTEND_DIR)/android" ]]; then \
	      cd "$(FRONTEND_DIR)"; flutter create --platforms=android .; cd "$(ROOT_DIR)"; \
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
	    cp "$$apk_src" "$$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).apk"; \
	    echo "Output: $$out_dir/$(APP_NAME)-$(APP_VERSION)-$(PROFILE).apk" ;; \
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
