SHELL := bash

# $(CURDIR) on Windows returns a path like D:/a/... which rsync misreads as a
# remote host:path pair (the drive letter looks like a hostname).  Using
# $(shell pwd) instead always yields a POSIX path (/d/a/...) in bash.
# NOTE: Do NOT install rsync via choco on the Windows CI runner.  Chocolatey's
# cwRsync uses Cygwin conventions (/cygdrive/d/...) and does not understand
# MSYS2-style POSIX paths (/d/a/...).  Git for Windows does NOT ship rsync.
# Use MSYS2 pacman (pre-installed at C:\msys64 on windows-latest) to install
# rsync and prepend C:\msys64\usr\bin to PATH before running make.
ROOT_DIR      := $(shell pwd)
FRONTEND_DIR  := $(ROOT_DIR)/frontend
PLATFORMS_DIR := $(ROOT_DIR)/platforms
BUILD_DIR     := $(ROOT_DIR)/build
APPLE_PROJECT   := $(PLATFORMS_DIR)/apple/Runner.xcodeproj
APPLE_WORKSPACE := $(PLATFORMS_DIR)/apple/Runner.xcworkspace

# App identity comes from the Rust project (Cargo.toml / pubspec.yaml).
APP_NAME         := $(shell awk -F'"' '/^name/{print $$2; exit}' Cargo.toml | sed 's/[-[:space:]]//g')
APP_VERSION      := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | cut -d+ -f1)
APP_BUILD_NUMBER := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | awk -F+ '{print ($$2 == "" ? "1" : $$2)}')
# Revision number = total commit count (deterministic, same locally and in CI).
APP_REV          := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
APP_BUILD_LABEL  := $(APP_VERSION)-r$(APP_REV)

.PHONY: clean \
        macos-rust-debug macos-rust-release \
        macos-xcode-debug macos-xcode-release \
        macos-debug macos-release \
        ios-rust-debug ios-rust-release \
        ios-xcode-debug ios-xcode-release \
        ios-debug ios-release \
        android-rust-debug android-rust-release \
        android-gradle-debug android-gradle-release \
        android-debug android-release \
        linux-rust-debug linux-rust-release \
        linux-bundle-debug linux-bundle-release \
        linux-debug linux-release \
        windows-rust-debug windows-rust-release \
        windows-bundle-debug windows-bundle-release \
        windows-debug windows-release \
        push

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -rf "$(BUILD_DIR)/intermediates"

# ── macOS: Rust only ──────────────────────────────────────────────────────────
#
# Builds and lipo-merges libmesh_infinity.dylib for both darwin triples.
# Output: build/intermediates/macos/rust/<profile>/libmesh_infinity.dylib
#
# Used by CI to pre-build Rust in a dedicated job before running Xcode.
# For local full builds use macos-debug / macos-release instead.

macos-rust-debug macos-rust-release: macos-rust-%:
	@set -euo pipefail; \
	profile="$*"; \
	cargo_flags=""; [[ "$$profile" == "release" ]] && cargo_flags="--release"; \
	rust_subdir="debug"; [[ "$$profile" == "release" ]] && rust_subdir="release"; \
	rust_target="$(BUILD_DIR)/intermediates/macos/backend/$$profile"; \
	rust_out="$(BUILD_DIR)/intermediates/macos/rust/$$profile"; \
	\
	mkdir -p "$$rust_target" "$$rust_out"; \
	\
	CARGO_TARGET_DIR="$$rust_target" \
	  cargo build -p mesh-infinity --target aarch64-apple-darwin $$cargo_flags; \
	CARGO_TARGET_DIR="$$rust_target" \
	  cargo build -p mesh-infinity --target x86_64-apple-darwin $$cargo_flags; \
	lipo -create \
	  "$$rust_target/aarch64-apple-darwin/$$rust_subdir/libmesh_infinity.dylib" \
	  "$$rust_target/x86_64-apple-darwin/$$rust_subdir/libmesh_infinity.dylib" \
	  -output "$$rust_out/libmesh_infinity.dylib"; \
	echo "Rust output: $$rust_out/libmesh_infinity.dylib"

# ── macOS: Xcode only ─────────────────────────────────────────────────────────
#
# Runs Flutter framework build + Xcode + DMG packaging.
# Requires Rust dylib to already exist at:
#   build/intermediates/macos/rust/<profile>/libmesh_infinity.dylib
#
# Used by CI after downloading the pre-built Rust artifact.
# For local full builds use macos-debug / macos-release instead.

macos-xcode-debug macos-xcode-release: macos-xcode-%:
	@set -euo pipefail; \
	profile="$*"; \
	cfg="Debug"; [[ "$$profile" == "release" ]] && cfg="Release"; \
	src_dir="$(BUILD_DIR)/intermediates/macos/$$profile/src"; \
	fw_dir="$(BUILD_DIR)/intermediates/macos/$$profile/frontend"; \
	rust_out="$(BUILD_DIR)/intermediates/macos/$$profile/backend"; \
	rust_src="$(BUILD_DIR)/intermediates/macos/rust/$$profile/libmesh_infinity.dylib"; \
	\
	mkdir -p \
	  "$$src_dir" \
	  "$$fw_dir" \
	  "$$rust_out" \
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
	rsync -a "$(ROOT_DIR)/assets/" "$(BUILD_DIR)/intermediates/macos/$$profile/assets/"; \
	mkdir -p "$$src_dir/macos"; \
	\
	cp "$$rust_src" "$$rust_out/libmesh_infinity.dylib"; \
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
	  "$$fw_dir/$$cfg/FlutterMacOS.xcframework/macos-arm64_x86_64/FlutterMacOS.framework/FlutterMacOS" \
	  "$$fw_dir/$$cfg/App.xcframework/macos-arm64_x86_64/App.framework/App" \
	  > "$(BUILD_DIR)/intermediates/apple/flutter/FlutterInputs.xcfilelist"; \
	printf "%s\n" \
	  "$(BUILD_DIR)/intermediates/macos/xcode/Build/Products/$$cfg/Runner.app/Contents/Frameworks/FlutterMacOS.framework/FlutterMacOS" \
	  "$(BUILD_DIR)/intermediates/macos/xcode/Build/Products/$$cfg/Runner.app/Contents/Frameworks/App.framework/App" \
	  > "$(BUILD_DIR)/intermediates/apple/flutter/FlutterOutputs.xcfilelist"; \
	\
	mkdir -p "$(PLATFORMS_DIR)/apple/Flutter/ephemeral"; \
	(cd "$(PLATFORMS_DIR)/apple" && FLUTTER_APPLICATION_PATH="$(PLATFORMS_DIR)/apple" pod install); \
	\
	xcodebuild \
	  -workspace "$(APPLE_WORKSPACE)" \
	  -scheme Runner \
	  -configuration "$$cfg" \
	  -derivedDataPath "$(BUILD_DIR)/intermediates/macos/xcode" \
	  ARCHS="arm64 x86_64" \
	  ONLY_ACTIVE_ARCH=NO \
	  CODE_SIGNING_ALLOWED=NO \
	  CODE_SIGNING_REQUIRED=NO \
	  CODE_SIGN_IDENTITY="" \
	  MESH_RUST_DYLIB_PATH="$$rust_src" \
	  build; \
	\
	app_src="$(BUILD_DIR)/intermediates/macos/xcode/Build/Products/$$cfg/$(APP_NAME).app"; \
	for xcfw in "$$fw_dir/$$cfg"/*.xcframework; do \
	  _n="$$(basename "$$xcfw" .xcframework)"; \
	  [ "$$_n" = "FlutterMacOS" ] && continue; \
	  [ "$$_n" = "App" ] && continue; \
	  _slice="$$(find "$$xcfw" -maxdepth 1 -name 'macos-*' -type d | head -1)"; \
	  [ -n "$$_slice" ] && [ -d "$$_slice/$$_n.framework" ] && \
	    cp -R "$$_slice/$$_n.framework" "$$app_src/Contents/Frameworks/"; \
	done; \
	native_assets_dir="$$src_dir/build/native_assets/macos"; \
	if [ -d "$$native_assets_dir" ]; then \
	  for na_fw in "$$native_assets_dir"/*.framework; do \
	    [ -d "$$na_fw" ] || continue; \
	    cp -R "$$na_fw" "$$app_src/Contents/Frameworks/"; \
	    na_name=$$(basename "$$na_fw"); \
	    codesign --force --sign - "$$app_src/Contents/Frameworks/$$na_name"; \
	  done; \
	fi; \
	dmg_stage="$(BUILD_DIR)/intermediates/macos/$$profile/dmg-stage"; \
	rm -rf "$$dmg_stage"; \
	mkdir "$$dmg_stage"; \
	cp -R "$$app_src" "$$dmg_stage/"; \
	ln -s /Applications "$$dmg_stage/Applications"; \
	hdiutil create \
	  -volname "$(APP_NAME)" \
	  -srcfolder "$$dmg_stage" \
	  -ov -format UDZO \
	  "$(BUILD_DIR)/output/macos/$$profile/$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile.dmg"; \
	rm -rf "$$dmg_stage"; \
	echo "Output: $(BUILD_DIR)/output/macos/$$profile/$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile.dmg"

# ── macOS: full (Rust + Xcode) ────────────────────────────────────────────────
#
# Convenience target for local development. Equivalent to the CI two-job split.

macos-debug macos-release: macos-%:
	$(MAKE) macos-rust-$*
	$(MAKE) macos-xcode-$*

# ── iOS: Rust only ────────────────────────────────────────────────────────────
#
# Builds libmesh_infinity.a (staticlib) for the device ABI (aarch64-apple-ios).
# Output: build/intermediates/ios/rust/<profile>/libmesh_infinity.a
#
# Used by CI to pre-build Rust in a dedicated job before running Xcode.
# For local full builds use ios-debug / ios-release instead.

ios-rust-debug ios-rust-release: ios-rust-%:
	@set -euo pipefail; \
	profile="$*"; \
	cargo_flags=""; [[ "$$profile" == "release" ]] && cargo_flags="--release"; \
	rust_subdir="debug"; [[ "$$profile" == "release" ]] && rust_subdir="release"; \
	rust_target="$(BUILD_DIR)/intermediates/ios/backend/$$profile"; \
	rust_out="$(BUILD_DIR)/intermediates/ios/rust/$$profile"; \
	\
	mkdir -p "$$rust_target" "$$rust_out"; \
	\
	CARGO_TARGET_DIR="$$rust_target" \
	  IPHONEOS_DEPLOYMENT_TARGET=13.0 \
	  cargo build -p mesh-infinity --target aarch64-apple-ios $$cargo_flags; \
	cp "$$rust_target/aarch64-apple-ios/$$rust_subdir/libmesh_infinity.a" \
	   "$$rust_out/libmesh_infinity.a"; \
	echo "Rust output: $$rust_out/libmesh_infinity.a"

# ── iOS: Xcode only ───────────────────────────────────────────────────────────
#
# Runs Flutter framework build + Xcode archive → unsigned IPA.
# Requires Rust staticlib to already exist at:
#   build/intermediates/ios/rust/<profile>/libmesh_infinity.a
#
# Used by CI after downloading the pre-built Rust artifact.
# For local full builds use ios-debug / ios-release instead.

ios-xcode-debug ios-xcode-release: ios-xcode-%:
	@set -euo pipefail; \
	profile="$*"; \
	cfg="Debug"; [[ "$$profile" == "release" ]] && cfg="Release"; \
	src_dir="$(BUILD_DIR)/intermediates/ios/$$profile/src"; \
	fw_dir="$(BUILD_DIR)/intermediates/ios/$$profile/frontend"; \
	rust_out="$(BUILD_DIR)/intermediates/ios/$$profile/backend"; \
	rust_src="$(BUILD_DIR)/intermediates/ios/rust/$$profile/libmesh_infinity.a"; \
	\
	mkdir -p \
	  "$$src_dir" \
	  "$$fw_dir" \
	  "$$rust_out" \
	  "$(BUILD_DIR)/intermediates/ios/$$profile/xcode" \
	  "$(BUILD_DIR)/intermediates/apple/flutter" \
	  "$(BUILD_DIR)/output/ios/$$profile"; \
	\
	rsync -a --delete \
	  --exclude=build/ \
	  --exclude=.dart_tool/ \
	  --exclude=.flutter-plugins \
	  --exclude=.flutter-plugins-dependencies \
	  --exclude=ios/Podfile \
	  --exclude=ios/Runner.xcodeproj/ \
	  --exclude=ios/Runner.xcworkspace/ \
	  --exclude=ios/Pods/ \
	  "$(FRONTEND_DIR)/" "$$src_dir/"; \
	rsync -a "$(ROOT_DIR)/assets/" "$(BUILD_DIR)/intermediates/ios/$$profile/assets/"; \
	mkdir -p "$$src_dir/ios" "$$src_dir/Flutter"; \
	\
	cp "$$rust_src" "$$rust_out/libmesh_infinity.a"; \
	\
	flutter config --enable-ios; \
	( cd "$$src_dir" && flutter pub get ); \
	rm -rf "$$src_dir/ios/Runner.xcodeproj" "$$src_dir/ios/Runner.xcworkspace" "$$src_dir/ios/Pods"; \
	ln -sfn "$(ROOT_DIR)/platforms/apple/Runner.xcodeproj" "$$src_dir/ios/Runner.xcodeproj"; \
	cp "$(ROOT_DIR)/platforms/apple/Podfile.ios.build" "$$src_dir/ios/Podfile"; \
	flutter_mode_flags="--$$profile"; \
	[[ "$$profile" != "debug"   ]] && flutter_mode_flags="$$flutter_mode_flags --no-debug"; \
	[[ "$$profile" != "profile" ]] && flutter_mode_flags="$$flutter_mode_flags --no-profile"; \
	[[ "$$profile" != "release" ]] && flutter_mode_flags="$$flutter_mode_flags --no-release"; \
	( cd "$$src_dir" && flutter build ios-framework $$flutter_mode_flags \
	    --output "$$fw_dir" ); \
	\
	rm -rf \
	  "$$src_dir/ios/Runner.xcodeproj" \
	  "$$src_dir/ios/Runner.xcworkspace" \
	  "$$src_dir/ios/Pods" \
	  "$$src_dir/ios/Flutter" \
	  "$$src_dir/ios/RunnerIOS" \
	  "$$src_dir/ios/FlutterIOS" \
	  "$$src_dir/ios/Runner/Configs" \
	  "$$src_dir/apple" \
	  "$(BUILD_DIR)/intermediates/ios/$$profile/build/intermediates/apple/flutter"; \
	rsync -a "$(ROOT_DIR)/platforms/apple/Flutter/" "$$src_dir/ios/Flutter/"; \
	rsync -a "$(ROOT_DIR)/platforms/apple/RunnerIOS/" "$$src_dir/ios/RunnerIOS/"; \
	rsync -a "$(ROOT_DIR)/platforms/apple/FlutterIOS/" "$$src_dir/ios/FlutterIOS/"; \
	mkdir -p "$$src_dir/ios/Runner"; \
	rsync -a "$(ROOT_DIR)/platforms/apple/Runner/Configs/" "$$src_dir/ios/Runner/Configs/"; \
	cp "$$src_dir/ios/Runner/GeneratedPluginRegistrant.h" "$$src_dir/ios/RunnerIOS/"; \
	cp "$$src_dir/ios/Runner/GeneratedPluginRegistrant.m" "$$src_dir/ios/RunnerIOS/"; \
	ln -sfn "$(ROOT_DIR)/platforms/apple" "$$src_dir/apple"; \
	ln -sfn "$(ROOT_DIR)/platforms/apple/Runner.xcodeproj" "$$src_dir/ios/Runner.xcodeproj"; \
	cp "$(ROOT_DIR)/platforms/apple/Podfile.ios" "$$src_dir/ios/Podfile"; \
	\
	flutter_root="$$(flutter --version --machine | jq -r .flutterRoot)"; \
	printf "%s\n" \
	  "FLUTTER_ROOT=$$flutter_root" \
	  "FLUTTER_APPLICATION_PATH=$$src_dir" \
	  "FLUTTER_FRAMEWORK_BASE=$(BUILD_DIR)/intermediates/ios" \
	  "FLUTTER_TARGET=lib/main.dart" \
	  "FLUTTER_BUILD_DIR=build" \
	  "FLUTTER_BUILD_NAME=$(APP_VERSION)" \
	  "FLUTTER_BUILD_NUMBER=$(APP_BUILD_NUMBER)" \
	  > "$(BUILD_DIR)/intermediates/apple/flutter/Flutter-Generated.xcconfig"; \
	mkdir -p "$(BUILD_DIR)/intermediates/ios/$$profile/build/intermediates/apple/flutter"; \
	cp "$(BUILD_DIR)/intermediates/apple/flutter/Flutter-Generated.xcconfig" \
	  "$(BUILD_DIR)/intermediates/ios/$$profile/build/intermediates/apple/flutter/Flutter-Generated.xcconfig"; \
	export FLUTTER_ROOT="$$flutter_root"; \
	export FLUTTER_APPLICATION_PATH="$$src_dir"; \
	( cd "$$src_dir/ios" && pod install ); \
	\
	xcodebuild \
	  -workspace "$$src_dir/ios/Runner.xcworkspace" \
	  -scheme RunnerIOS \
	  -configuration "$$cfg" \
	  -sdk iphoneos \
	  -derivedDataPath "$(BUILD_DIR)/intermediates/ios/$$profile/xcode" \
	  ARCHS=arm64 \
	  ONLY_ACTIVE_ARCH=NO \
	  CODE_SIGNING_ALLOWED=NO \
	  CODE_SIGNING_REQUIRED=NO \
	  CODE_SIGN_IDENTITY="" \
	  FLUTTER_FRAMEWORK_BASE="$(BUILD_DIR)/intermediates/ios" \
	  'LIBRARY_SEARCH_PATHS=$$(inherited)'"  $$rust_out" \
	  'OTHER_LDFLAGS=$$(inherited) -lmesh_infinity -lresolv' \
	  build; \
	\
	ipa_payload="$(BUILD_DIR)/output/ios/$$profile/Payload"; \
	rm -rf "$$ipa_payload"; \
	mkdir -p "$$ipa_payload"; \
	cp -R \
	  "$(BUILD_DIR)/intermediates/ios/$$profile/xcode/Build/Products/$$cfg-iphoneos/"*.app \
	  "$$ipa_payload/"; \
	native_assets_dir="$$src_dir/build/native_assets/ios"; \
	if [ -d "$$native_assets_dir" ]; then \
	  for na_fw in "$$native_assets_dir"/*.framework; do \
	    [ -d "$$na_fw" ] || continue; \
	    for _app in "$$ipa_payload/"*.app; do \
	      mkdir -p "$$_app/Frameworks"; \
	      cp -R "$$na_fw" "$$_app/Frameworks/"; \
	      na_name=$$(basename "$$na_fw"); \
	      codesign --force --sign - "$$_app/Frameworks/$$na_name"; \
	    done; \
	  done; \
	fi; \
	for _app in "$$ipa_payload/"*.app; do \
	  for _fw in "$$_app/Frameworks/"*.framework; do \
	    _bin="$$_fw/$$(basename $$_fw .framework)"; \
	    if [ -f "$$_bin" ] && file "$$_bin" | grep -q "ar archive"; then \
	      echo "Removing static framework from bundle: $$(basename $$_fw)"; \
	      rm -rf "$$_fw"; \
	    fi; \
	  done; \
	done; \
	( cd "$(BUILD_DIR)/output/ios/$$profile" \
	  && zip -qr "$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile.ipa" Payload ); \
	rm -rf "$$ipa_payload"; \
	echo "Output: $(BUILD_DIR)/output/ios/$$profile/$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile.ipa"

# ── iOS: full (Rust + Xcode) ──────────────────────────────────────────────────
#
# Convenience target for local development. Equivalent to the CI two-job split.

ios-debug ios-release: ios-%:
	$(MAKE) ios-rust-$*
	$(MAKE) ios-xcode-$*

# ── Android: Rust only ────────────────────────────────────────────────────────
#
# Builds libmesh_infinity.so for all Android ABIs via cargo-ndk.
# Output: build/intermediates/android/jni/<profile>/<abi>/libmesh_infinity.so
#
# Used by CI to pre-build Rust in a dedicated job before running Gradle.
# For local full builds use android-debug / android-release instead.

android-rust-debug android-rust-release: android-rust-%:
	@set -euo pipefail; \
	profile="$*"; \
	cargo_flags=""; [[ "$$profile" == "release" ]] && cargo_flags="--release"; \
	rust_target="$(BUILD_DIR)/intermediates/android/backend/$$profile"; \
	jni_out="$(BUILD_DIR)/intermediates/android/jni/$$profile"; \
	\
	mkdir -p "$$rust_target" "$$jni_out"; \
	CARGO_TARGET_DIR="$$rust_target" \
	  cargo ndk \
	    -t arm64-v8a \
	    -t armeabi-v7a \
	    -t x86_64 \
	    -o "$$jni_out" \
	    -- build -p mesh-infinity $$cargo_flags; \
	echo "Rust output: $$jni_out"

# ── Android: Gradle only ──────────────────────────────────────────────────────
#
# Copies pre-built JNI libs into place, runs Gradle, and copies the APK.
# Requires Rust .so files to already exist at:
#   build/intermediates/android/jni/<profile>/<abi>/libmesh_infinity.so
#
# Used by CI after downloading the pre-built Rust artifact.
# For local full builds use android-debug / android-release instead.

android-gradle-debug android-gradle-release: android-gradle-%:
	@set -euo pipefail; \
	profile="$*"; \
	gradle_task="assembleDebug"; [[ "$$profile" == "release" ]] && gradle_task="assembleRelease"; \
	jni_src="$(BUILD_DIR)/intermediates/android/jni/$$profile"; \
	jni_out="$(PLATFORMS_DIR)/android/app/src/main/jniLibs"; \
	\
	mkdir -p "$(BUILD_DIR)/output/android/$$profile"; \
	flutter_root="$$(flutter --version --machine | jq -r .flutterRoot)"; \
	{ \
	  [[ -n "$${ANDROID_HOME:-}" ]] && printf "sdk.dir=%s\n" "$$ANDROID_HOME"; \
	  printf "flutter.sdk=%s\n" "$$flutter_root"; \
	} > "$(PLATFORMS_DIR)/android/local.properties"; \
	flutter config --enable-android; \
	( cd "$(FRONTEND_DIR)" && flutter pub get ); \
	cp -r "$$jni_src/." "$$jni_out/"; \
	( cd "$(PLATFORMS_DIR)/android" && gradle $$gradle_task ); \
	apk_src="$(BUILD_DIR)/app/outputs/apk/$$profile/app-$$profile.apk"; \
	cp "$$apk_src" \
	   "$(BUILD_DIR)/output/android/$$profile/$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile.apk"; \
	echo "Output: $(BUILD_DIR)/output/android/$$profile/$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile.apk"

# ── Android: full (Rust + Gradle) ─────────────────────────────────────────────
#
# Convenience target for local development. Equivalent to the CI two-job split.

android-debug android-release: android-%:
	$(MAKE) android-rust-$*
	$(MAKE) android-gradle-$*

# ── Linux: Rust only ──────────────────────────────────────────────────────────
#
# Builds libmesh_infinity.so natively for x86_64 Linux.
# Output: build/intermediates/linux/rust/<profile>/libmesh_infinity.so
#
# Used by CI to pre-build Rust in a dedicated job before the Flutter/packaging job.
# For local full builds use linux-debug / linux-release instead.

linux-rust-debug linux-rust-release: linux-rust-%:
	@set -euo pipefail; \
	profile="$*"; \
	cargo_flags=""; [[ "$$profile" == "release" ]] && cargo_flags="--release"; \
	rust_subdir="debug"; [[ "$$profile" == "release" ]] && rust_subdir="release"; \
	rust_target="$(BUILD_DIR)/intermediates/linux/backend/$$profile"; \
	rust_out="$(BUILD_DIR)/intermediates/linux/rust/$$profile"; \
	\
	mkdir -p "$$rust_target" "$$rust_out"; \
	\
	CARGO_TARGET_DIR="$$rust_target" \
	  cargo build -p mesh-infinity --target x86_64-unknown-linux-gnu $$cargo_flags; \
	cp "$$rust_target/x86_64-unknown-linux-gnu/$$rust_subdir/libmesh_infinity.so" \
	   "$$rust_out/libmesh_infinity.so"; \
	echo "Rust output: $$rust_out/libmesh_infinity.so"

# ── Linux: Flutter bundle + packaging only ────────────────────────────────────
#
# Runs Flutter build linux, copies Rust .so into bundle, then packages as:
#   AppImage, tar.gz, DEB, RPM
#
# Requires Rust .so to already exist at:
#   build/intermediates/linux/rust/<profile>/libmesh_infinity.so
#
# Used by CI after downloading the pre-built Rust artifact.
# For local full builds use linux-debug / linux-release instead.
#
# CI dependencies (ubuntu):
#   libgtk-3-dev libblkid-dev liblzma-dev ninja-build
#   rpm ruby-dev && gem install --no-document fpm
#   appimagetool (downloaded from GitHub)

linux-bundle-debug linux-bundle-release: linux-bundle-%:
	@set -euo pipefail; \
	profile="$*"; \
	flutter_profile="$$profile"; \
	src_dir="$(BUILD_DIR)/intermediates/linux/$$profile/src"; \
	rust_so="$(BUILD_DIR)/intermediates/linux/rust/$$profile/libmesh_infinity.so"; \
	out_dir="$(BUILD_DIR)/output/linux/$$profile"; \
	\
	mkdir -p "$$src_dir" "$$out_dir"; \
	\
	rsync -a --delete \
	  --exclude=build/ \
	  --exclude=.dart_tool/ \
	  --exclude=.flutter-plugins \
	  --exclude=.flutter-plugins-dependencies \
	  "$(FRONTEND_DIR)/" "$$src_dir/"; \
	rsync -a "$(ROOT_DIR)/assets/" "$(BUILD_DIR)/intermediates/linux/$$profile/assets/"; \
	mkdir -p "$$src_dir/linux"; \
	rsync -a "$(PLATFORMS_DIR)/linux/" "$$src_dir/linux/"; \
	\
	flutter config --enable-linux-desktop; \
	( cd "$$src_dir" && flutter pub get ); \
	( cd "$$src_dir" && flutter build linux "--$$profile" ); \
	\
	bundle_dir="$$src_dir/build/linux/x64/$$profile/bundle"; \
	mkdir -p "$$bundle_dir/lib"; \
	cp "$$rust_so" "$$bundle_dir/lib/libmesh_infinity.so"; \
	\
	appimage_dir="$(BUILD_DIR)/intermediates/linux/$$profile/AppDir"; \
	rm -rf "$$appimage_dir"; \
	mkdir -p "$$appimage_dir/usr/bin" "$$appimage_dir/usr/lib" \
	          "$$appimage_dir/usr/share/applications" \
	          "$$appimage_dir/usr/share/icons/hicolor/256x256/apps"; \
	cp -r "$$bundle_dir/." "$$appimage_dir/usr/bin/"; \
	printf '[Desktop Entry]\nType=Application\nName=Mesh Infinity\nExec=mesh_infinity_frontend\nIcon=meshinfinity\nCategories=Network;\n' \
	  > "$$appimage_dir/usr/share/applications/meshinfinity.desktop"; \
	cp "$$appimage_dir/usr/share/applications/meshinfinity.desktop" \
	   "$$appimage_dir/meshinfinity.desktop"; \
	if [ -f "$(ROOT_DIR)/assets/icons/icon_256.png" ]; then \
	  cp "$(ROOT_DIR)/assets/icons/icon_256.png" \
	     "$$appimage_dir/usr/share/icons/hicolor/256x256/apps/meshinfinity.png"; \
	  cp "$(ROOT_DIR)/assets/icons/icon_256.png" "$$appimage_dir/meshinfinity.png"; \
	else \
	  touch "$$appimage_dir/meshinfinity.png"; \
	fi; \
	APPIMAGE_EXTRACT_AND_RUN=1 appimagetool "$$appimage_dir" \
	  "$$out_dir/$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile-x86_64.AppImage"; \
	\
	tar -czf "$$out_dir/$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile-linux-x86_64.tar.gz" \
	  -C "$(BUILD_DIR)/intermediates/linux/$$profile/src/build/linux/x64/$$profile" bundle; \
	\
	fpm -s dir -t deb \
	  --name mesh-infinity \
	  --version "$(APP_VERSION)" \
	  --architecture amd64 \
	  --description "Mesh Infinity — decentralised mesh networking" \
	  --maintainer "Onii Media Works" \
	  --package "$$out_dir/$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile-amd64.deb" \
	  "$$bundle_dir/=/opt/mesh-infinity"; \
	\
	fpm -s dir -t rpm \
	  --name mesh-infinity \
	  --version "$(APP_VERSION)" \
	  --architecture x86_64 \
	  --description "Mesh Infinity — decentralised mesh networking" \
	  --maintainer "Onii Media Works" \
	  --package "$$out_dir/$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile-x86_64.rpm" \
	  "$$bundle_dir/=/opt/mesh-infinity"; \
	\
	echo "Output: $$out_dir/"

# ── Linux: full (Rust + bundle + packaging) ───────────────────────────────────
#
# Convenience target for local development. Equivalent to the CI two-job split.

linux-debug linux-release: linux-%:
	$(MAKE) linux-rust-$*
	$(MAKE) linux-bundle-$*

# ── Windows: Rust only ────────────────────────────────────────────────────────
#
# Builds mesh_infinity.dll natively for x86_64 Windows.
# Output: build/intermediates/windows/rust/<profile>/mesh_infinity.dll
#
# Used by CI to pre-build Rust in a dedicated job before the Flutter/packaging job.
# For local full builds use windows-debug / windows-release instead.

windows-rust-debug windows-rust-release: windows-rust-%:
	@set -euo pipefail; \
	profile="$*"; \
	cargo_flags=""; [[ "$$profile" == "release" ]] && cargo_flags="--release"; \
	rust_subdir="debug"; [[ "$$profile" == "release" ]] && rust_subdir="release"; \
	rust_target="$(BUILD_DIR)/intermediates/windows/backend/$$profile"; \
	rust_out="$(BUILD_DIR)/intermediates/windows/rust/$$profile"; \
	\
	mkdir -p "$$rust_target" "$$rust_out"; \
	\
	unset MAKEFLAGS; \
	CARGO_TARGET_DIR="$$rust_target" \
	  cargo build -p mesh-infinity --target x86_64-pc-windows-msvc $$cargo_flags; \
	cp "$$rust_target/x86_64-pc-windows-msvc/$$rust_subdir/mesh_infinity.dll" \
	   "$$rust_out/mesh_infinity.dll"; \
	echo "Rust output: $$rust_out/mesh_infinity.dll"

# ── Windows: Flutter bundle + packaging only ──────────────────────────────────
#
# Runs Flutter build windows, copies Rust .dll into bundle, then packages as:
#   NSIS installer, portable zip
#
# Requires Rust .dll to already exist at:
#   build/intermediates/windows/rust/<profile>/mesh_infinity.dll
#
# Used by CI after downloading the pre-built Rust artifact.
# For local full builds use windows-debug / windows-release instead.

windows-bundle-debug windows-bundle-release: windows-bundle-%:
	@set -euo pipefail; \
	profile="$*"; \
	cfg="Debug"; [[ "$$profile" == "release" ]] && cfg="Release"; \
	src_dir="$(BUILD_DIR)/intermediates/windows/$$profile/src"; \
	rust_dll="$(BUILD_DIR)/intermediates/windows/rust/$$profile/mesh_infinity.dll"; \
	bundle_stage="$(BUILD_DIR)/intermediates/windows/bundle/$$profile"; \
	out_dir="$(BUILD_DIR)/output/windows/$$profile"; \
	\
	mkdir -p "$$src_dir" "$$bundle_stage" "$$out_dir"; \
	\
	rsync -a --delete \
	  --exclude=build/ \
	  --exclude=.dart_tool/ \
	  --exclude=.flutter-plugins \
	  --exclude=.flutter-plugins-dependencies \
	  "$(FRONTEND_DIR)/" "$$src_dir/"; \
	rsync -a "$(ROOT_DIR)/assets/" "$(BUILD_DIR)/intermediates/windows/$$profile/assets/"; \
	mkdir -p "$$src_dir/windows"; \
	rsync -a "$(PLATFORMS_DIR)/windows/" "$$src_dir/windows/"; \
	\
	flutter config --enable-windows-desktop; \
	( cd "$$src_dir" && flutter pub get ); \
	( cd "$$src_dir" && flutter build windows "--$$profile" ); \
	\
	bundle_dir="$$src_dir/build/windows/x64/runner/$$cfg"; \
	cp "$$rust_dll" "$$bundle_dir/mesh_infinity.dll"; \
	\
	rsync -a --delete "$$bundle_dir/" "$$bundle_stage/"; \
	\
	bundle_stage_win="$$(cygpath -w "$$bundle_stage")"; \
	out_dir_win="$$(cygpath -w "$$out_dir")"; \
	nsi_script="$$(cygpath -w "$(PLATFORMS_DIR)/windows/installer.nsi")"; \
	MSYS2_ARG_CONV_EXCL="/D" makensis \
	  /DAPP_NAME="$(APP_NAME)" \
	  /DAPP_VERSION="$(APP_BUILD_LABEL)" \
	  /DPROFILE="$$profile" \
	  "/DBUNDLE_DIR=$$bundle_stage_win" \
	  "/DOUT_FILE=$$out_dir_win\\$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile-setup.exe" \
	  "$$nsi_script"; \
	\
	7z a -tzip \
	  "$$out_dir_win\\$(APP_NAME)-$(APP_BUILD_LABEL)-$$profile-windows-portable.zip" \
	  "$$bundle_stage_win\\*"; \
	\
	echo "Output: $$out_dir/"

# ── Windows: full (Rust + bundle + packaging) ─────────────────────────────────
#
# Convenience target for local development. Equivalent to the CI two-job split.

windows-debug windows-release: windows-%:
	$(MAKE) windows-rust-$*
	$(MAKE) windows-bundle-$*

# ── Push with prerelease tag ──────────────────────────────────────────────────
# Creates a revision tag (v<version>-r<commit_count>) and pushes code + tag to
# origin.  The tag lives on Gitea, so the push mirror preserves it on GitHub
# and the prerelease workflow attaches assets to it.

push:
	@rev=$$(git rev-list --count HEAD); \
	tag="v$(APP_VERSION)-r$$rev"; \
	echo "Tagging $$tag ..."; \
	git tag -f "$$tag" HEAD; \
	git push origin main "$$tag"
