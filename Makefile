SHELL := /bin/zsh

ROOT_DIR := $(CURDIR)
FRONTEND_DIR := $(ROOT_DIR)/frontend
PLATFORMS_DIR := $(ROOT_DIR)/platforms
BUILD_DIR := $(ROOT_DIR)/build
FLUTTER_INTERMEDIATE_DIR := $(BUILD_DIR)/intermediates/flutter
RUST_INTERMEDIATE_DIR := $(BUILD_DIR)/intermediates/rust
APPLE_PROJECT := $(PLATFORMS_DIR)/apple/Runner.xcodeproj
APP_VERSION := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | cut -d+ -f1)
APP_BUILD_NUMBER := $(shell awk -F': ' '/^version:/{print $$2}' $(FRONTEND_DIR)/pubspec.yaml | awk -F+ '{print ($$2 == "" ? "1" : $$2)}')

OS ?=
PROFILE ?= release
UNSIGNED ?= 1

.PHONY: help guard-os guard-profile setup-build clean build build-debug build-release build-both ios macos linux windows ios-both macos-both

help:
	@echo "Mesh Infinity canonical build entrypoint (Makefile)"
	@echo ""
	@echo "Usage:"
	@echo "  make build OS=<android|ios|macos|linux|windows> [PROFILE=debug|release] [UNSIGNED=1|0]"
	@echo "  make build-debug OS=<android|ios|macos|linux|windows>"
	@echo "  make build-release OS=<android|ios|macos|linux|windows>"
	@echo "  make build-both OS=<android|ios|macos|linux|windows>"
	@echo "  make ios"
	@echo "  make macos"
	@echo "  make ios-both"
	@echo "  make macos-both"

guard-os:
	@if [[ -z "$(OS)" ]]; then echo "ERROR: OS is required"; exit 1; fi
	@set -euo pipefail; \
	raw_os="$(OS)"; \
	for os in $${=raw_os//,/ }; do \
		if [[ "$$os" != "android" && "$$os" != "ios" && "$$os" != "macos" && "$$os" != "linux" && "$$os" != "windows" ]]; then \
			echo "ERROR: OS token '$$os' must be one of android|ios|macos|linux|windows"; exit 1; \
		fi; \
	done

guard-profile:
	@if [[ "$(PROFILE)" != "debug" && "$(PROFILE)" != "release" ]]; then \
		echo "ERROR: PROFILE must be debug or release"; exit 1; \
	fi

setup-build:
	@mkdir -p "$(BUILD_DIR)/output" "$(FLUTTER_INTERMEDIATE_DIR)" "$(RUST_INTERMEDIATE_DIR)" "$(BUILD_DIR)/logs"

clean:
	rm -rf "$(BUILD_DIR)"

build: guard-os guard-profile setup-build
	@set -euo pipefail; \
	raw_os="$(OS)"; \
	os_count=0; \
	for _ in $${=raw_os//,/ }; do os_count=$$((os_count+1)); done; \
	if [[ "$$os_count" -gt 1 ]]; then \
		for os in $${=raw_os//,/ }; do \
			$(MAKE) build OS="$$os" PROFILE="$(PROFILE)" UNSIGNED="$(UNSIGNED)"; \
		done; \
		exit 0; \
	fi; \
	if [[ -f "$(PLATFORMS_DIR)/apple/policy.env" ]]; then source "$(PLATFORMS_DIR)/apple/policy.env"; fi; \
	rustup_cargo="$$(rustup which cargo 2>/dev/null || command -v cargo)"; \
	rustup_rustc="$$(rustup which rustc 2>/dev/null || command -v rustc)"; \
	cargo_flags=""; \
	flutter_flags="--debug"; \
	if [[ "$(PROFILE)" == "release" ]]; then cargo_flags="--release"; flutter_flags="--release"; fi; \
	if [[ "$(OS)" == "ios" || "$(OS)" == "macos" ]]; then \
		ephemeral_dir="$(BUILD_DIR)/intermediates/apple/flutter"; \
		mkdir -p "$$ephemeral_dir"; \
		if [[ ! -f "$$ephemeral_dir/Flutter-Generated.xcconfig" ]]; then \
			flutter_root="$$(flutter --version --machine | ruby -rjson -e 'puts JSON.parse(STDIN.read)["flutterRoot"]')"; \
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
	fi; \
	if [[ "$(OS)" == "ios" ]]; then \
		RUSTC="$$rustup_rustc" IPHONEOS_DEPLOYMENT_TARGET="$${APPLE_IOS_DEPLOYMENT_TARGET:-13.0}" CARGO_TARGET_DIR="$(RUST_INTERMEDIATE_DIR)" "$$rustup_cargo" build -p mesh-infinity --target aarch64-apple-ios $$cargo_flags; \
		RUSTC="$$rustup_rustc" IPHONEOS_DEPLOYMENT_TARGET="$${APPLE_IOS_DEPLOYMENT_TARGET:-13.0}" CARGO_TARGET_DIR="$(RUST_INTERMEDIATE_DIR)" "$$rustup_cargo" build -p mesh-infinity --target x86_64-apple-ios $$cargo_flags || true; \
	else \
		RUSTC="$$rustup_rustc" CARGO_TARGET_DIR="$(RUST_INTERMEDIATE_DIR)" "$$rustup_cargo" build -p mesh-infinity $$cargo_flags; \
	fi; \
	if [[ "$(UNSIGNED)" == "1" ]]; then export MESH_UNSIGNED=1; fi; \
	out_ts="$$(date +%Y%m%d-%H%M%S)"; \
	out_dir="$(BUILD_DIR)/output/$$out_ts/$(OS)"; \
	mkdir -p "$$out_dir"; \
	case "$(OS)" in \
		macos) \
			xcodebuild \
				-project "$(APPLE_PROJECT)" \
				-scheme Runner \
				-configuration $$( [[ "$(PROFILE)" == "release" ]] && echo Release || echo Debug ) \
				-derivedDataPath "$(BUILD_DIR)/intermediates/apple/macos" \
				CODE_SIGNING_ALLOWED=NO \
				CODE_SIGNING_REQUIRED=NO \
				CODE_SIGN_IDENTITY="" \
				build; \
			app_src="$(BUILD_DIR)/intermediates/apple/macos/Build/Products/$$( [[ "$(PROFILE)" == "release" ]] && echo Release || echo Debug )/meshinfinity.app"; \
			app_dst="$$out_dir/meshinfinity-$(APP_VERSION)-$(PROFILE).app"; \
			rm -rf "$$app_dst"; \
			cp -R "$$app_src" "$$app_dst"; \
			echo "Output: $$app_dst" ;; \
		ios) \
			archive_dir="$(BUILD_DIR)/intermediates/apple/ios"; \
			archive_path="$$archive_dir/RunnerIOS.xcarchive"; \
			export_plist="$$archive_dir/ExportOptions-$(PROFILE).plist"; \
			mkdir -p "$$archive_dir"; \
			export_method="$$( [[ "$(PROFILE)" == "release" ]] && echo app-store || echo debugging )"; \
			if [[ "$(UNSIGNED)" == "1" ]]; then export_method=debugging; fi; \
			printf '%s\n' \
				'<?xml version="1.0" encoding="UTF-8"?>' \
				'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
				'<plist version="1.0">' \
				'<dict>' \
				'  <key>method</key>' \
				"  <string>$$export_method</string>" \
				'  <key>signingStyle</key>' \
				'  <string>automatic</string>' \
				'  <key>stripSwiftSymbols</key>' \
				'  <true/>' \
				'  <key>compileBitcode</key>' \
				'  <false/>' \
				'</dict>' \
				'</plist>' > "$$export_plist"; \
			xcodebuild \
				-project "$(APPLE_PROJECT)" \
				-scheme RunnerIOS \
				-configuration $$( [[ "$(PROFILE)" == "release" ]] && echo Release || echo Debug ) \
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
			if [[ -f "$$ipa_src" ]]; then mv -f "$$ipa_src" "$$ipa_dst"; fi; \
			echo "Output: $$ipa_dst" ;; \
		android) \
			cd "$(PLATFORMS_DIR)/android"; \
			./gradlew assemble$$( [[ "$(PROFILE)" == "release" ]] && echo Release || echo Debug ) ;; \
		linux|windows) \
			echo "ERROR: $(OS) host project migration to platforms/ is not wired in Makefile yet"; \
			exit 1 ;; \
	esac

build-debug:
	@$(MAKE) build OS="$(OS)" PROFILE=debug UNSIGNED="$(UNSIGNED)"

build-release:
	@$(MAKE) build OS="$(OS)" PROFILE=release UNSIGNED="$(UNSIGNED)"

build-both:
	@set -euo pipefail; \
	for profile in debug release; do \
		$(MAKE) build OS="$(OS)" PROFILE="$$profile" UNSIGNED="$(UNSIGNED)"; \
	done

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

windows:
	@$(MAKE) build OS=windows PROFILE=debug

android:
	@$(MAKE) build OS=android PROFILE=debug
