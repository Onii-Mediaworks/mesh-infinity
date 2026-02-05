#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_DIR="$ROOT_DIR/frontend/android"
KEYSTORE_PATH="$ANDROID_DIR/meshinfinity-release.jks"
KEY_ALIAS="meshinfinity"

if ! command -v keytool >/dev/null 2>&1; then
  echo "keytool is required (comes with a JDK). Install JDK 17 and ensure keytool is on PATH."
  exit 1
fi

read -r -s -p "Keystore password: " STORE_PASS
echo
read -r -s -p "Key password (press Enter to reuse keystore password): " KEY_PASS
echo
if [[ -z "$KEY_PASS" ]]; then
  KEY_PASS="$STORE_PASS"
fi

if [[ -f "$KEYSTORE_PATH" ]]; then
  echo "Keystore already exists at $KEYSTORE_PATH"
else
  keytool -genkey -v \
    -keystore "$KEYSTORE_PATH" \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -alias "$KEY_ALIAS" \
    -storepass "$STORE_PASS" \
    -keypass "$KEY_PASS"
fi

cat > "$ANDROID_DIR/key.properties" <<EOF
storePassword=$STORE_PASS
keyPassword=$KEY_PASS
keyAlias=$KEY_ALIAS
storeFile=meshinfinity-release.jks
EOF

echo "Wrote $ANDROID_DIR/key.properties"
