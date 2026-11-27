#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="ClaudeGate"
APP_DIR="${ROOT_DIR}/build/${APP_NAME}.app"
CONTENTS_DIR="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"
ENGINE_DIR="${RESOURCES_DIR}/engine"

echo "1) Building TypeScript engine..."
cd "${ROOT_DIR}"
npm run build

echo "2) Assembling ${APP_DIR}..."
rm -rf "${APP_DIR}"
mkdir -p "${MACOS_DIR}" "${ENGINE_DIR}"

echo "3) Generating AppIcon.icns..."
ICONSET_DIR="${ROOT_DIR}/build/AppIcon.iconset"
rm -rf "${ICONSET_DIR}"
if swift "${ROOT_DIR}/macos/generate-icon.swift" "${ICONSET_DIR}" && iconutil -c icns "${ICONSET_DIR}" -o "${RESOURCES_DIR}/AppIcon.icns"; then
  rm -rf "${ICONSET_DIR}"
else
  echo "Warning: icon generation skipped"
  rm -rf "${ICONSET_DIR}"
fi

echo "4) Compiling native Swift menu bar app..."
ARCH="$(uname -m)"
swiftc -O -swift-version 5 \
  -target "${ARCH}-apple-macos13.0" \
  -framework AppKit \
  -framework WebKit \
  -o "${MACOS_DIR}/${APP_NAME}" \
  "${ROOT_DIR}/macos/ClaudeGateApp.swift"

echo "5) Writing Info.plist..."
cat > "${CONTENTS_DIR}/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>zh_CN</string>
  <key>CFBundleDisplayName</key>
  <string>ClaudeGate</string>
  <key>CFBundleExecutable</key>
  <string>ClaudeGate</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>com.claudeban.claudegate</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>ClaudeGate</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsLocalNetworking</key>
    <true/>
  </dict>
</dict>
</plist>
EOF

echo "6) Copying engine runtime files..."
cp -R "${ROOT_DIR}/dist" "${ENGINE_DIR}/dist"
cp -R "${ROOT_DIR}/public" "${ENGINE_DIR}/public"
cp "${ROOT_DIR}/package.json" "${ENGINE_DIR}/package.json"

NODE_PATH="$(which node || true)"
if [[ -n "${NODE_PATH}" ]]; then
  echo "${NODE_PATH}" > "${ENGINE_DIR}/node-path.txt"
fi

echo "7) Signing app bundle (ad-hoc)..."
codesign --force --deep --sign - "${APP_DIR}"

echo "✅ Built ${APP_DIR}"

if [[ "${1:-}" == "--install" ]]; then
  TARGET="/Applications/${APP_NAME}.app"
  if [[ -w "/Applications" ]]; then
    rm -rf "${TARGET}"
    cp -R "${APP_DIR}" "${TARGET}"
    echo "✅ Installed to ${TARGET}"
  else
    mkdir -p "${HOME}/Applications"
    TARGET="${HOME}/Applications/${APP_NAME}.app"
    rm -rf "${TARGET}"
    cp -R "${APP_DIR}" "${TARGET}"
    echo "✅ Installed to ${TARGET}"
  fi
fi
