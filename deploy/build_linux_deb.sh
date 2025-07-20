#!/usr/bin/env bash
# Build AmneziaVPN for Linux and produce a .deb (amd64) under deploy/out/
# Requires: sudo for apt (optional); network for submodules / aqt (last resort).

set -o errexit -o nounset -o pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

DEB_OUT="${DEB_OUT:-$PROJECT_DIR/deploy/out}"
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/deploy/build-deb}"
STAGE_DIR="${BUILD_DIR}/deb-root"

# Qt 6 QML is split into qml6-module-* (not ELF-linked — dpkg-shlibdeps misses them).
# Covers imports under client/ui/qml (QtQuick.*, QtCore, Qt5Compat.*, Qt.labs.platform, Templates, WorkerScript).
LINUX_QML_RUNTIME_PKGS=(
  qml6-module-qtqml
  qml6-module-qtqml-workerscript
  qml6-module-qtqml-models
  qml6-module-qtcore
  qml6-module-qtquick
  qml6-module-qtquick-window
  qml6-module-qtquick-templates
  qml6-module-qtquick-controls
  qml6-module-qtquick-layouts
  qml6-module-qtquick-dialogs
  qml6-module-qtquick-shapes
  qml6-module-qt5compat-graphicaleffects
  qml6-module-qt-labs-platform
)
join_qml_depends() {
  local out="" p
  for p in "${LINUX_QML_RUNTIME_PKGS[@]}"; do
    out+="${p} (>= 6.3.0), "
  done
  printf '%s' "${out%, }"
}

VERSION="$(sed -nE 's/^set\(AMNEZIAVPN_VERSION ([^)]+)\).*/\1/p' "$PROJECT_DIR/CMakeLists.txt" | head -1)"
ARCH="$(dpkg-architecture -qDEB_BUILD_ARCH 2>/dev/null || echo amd64)"
PKG="amneziavpn_${VERSION}_${ARCH}"

echo "==> Version: $VERSION  Arch: $ARCH"

echo "==> Git submodules"
git submodule update --init --recursive --depth 1

echo "==> Install build dependencies (apt, optional)"
APT_PACKAGES=(build-essential cmake ninja-build pkg-config git dpkg-dev debhelper wget ca-certificates unzip p7zip-full
  libgl1-mesa-dev libvulkan-dev libsecret-1-dev libxkbcommon-x11-0 libxkbcommon0
  qt6-base-dev qt6-declarative-dev qt6-svg-dev qt6-tools-dev qt6-remoteobjects-dev qt6-5compat-dev)
apt_install() {
  apt-get update -y && apt-get install -y --no-install-recommends "$@"
}
if [[ "$(id -u)" -eq 0 ]]; then
  apt_install "${APT_PACKAGES[@]}" || true
  apt-get install -y --no-install-recommends qt6-shadertools-dev 2>/dev/null || true
elif command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends "${APT_PACKAGES[@]}" || true
  sudo apt-get install -y --no-install-recommends qt6-shadertools-dev 2>/dev/null || true
else
  echo "NOTE: no passwordless sudo / not root — skip apt. Install if needed:"
  echo "  sudo apt-get install ${APT_PACKAGES[*]} qt6-shadertools-dev"
fi

QT_CMAKE=""
QT_BIN_DIR="${QT_BIN_DIR:-}"
CMAKE_EXTRA=()
for qcfg in /usr/lib/x86_64-linux-gnu/cmake/Qt6/Qt6Config.cmake \
            /usr/lib/aarch64-linux-gnu/cmake/Qt6/Qt6Config.cmake; do
  if [[ -f "$qcfg" ]]; then
    export CMAKE_PREFIX_PATH="$(dirname "$(dirname "$(dirname "$qcfg")")")"
    QT_CMAKE="$(command -v qt-cmake 2>/dev/null || true)"
    if [[ -z "$QT_CMAKE" ]]; then
      QT_CMAKE="cmake"
    fi
    break
  fi
done
if [[ -z "$QT_CMAKE" || "$QT_CMAKE" == "cmake" && -z "${CMAKE_PREFIX_PATH:-}" ]]; then
  for d in /opt/Qt/*/gcc_64/bin "$HOME"/Qt/*/gcc_64/bin; do
    if [[ -x "$d/qt-cmake" ]]; then
      QT_BIN_DIR="$(dirname "$d")"
      export PATH="$QT_BIN_DIR:$PATH"
      QT_CMAKE="$d/qt-cmake"
      unset CMAKE_PREFIX_PATH
      break
    fi
  done
fi
if [[ -n "$QT_BIN_DIR" && -x "$QT_BIN_DIR/qt-cmake" ]]; then
  export PATH="$QT_BIN_DIR:$PATH"
  QT_CMAKE="$QT_BIN_DIR/qt-cmake"
fi
# Last resort: user-local Qt via aqtinstall (no root)
if [[ -z "$QT_CMAKE" ]]; then
  AQT_QT_VER="${AQT_QT_VER:-6.6.2}"
  AQT_BASE="${AQT_BASE:-$HOME/Qt}"
  if [[ ! -x "$AQT_BASE/$AQT_QT_VER/gcc_64/bin/qt-cmake" ]]; then
    echo "==> Installing Qt $AQT_QT_VER with aqtinstall (user dir: $AQT_BASE)"
    AQT_VENV="$PROJECT_DIR/deploy/.aqt-venv"
    python3 -m venv "$AQT_VENV"
    "$AQT_VENV/bin/pip" install -q "aqtinstall==3.1.*"
    "$AQT_VENV/bin/aqt" install-qt linux desktop "$AQT_QT_VER" gcc_64 -O "$AQT_BASE" \
      -m qtremoteobjects -m qt5compat -m qtshadertools
  fi
  export PATH="$AQT_BASE/$AQT_QT_VER/gcc_64/bin:$PATH"
  QT_CMAKE="$(command -v qt-cmake)"
fi
if [[ -z "$QT_CMAKE" ]]; then
  echo "ERROR: qt-cmake not found. Install qt6-base-dev or set QT_BIN_DIR." >&2
  exit 1
fi

echo "==> Configure ($QT_CMAKE ${CMAKE_PREFIX_PATH:+CMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH})"
cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  ${CMAKE_PREFIX_PATH:+-DCMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH"}

echo "==> Build"
cmake --build "$BUILD_DIR" -j"$(nproc)"

echo "==> Assemble AppDir (system Qt, no CQtDeployer)"
APP_DIR="$BUILD_DIR/AppDir"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR"

cp -a "$PROJECT_DIR/deploy/data/linux/"* "$APP_DIR/"
# qt.conf assumes bundled Qt layout; with distro Qt it breaks plugin discovery.
rm -f "$APP_DIR/client/bin/qt.conf" "$APP_DIR/service/bin/qt.conf" 2>/dev/null || true

mkdir -p "$APP_DIR/client/bin" "$APP_DIR/service/bin"
if [[ -d "$PROJECT_DIR/client/3rd-prebuilt/deploy-prebuilt/linux/client/bin" ]]; then
  cp -a "$PROJECT_DIR/client/3rd-prebuilt/deploy-prebuilt/linux/client/bin/"* "$APP_DIR/client/bin/" 2>/dev/null || true
fi
cp -f "$BUILD_DIR/client/AmneziaVPN" "$APP_DIR/client/bin/AmneziaVPN"
chmod a+x "$APP_DIR/client/bin/AmneziaVPN"
cp -f "$BUILD_DIR/service/server/AmneziaVPN-service" "$APP_DIR/service/bin/AmneziaVPN-service"
chmod a+x "$APP_DIR/service/bin/AmneziaVPN-service"

write_launcher() {
  local target="$1" binname="$2"
  cat >"$target" <<EOF
#!/bin/sh
# Packaged launcher: use system Qt 6 paths from qmake6; bundled tools in ./bin.
BASE_DIR=\$(dirname "\$(readlink -f "\$0")")
BIN_DIR="\$BASE_DIR/bin"
export LD_LIBRARY_PATH="\$BIN_DIR\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"

# Drop CQtDeployer / stale env so Qt does not pick wrong plugins (e.g. ../plugins built for another Qt).
unset QTDIR CQT_PKG_ROOT CQT_RUN_FILE QT_PLUGIN_PATH QT_QPA_PLATFORM_PLUGIN_PATH \
  QML2_IMPORT_PATH QML_IMPORT_PATH 2>/dev/null || true

# Only Qt 6 qmake — plain "qmake" is often Qt5 and yields empty/wrong plugin paths.
find_qmake6() {
  for c in \\
    /usr/lib/qt6/bin/qmake6 \\
    /usr/lib/x86_64-linux-gnu/qt6/bin/qmake6 \\
    /usr/lib/aarch64-linux-gnu/qt6/bin/qmake6 \\
    "\$(command -v qmake6 2>/dev/null)"; do
    [ -z "\$c" ] && continue
    [ -x "\$c" ] || continue
    _ver=\$("\$c" -query QT_VERSION 2>/dev/null | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')
    case "\$_ver" in 6.*) echo "\$c"; return 0;; esac
  done
  return 1
}

_plug=""
_qml=""
_libe=""

QMAKE=\$(find_qmake6) || QMAKE=
if [ -n "\$QMAKE" ]; then
  _qv() { "\$QMAKE" -query "\$1" 2>/dev/null | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
  _plug=\$(_qv QT_INSTALL_PLUGINS)
  _qml=\$(_qv QT_INSTALL_QML)
  _libe=\$(_qv QT_INSTALL_LIBEXECS)
fi

# No dev packages / qmake failed: Ubuntu/Debian multiarch layout (runtime libqt6* installs plugins here).
if [ -z "\$_plug" ] || [ ! -d "\$_plug/platforms" ]; then
  for d in /usr/lib/x86_64-linux-gnu/qt6/plugins /usr/lib/aarch64-linux-gnu/qt6/plugins /usr/lib/qt6/plugins; do
    if [ -d "\$d/platforms" ]; then
      _plug="\$d"
      break
    fi
  done
fi
if [ -z "\$_qml" ] && [ -d /usr/lib/x86_64-linux-gnu/qt6/qml ]; then
  _qml=/usr/lib/x86_64-linux-gnu/qt6/qml
elif [ -z "\$_qml" ] && [ -d /usr/lib/aarch64-linux-gnu/qt6/qml ]; then
  _qml=/usr/lib/aarch64-linux-gnu/qt6/qml
fi
if [ -z "\$_libe" ] && [ -d /usr/lib/x86_64-linux-gnu/qt6/libexec ]; then
  _libe=/usr/lib/x86_64-linux-gnu/qt6/libexec
elif [ -z "\$_libe" ] && [ -d /usr/lib/aarch64-linux-gnu/qt6/libexec ]; then
  _libe=/usr/lib/aarch64-linux-gnu/qt6/libexec
fi

if [ -n "\$_plug" ]; then
  export QT_PLUGIN_PATH="\$_plug"
  export QT_QPA_PLATFORM_PLUGIN_PATH="\$_plug/platforms"
fi
[ -n "\$_qml" ] && export QML2_IMPORT_PATH="\$_qml"
[ -n "\$_qml" ] && export QML_IMPORT_PATH="\$_qml"
if [ -n "\$_libe" ] && [ -x "\$_libe/QtWebEngineProcess" ]; then
  export QTWEBENGINEPROCESS_PATH="\$_libe/QtWebEngineProcess"
fi

exec "\$BIN_DIR/$binname" "\$@"
EOF
  chmod a+x "$target"
}

write_launcher "$APP_DIR/client/AmneziaVPN.sh" "AmneziaVPN"
write_launcher "$APP_DIR/service/AmneziaVPN-service.sh" "AmneziaVPN-service"

cp "$PROJECT_DIR/client/images/AmneziaVPN.png" "$APP_DIR/AmneziaVPN.png"
if [[ -f "$PROJECT_DIR/deploy/AppDir/AmneziaVPN.desktop" ]]; then
  cp "$PROJECT_DIR/deploy/AppDir/AmneziaVPN.desktop" "$APP_DIR/AmneziaVPN.desktop"
else
  sed 's/^Exec=.*/Exec=\/opt\/AmneziaVPN\/client\/AmneziaVPN.sh/' \
    "$PROJECT_DIR/deploy/installer/config/AmneziaVPN.desktop.in" > "$APP_DIR/AmneziaVPN.desktop"
fi
cp "$PROJECT_DIR/deploy/data/linux/AmneziaVPN.service" "$APP_DIR/AmneziaVPN.service"

echo "==> Stage .deb tree"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/DEBIAN" "$STAGE_DIR/opt/AmneziaVPN"
cp -a "$APP_DIR"/* "$STAGE_DIR/opt/AmneziaVPN/"

# systemd: ensure ExecStart; drop bundled-Qt LD_LIBRARY_PATH (launcher sets env for the binary).
sed -i 's|^ExecStart=.*|ExecStart=/opt/AmneziaVPN/service/AmneziaVPN-service.sh|' "$STAGE_DIR/opt/AmneziaVPN/AmneziaVPN.service"
sed -i '/^Environment=LD_LIBRARY_PATH=/d' "$STAGE_DIR/opt/AmneziaVPN/AmneziaVPN.service"

SHLIBS_DEPENDS=""
# dpkg-shlibdeps expects a stub debian/control in the current working directory.
SHLIB_WORK="$BUILD_DIR/shlibdeps-work"
mkdir -p "$SHLIB_WORK/debian"
cat >"$SHLIB_WORK/debian/control" <<EOF
Source: amneziavpn
Section: net
Priority: optional
Maintainer: AmneziaVPN <packaging@amnezia.org>

Package: amneziavpn
Architecture: any
Depends: \${shlibs:Depends}
Description: Dependency scan stub (not shipped)
EOF
if (cd "$SHLIB_WORK" && dpkg-shlibdeps -T"$STAGE_DIR/DEBIAN/substvars" \
  "$STAGE_DIR/opt/AmneziaVPN/client/bin/AmneziaVPN" \
  "$STAGE_DIR/opt/AmneziaVPN/service/bin/AmneziaVPN-service"); then
  if [[ -f "$STAGE_DIR/DEBIAN/substvars" ]]; then
    SHLIBS_DEPENDS="$(grep -E '^shlibs:Depends=' "$STAGE_DIR/DEBIAN/substvars" | head -1 | cut -d= -f2- || true)"
  fi
fi
if [[ -z "$SHLIBS_DEPENDS" ]]; then
  echo "WARN: dpkg-shlibdeps failed or empty; using conservative fallback Depends." >&2
  SHLIBS_DEPENDS="libc6 (>= 2.31), libstdc++6 (>= 10), libgcc-s1, zlib1g, libdbus-1-3, libglib2.0-0 (>= 2.56), libsecret-1-0, libxcb1, libx11-6, libx11-xcb1, libxcb-xinerama0, libxkbcommon0, libxkbcommon-x11-0, libfontconfig1, libfreetype6, libxrender1, libxi6, libegl1, libgl1, libsm6, libice6, libxext6"
fi
QML_MODULES_DEPENDS="$(join_qml_depends)"
# SVG icons in QML (Image / Controls icon) need Qt6 imageformats plugin libqsvg.so (not pulled by dpkg-shlibdeps).
SVG_PLUGIN_DEPENDS="libqt6svg6 (>= 6.3.0)"
DEB_DEPENDS="${SHLIBS_DEPENDS}, ${QML_MODULES_DEPENDS}, ${SVG_PLUGIN_DEPENDS}, openssh-client | ssh"

cat > "$STAGE_DIR/DEBIAN/control" <<EOF
Package: amneziavpn
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: AmneziaVPN <packaging@amnezia.org>
Homepage: https://amnezia.org/
Depends: ${DEB_DEPENDS}
Recommends: qt6-wayland
Description: AmneziaVPN self-hosted VPN client
 AmneziaVPN desktop client and system service (Linux).
EOF

cat > "$STAGE_DIR/DEBIAN/postinst" <<'EOS'
#!/bin/sh
set -e
case "$1" in
  configure)
    chmod a+x /opt/AmneziaVPN/client/AmneziaVPN.sh /opt/AmneziaVPN/service/AmneziaVPN-service.sh 2>/dev/null || true
    # Remove bundled Qt trees from older CQtDeployer installs (wrong Qt minor → platform plugin errors).
    rm -rf /opt/AmneziaVPN/client/plugins /opt/AmneziaVPN/client/lib /opt/AmneziaVPN/client/qml /opt/AmneziaVPN/client/translations 2>/dev/null || true
    rm -rf /opt/AmneziaVPN/service/plugins /opt/AmneziaVPN/service/lib /opt/AmneziaVPN/service/qml /opt/AmneziaVPN/service/translations 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then
      cp /opt/AmneziaVPN/AmneziaVPN.service /lib/systemd/system/AmneziaVPN.service
      systemctl daemon-reload
      systemctl enable AmneziaVPN.service
      systemctl restart AmneziaVPN.service || systemctl start AmneziaVPN.service || true
    fi
    if [ ! -e /usr/local/bin/AmneziaVPN ]; then
      ln -sf /opt/AmneziaVPN/client/AmneziaVPN.sh /usr/local/bin/AmneziaVPN
    fi
    if [ -f /opt/AmneziaVPN/AmneziaVPN.desktop ]; then
      cp /opt/AmneziaVPN/AmneziaVPN.desktop /usr/share/applications/AmneziaVPN.desktop
      chmod 0644 /usr/share/applications/AmneziaVPN.desktop
    fi
    if [ -f /opt/AmneziaVPN/AmneziaVPN.png ]; then
      cp /opt/AmneziaVPN/AmneziaVPN.png /usr/share/pixmaps/AmneziaVPN.png
      chmod 0644 /usr/share/pixmaps/AmneziaVPN.png
    fi
    ;;
esac
exit 0
EOS
chmod 0755 "$STAGE_DIR/DEBIAN/postinst"

cat > "$STAGE_DIR/DEBIAN/prerm" <<'EOS'
#!/bin/sh
set -e
case "$1" in
  remove|upgrade|deconfigure)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop AmneziaVPN.service 2>/dev/null || true
      systemctl disable AmneziaVPN.service 2>/dev/null || true
    fi
    rm -f /lib/systemd/system/AmneziaVPN.service
    rm -f /usr/local/bin/AmneziaVPN
    ;;
esac
exit 0
EOS
chmod 0755 "$STAGE_DIR/DEBIAN/prerm"

mkdir -p "$DEB_OUT"
rm -f "$DEB_OUT/${PKG}.deb"
dpkg-deb --root-owner-group --build "$STAGE_DIR" "$DEB_OUT/${PKG}.deb"

echo "==> Done: $DEB_OUT/${PKG}.deb"
ls -lh "$DEB_OUT/${PKG}.deb"
echo "==> On a dev machine, install Qt6 QML + SVG plugin (icons) at once:"
echo "    sudo apt-get install -y libqt6svg6 ${LINUX_QML_RUNTIME_PKGS[*]}"
