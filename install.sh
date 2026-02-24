#!/bin/sh
# Shenan CLI installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/jhnlsn/shenan/main/install.sh | sh

set -e

REPO="jhnlsn/shenan"
BINARY="shenan"
INSTALL_DIR="${HOME}/.local/bin"

# Detect OS
OS=$(uname -s)
case "${OS}" in
  Darwin) OS_NAME="apple-darwin" ;;
  Linux)  OS_NAME="unknown-linux-gnu" ;;
  *)
    echo "Unsupported OS: ${OS}" >&2
    exit 1
    ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "${ARCH}" in
  x86_64)        ARCH_NAME="x86_64" ;;
  arm64|aarch64) ARCH_NAME="aarch64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    exit 1
    ;;
esac

TARGET="${ARCH_NAME}-${OS_NAME}"

# Resolve latest release version
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "${VERSION}" ]; then
  echo "Failed to determine latest release version." >&2
  exit 1
fi

ARCHIVE="${BINARY}-${VERSION}-${TARGET}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

# Work in a temporary directory
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

mkdir -p "${INSTALL_DIR}"

echo "Installing shenan ${VERSION} for ${TARGET}..."

curl -fsSL "${BASE_URL}/${ARCHIVE}"        -o "${TMP}/${ARCHIVE}"
curl -fsSL "${BASE_URL}/${ARCHIVE}.sha256" -o "${TMP}/${ARCHIVE}.sha256"

# Verify checksum
EXPECTED=$(awk '{print $1}' "${TMP}/${ARCHIVE}.sha256")
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "${TMP}/${ARCHIVE}" | awk '{print $1}')
else
  ACTUAL=$(shasum -a 256 "${TMP}/${ARCHIVE}" | awk '{print $1}')
fi

if [ "${EXPECTED}" != "${ACTUAL}" ]; then
  echo "Checksum verification failed." >&2
  exit 1
fi

tar xzf "${TMP}/${ARCHIVE}" -C "${TMP}"
install -m 755 "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

echo ""
echo "shenan ${VERSION} installed to ${INSTALL_DIR}/${BINARY}"

# Warn if the install dir isn't on PATH
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "NOTE: ${INSTALL_DIR} is not in your PATH."
    echo "Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    echo "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    ;;
esac

echo ""
echo "Run 'shenan --help' to get started."
