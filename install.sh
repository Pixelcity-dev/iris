#!/bin/bash
set -e

# Iris Installer v2 - Ultra Easy Install
# All-in-one Cybersecurity CLI Tool
#
# Quick Install (pick one):
#   curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh
#   curl -fsSL https://cdn.pixelcity.top/iris/install.sh | sh
#   wget -qO- https://cdn.pixelcity.dev/iris/install.sh | sh
#   sh -c "$(curl -fsSL https://cdn.pixelcity.dev/iris/install.sh)"
#
# Custom version / dir:
#   curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | DEEPSEC_VERSION=v1.2.0 sh
#   curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | INSTALL_DIR=/usr/local/bin sh
#
# Other methods:
#   go install github.com/Pixelcity-dev/Deepsec/cmd/iris@latest
#   docker pull pixelcity/iris:latest && docker run --rm pixelcity/iris --help
#   brew install pixelcity/tap/iris  (coming soon)

DEEPSEC_VERSION="${DEEPSEC_VERSION:-v1.2.0}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BASE_URL="${BASE_URL:-https://cdn.pixelcity.dev/iris/releases}"
FALLBACK_URL="https://cdn.pixelcity.top/iris/releases"
GITHUB_RELEASES="https://github.com/Pixelcity-dev/Deepsec/releases/download"

# colors (auto-disable if not tty)
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; DIM=''; NC=''
fi

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

# handle --help / --uninstall
for arg in "$@"; do
  case "$arg" in
    -h|--help)
      echo "Iris Installer"
      echo "Usage: curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh"
      echo ""
      echo "Env:"
      echo "  DEEPSEC_VERSION=v1.2.0   version to install (or 'latest')"
      echo "  INSTALL_DIR=\$HOME/.local/bin   install directory"
      echo "  BASE_URL=https://cdn.pixelcity.dev/iris/releases override"
      echo "Args:"
      echo "  --help        show this"
      echo "  --uninstall   remove iris from INSTALL_DIR"
      echo "  --version     print latest version and exit"
      echo "  --dry-run     show what would be installed"
      exit 0
      ;;
    --uninstall)
      echo -e "${YELLOW}Uninstalling iris from $INSTALL_DIR ...${NC}"
      rm -f "$INSTALL_DIR/iris" "$INSTALL_DIR/iris.exe"
      echo -e "${GREEN}Done${NC}"
      exit 0
      ;;
    --version)
      echo "$DEEPSEC_VERSION"
      exit 0
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
  esac
done

echo ""
echo -e "${CYAN}  ____                           ____  ______  __ __ ${NC}"
echo -e "${CYAN} |  _ \\  ___  ___ _   _ _ __ ___|  _ \\|  _ \\ \\ V / |${NC}"
echo -e "${CYAN} | | | |/ _ \\/ __| | | | '__/ __| | | | | | | | |  |${NC}"
echo -e "${CYAN} | |_| |  __/\\__ \\ |_| | | | (__| |_| | |_| | | |  |${NC}"
echo -e "${CYAN} |____/ \\___||___/\\__,_|_|  \\___|____/|____/ |_|__|${NC}"
echo -e "${CYAN}                                     ${DEEPSEC_VERSION}${NC}"
echo ""
echo -e "  ${DIM}All-in-one Cybersecurity CLI — SAST/SCA/Secrets/IaC/Container/DAST/Network/License + WebScan${NC}"
echo ""

check_deps() {
  # curl or wget required; uname required
  if ! command -v uname >/dev/null 2>&1; then
    error "uname is required but not installed."
  fi
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    error "curl or wget is required but neither is installed. Install curl: apt install curl / brew install curl"
  fi
}

resolve_latest() {
  if [ "$DEEPSEC_VERSION" = "latest" ] || [ "$DEEPSEC_VERSION" = "stable" ]; then
    info "Resolving latest version..."
    # try CDN VERSION file, then fallback to v1.2.0
    LATEST_URL="$BASE_URL/../VERSION"
    # Try to fetch latest version string; ignore errors
    RESOLVED=""
    if command -v curl >/dev/null 2>&1; then
      RESOLVED=$(curl -fsSL "$LATEST_URL" 2>/dev/null | tr -d ' \n\r' | head -c 20 || true)
    elif command -v wget >/dev/null 2>&1; then
      RESOLVED=$(wget -qO- "$LATEST_URL" 2>/dev/null | tr -d ' \n\r' | head -c 20 || true)
    fi
    if echo "$RESOLVED" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+'; then
      DEEPSEC_VERSION="$RESOLVED"
      info "Latest is $DEEPSEC_VERSION"
    else
      DEEPSEC_VERSION="v1.2.0"
      warn "Could not resolve latest, using $DEEPSEC_VERSION"
    fi
  fi
}

detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case $ARCH in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armhf) ARCH="arm" ;;
    armv6l) ARCH="arm" ;;
    *) error "Unsupported architecture: $ARCH (supported: amd64, arm64, arm)" ;;
  esac
  case $OS in
    linux) PLATFORM="linux" ;;
    darwin) PLATFORM="darwin" ;;
    mingw*|msys*|cygwin*|windows*) PLATFORM="windows" ;;
    *) error "Unsupported OS: $OS (supported: linux, darwin, windows). Try Docker: docker run pixelcity/iris" ;;
  esac
  BINARY_NAME="iris"
  [ "$PLATFORM" = "windows" ] && BINARY_NAME="iris.exe"
  DETECTED="${PLATFORM}-${ARCH}"
  info "Detected platform: ${DETECTED}"
  # windows warning about INSTALL_DIR
  if [ "$PLATFORM" = "windows" ] && [ "$INSTALL_DIR" = "$HOME/.local/bin" ]; then
    warn "On Windows, consider INSTALL_DIR=/usr/local/bin or \$HOME/bin"
  fi
}

# download helper: try curl then wget, with fallback URLs
download_file() {
  URL="$1"
  OUT="$2"
  # Try curl
  if command -v curl >/dev/null 2>&1; then
    HTTP_CODE=$(curl -w "%{http_code}" -fsSL -o "$OUT" "$URL" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
      return 0
    fi
    # also try without -f to capture code
    HTTP_CODE=$(curl -w "%{http_code}" -sL -o "$OUT" "$URL" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then return 0; fi
    return 1
  fi
  if command -v wget >/dev/null 2>&1; then
    if wget -qO "$OUT" "$URL" 2>/dev/null; then
      return 0
    fi
    return 1
  fi
  return 1
}

install_binary() {
  info "Downloading Iris ${DEEPSEC_VERSION} for ${DETECTED}..."

  # primary and fallback URLs
  PRIMARY_URL="${BASE_URL}/${DEEPSEC_VERSION}/iris-${DETECTED}"
  FALLBACK_PRIMARY="${FALLBACK_URL}/${DEEPSEC_VERSION}/iris-${DETECTED}"
  GITHUB_URL="${GITHUB_RELEASES}/${DEEPSEC_VERSION}/iris-${DETECTED}"
  [ "$PLATFORM" = "windows" ] && PRIMARY_URL="${PRIMARY_URL}.exe" && FALLBACK_PRIMARY="${FALLBACK_PRIMARY}.exe" && GITHUB_URL="${GITHUB_URL}.exe"

  mkdir -p "$INSTALL_DIR"

  TEMP_FILE=$(mktemp 2>/dev/null || mktemp -t iris)
  TEMP_SHA=$(mktemp 2>/dev/null || mktemp -t iris_sha)

  URL_TO_TRY=""
  SUCCESS=0

  for URL in "$PRIMARY_URL" "$FALLBACK_PRIMARY" "$GITHUB_URL"; do
    info "Trying: $URL"
    if [ -n "$DRY_RUN" ]; then
      echo "  [dry-run] would download $URL -> $INSTALL_DIR/$BINARY_NAME"
      SUCCESS=1
      URL_TO_TRY="$URL"
      break
    fi
    if download_file "$URL" "$TEMP_FILE"; then
      SUCCESS=1
      URL_TO_TRY="$URL"
      success "Downloaded from $URL"
      break
    else
      warn "Failed: $URL"
    fi
  done

  if [ "$SUCCESS" != "1" ]; then
    rm -f "$TEMP_FILE" "$TEMP_SHA"
    echo ""
    error "Failed to download Iris for $DETECTED.
  Tried:
    - $PRIMARY_URL
    - $FALLBACK_PRIMARY
    - $GITHUB_URL
  Check your network or try manual download:
    curl -fsSL $PRIMARY_URL -o iris && chmod +x iris && sudo mv iris /usr/local/bin/
  Or via go: go install github.com/Pixelcity-dev/Deepsec/cmd/iris@latest
  Or docker: docker run --rm pixelcity/iris --help
  Issues: https://github.com/Pixelcity-dev/Deepsec/issues"
  fi

  if [ -n "$DRY_RUN" ]; then
    rm -f "$TEMP_FILE" "$TEMP_SHA"
    exit 0
  fi

  # Optional sha256 check if available on CDN (iris-XXX.sha256)
  SHA_URL="${URL_TO_TRY}.sha256"
  if download_file "$SHA_URL" "$TEMP_SHA" 2>/dev/null; then
    if command -v sha256sum >/dev/null 2>&1; then
      EXPECTED=$(awk '{print $1}' "$TEMP_SHA" | head -n1)
      ACTUAL=$(sha256sum "$TEMP_FILE" | awk '{print $1}')
      if [ "$EXPECTED" = "$ACTUAL" ]; then
        success "Checksum verified (sha256)"
      else
        warn "Checksum mismatch! expected $EXPECTED got $ACTUAL — continuing anyway"
      fi
    elif command -v shasum >/dev/null 2>&1; then
      EXPECTED=$(awk '{print $1}' "$TEMP_SHA" | head -n1)
      ACTUAL=$(shasum -a 256 "$TEMP_FILE" | awk '{print $1}')
      if [ "$EXPECTED" = "$ACTUAL" ]; then
        success "Checksum verified (sha256)"
      else
        warn "Checksum mismatch! expected $EXPECTED got $ACTUAL — continuing anyway"
      fi
    fi
  fi
  rm -f "$TEMP_SHA"

  # Verify it's not HTML error page
  if head -c 200 "$TEMP_FILE" | grep -qi "<!DOCTYPE\|<html"; then
    rm -f "$TEMP_FILE"
    error "Downloaded file is HTML (likely 404). Release $DEEPSEC_VERSION may not exist for $DETECTED.
  Available: https://cdn.pixelcity.dev/iris/releases/
  GitHub: https://github.com/Pixelcity-dev/Deepsec/releases"
  fi

  # Verify executable magic if 'file' exists
  if command -v file >/dev/null 2>&1; then
    if ! file "$TEMP_FILE" | grep -qi "executable\|ELF\|Mach-O\|PE32"; then
      # allow empty check on windows? be permissive
      if [ "$PLATFORM" != "windows" ] && [ "$(wc -c < "$TEMP_FILE")" -lt 1000 ]; then
        rm -f "$TEMP_FILE"
        error "Downloaded file too small / not a binary. Check $URL_TO_TRY"
      fi
    fi
  fi

  chmod +x "$TEMP_FILE"
  # handle sudo if INSTALL_DIR is system dir and not writable
  if [ ! -w "$INSTALL_DIR" ]; then
    if command -v sudo >/dev/null 2>&1; then
      warn "$INSTALL_DIR not writable, trying sudo..."
      sudo mv "$TEMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
    else
      rm -f "$TEMP_FILE"
      error "$INSTALL_DIR not writable and no sudo. Try: INSTALL_DIR=\$HOME/.local/bin sh install.sh"
    fi
  else
    mv "$TEMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
  fi

  success "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
  echo -e "  ${DIM}URL: $URL_TO_TRY${NC}"
}

update_path() {
  # if already in PATH, done
  if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
    return 0
  fi
  # detect shell rc files
  SHELL_NAME=$(basename "${SHELL:-sh}")
  RC_FILES=""
  # bash
  [ -f "$HOME/.bashrc" ] && RC_FILES="$RC_FILES $HOME/.bashrc"
  [ -f "$HOME/.bash_profile" ] && RC_FILES="$RC_FILES $HOME/.bash_profile"
  # zsh
  [ -f "$HOME/.zshrc" ] && RC_FILES="$RC_FILES $HOME/.zshrc"
  # fish
  if [ -f "$HOME/.config/fish/config.fish" ]; then
    if ! grep -q "$INSTALL_DIR" "$HOME/.config/fish/config.fish" 2>/dev/null; then
      echo "set -gx PATH \$PATH $INSTALL_DIR" >> "$HOME/.config/fish/config.fish"
      warn "Added $INSTALL_DIR to PATH in ~/.config/fish/config.fish (fish)"
    fi
    return 0
  fi

  # default: add to first rc file
  TARGET_RC=""
  if [ -f "$HOME/.zshrc" ]; then
    TARGET_RC="$HOME/.zshrc"
  elif [ -f "$HOME/.bashrc" ]; then
    TARGET_RC="$HOME/.bashrc"
  elif [ -f "$HOME/.bash_profile" ]; then
    TARGET_RC="$HOME/.bash_profile"
  fi

  if [ -n "$TARGET_RC" ]; then
    if ! grep -q "$INSTALL_DIR" "$TARGET_RC" 2>/dev/null; then
      echo "" >> "$TARGET_RC"
      echo "# Iris" >> "$TARGET_RC"
      echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$TARGET_RC"
      warn "Added $INSTALL_DIR to PATH in $TARGET_RC"
      warn "Run: source $TARGET_RC  or restart your terminal"
    fi
  else
    warn "Add $INSTALL_DIR to your PATH manually:"
    warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi

  # also export for current session
  export PATH="$INSTALL_DIR:$PATH"
}

verify_install() {
  echo ""
  if [ -x "${INSTALL_DIR}/${BINARY_NAME}" ]; then
    success "Iris installed successfully!"
    echo ""
    echo -e "  ${GREEN}Location:${NC} ${INSTALL_DIR}/${BINARY_NAME}"
    if command -v "${INSTALL_DIR}/${BINARY_NAME}" >/dev/null 2>&1; then
      VER=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || "${INSTALL_DIR}/${BINARY_NAME}" version 2>/dev/null || echo "$DEEPSEC_VERSION")
      echo -e "  ${GREEN}Version:${NC}  $VER"
    fi
    echo ""
    echo -e "  ${CYAN}Quick Start:${NC}"
    echo -e "    iris scan .                          ${DIM}# Scan current dir${NC}"
    echo -e "    iris scan https://example.com --scanner dast,webscan  ${DIM}# Deep website scan${NC}"
    echo -e "    iris scan . --scanner sast,sca,secrets  ${DIM}# Specific scanners${NC}"
    echo -e "    iris webscan https://example.com     ${DIM}# Full website audit (new!)${NC}"
    echo -e "    iris init                            ${DIM}# Create .iris.yaml${NC}"
    echo -e "    iris --help                          ${DIM}# All commands${NC}"
    echo ""
    echo -e "  ${DIM}Docs:     https://github.com/Pixelcity-dev/Deepsec${NC}"
    echo -e "  ${DIM}Releases: https://cdn.pixelcity.dev/iris/releases/${NC}"
    echo -e "  ${DIM}CDN:      https://cdn.pixelcity.dev/iris/install.sh${NC}"
    echo -e "  ${DIM}Alt CDN:  https://cdn.pixelcity.top/iris/install.sh${NC}"
    echo ""
    # if not in PATH, hint
    if ! command -v iris >/dev/null 2>&1; then
      warn "Not in current PATH. Try:"
      warn "  ${INSTALL_DIR}/iris --help"
      warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
  else
    warn "Binary installed but not executable. Check ${INSTALL_DIR}/${BINARY_NAME}"
  fi
  echo -e "${DIM}Tip: DEEPSEC_VERSION=latest curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh  # always latest${NC}"
  echo ""
}

main() {
  check_deps
  resolve_latest
  detect_platform
  install_binary
  update_path
  verify_install
}

main "$@"
