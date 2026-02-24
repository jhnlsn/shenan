#!/usr/bin/env bash
# Shenan relay installer
# Installs shenan-relay as a systemd service with TLS via Let's Encrypt.
# Tested on: Ubuntu 20.04+, Ubuntu 22.04+
#
# The shenan-relay binary is deployed separately (e.g. by CI/CD) to
# /usr/local/bin/shenan-relay before running this script.
#
# Usage:
#   sudo ./install.sh --domain relay.shenan.dev
#   sudo ./install.sh --domain relay.shenan.dev --bind 0.0.0.0:8443
#   sudo ./install.sh --uninstall
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────

BINARY_NAME="shenan-relay"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="shenan-relay"
SERVICE_USER="shenan-relay"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
RENEWAL_HOOK="/etc/letsencrypt/renewal-hooks/deploy/restart-shenan-relay.sh"

DOMAIN=""
BIND="0.0.0.0:443"
UNINSTALL=false

# ── Argument parsing ──────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Options:
  --domain <domain>    Domain name for TLS (e.g. relay.shenan.dev)  [required]
  --bind <addr>        Bind address (default: 0.0.0.0:443)
  --uninstall          Remove the service, user, and renewal hook
  --help               Show this help

Prerequisites on Ubuntu 20.04+:
  # Deploy the shenan-relay binary to /usr/local/bin/shenan-relay first
  # Install certbot and the Route 53 plugin via snap (recommended)
  sudo snap install --classic certbot
  sudo snap set certbot trust-plugin-with-root=ok
  sudo snap install certbot-dns-route53

Examples:
  sudo $0 --domain relay.shenan.dev
  sudo $0 --domain relay.shenan.dev --bind 0.0.0.0:8443
  sudo $0 --uninstall
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)    DOMAIN="$2";    shift 2 ;;
        --bind)      BIND="$2";      shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        --help)      usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────

info() { echo "[shenan-relay] $*"; }
ok()   { echo "[shenan-relay] ✓ $*"; }
die()  { echo "[shenan-relay] error: $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "this script must be run as root (sudo $0)"
}

require_cmd() {
    local cmd="$1"
    local hint="${2:-}"
    if ! command -v "${cmd}" &>/dev/null; then
        if [[ -n "${hint}" ]]; then
            die "'${cmd}' not found — ${hint}"
        else
            die "'${cmd}' not found — please install it first"
        fi
    fi
}

# Find nologin shell portably (Amazon Linux: /sbin/nologin, others: /usr/sbin/nologin)
find_nologin() {
    command -v nologin 2>/dev/null \
        || { [[ -x /sbin/nologin ]] && echo /sbin/nologin; } \
        || { [[ -x /usr/sbin/nologin ]] && echo /usr/sbin/nologin; } \
        || echo /bin/false
}

# Grant the service user read access to letsencrypt dirs.
# Prefers adding the user to the letsencrypt group (certbot creates it).
# Falls back to ACLs, then a restrictive chmod as a last resort.
grant_cert_access() {
    local user="$1"

    if getent group letsencrypt &>/dev/null; then
        usermod -aG letsencrypt "${user}"
        # Ensure the letsencrypt group can read live + archive
        chmod g+rX /etc/letsencrypt/live    2>/dev/null || true
        chmod g+rX /etc/letsencrypt/archive 2>/dev/null || true
        find /etc/letsencrypt/live    -type f -exec chmod g+r {} + 2>/dev/null || true
        find /etc/letsencrypt/archive -type f -exec chmod g+r {} + 2>/dev/null || true
        ok "added ${user} to letsencrypt group"
    elif command -v setfacl &>/dev/null; then
        setfacl -R -m "u:${user}:rX" /etc/letsencrypt/live    2>/dev/null || true
        setfacl -R -m "u:${user}:rX" /etc/letsencrypt/archive 2>/dev/null || true
        ok "granted cert access via ACL"
    else
        # Last resort: make archive world-readable (certs are not secret by themselves;
        # only the private key matters, and it's already mode 600 owned by root)
        chmod o+rX /etc/letsencrypt/live    2>/dev/null || true
        chmod o+rX /etc/letsencrypt/archive 2>/dev/null || true
        find /etc/letsencrypt/archive -name "*.pem" ! -name "privkey*" \
            -exec chmod o+r {} + 2>/dev/null || true
        ok "granted cert access via chmod (install acl for better isolation)"
    fi
}

# ── Uninstall ─────────────────────────────────────────────────────────────────

do_uninstall() {
    info "Uninstalling ${SERVICE_NAME}..."

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl stop "${SERVICE_NAME}"
        ok "service stopped"
    fi

    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl disable "${SERVICE_NAME}"
        ok "service disabled"
    fi

    [[ -f "${SERVICE_FILE}" ]] \
        && rm -f "${SERVICE_FILE}" && ok "removed ${SERVICE_FILE}"
    [[ -f "${RENEWAL_HOOK}" ]] \
        && rm -f "${RENEWAL_HOOK}" && ok "removed ${RENEWAL_HOOK}"

    if id "${SERVICE_USER}" &>/dev/null; then
        userdel "${SERVICE_USER}"
        ok "removed user ${SERVICE_USER}"
    fi

    systemctl daemon-reload
    ok "uninstall complete"
}

# ── Install ───────────────────────────────────────────────────────────────────

do_install() {
    [[ -n "${DOMAIN}" ]] || die "--domain is required"

    require_cmd systemctl
    require_cmd certbot \
        "install via: sudo pip3 install certbot certbot-dns-route53"

    local cert_dir="/etc/letsencrypt/live/${DOMAIN}"
    local cert_file="${cert_dir}/fullchain.pem"
    local key_file="${cert_dir}/privkey.pem"

    # ── Binary check ──────────────────────────────────────────────────────────

    [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]] \
        || die "binary not found at ${INSTALL_DIR}/${BINARY_NAME} — deploy it via CI/CD first"
    ok "binary found at ${INSTALL_DIR}/${BINARY_NAME}"

    # ── Service user ──────────────────────────────────────────────────────────

    local nologin
    nologin="$(find_nologin)"

    if ! id "${SERVICE_USER}" &>/dev/null; then
        useradd --system --no-create-home --shell "${nologin}" "${SERVICE_USER}"
        ok "created system user ${SERVICE_USER} (shell: ${nologin})"
    else
        ok "system user ${SERVICE_USER} already exists"
    fi

    # ── TLS certificate ───────────────────────────────────────────────────────

    if [[ -f "${cert_file}" && -f "${key_file}" ]]; then
        ok "TLS cert already exists at ${cert_dir}"
    else
        info "Obtaining TLS certificate for ${DOMAIN} via certbot (DNS-Route53)..."
        info "  The EC2 instance must have an IAM role with Route 53 write permissions."

        if certbot certonly \
            --dns-route53 \
            --non-interactive \
            --agree-tos \
            --register-unsafely-without-email \
            -d "${DOMAIN}"; then
            ok "TLS certificate obtained"
        else
            echo ""
            echo "  certbot failed. Obtain the cert manually and re-run:"
            echo "    certbot certonly --dns-route53 -d ${DOMAIN}"
            echo ""
            die "TLS certificate could not be obtained"
        fi
    fi

    # Grant service user access to the cert files
    grant_cert_access "${SERVICE_USER}"

    # ── Systemd unit ──────────────────────────────────────────────────────────

    info "Writing systemd service to ${SERVICE_FILE}..."
    cat > "${SERVICE_FILE}" <<UNIT
[Unit]
Description=Shenan protocol relay server
Documentation=https://github.com/shenan
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/${BINARY_NAME} \\
    --tls-cert ${cert_file} \\
    --tls-key  ${key_file} \\
    --bind ${BIND}
Restart=on-failure
RestartSec=5

# Harden the service
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
# Allow binding port 443 as non-root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
    ok "systemd unit written"

    # ── Certbot renewal hook ───────────────────────────────────────────────────

    info "Installing certbot renewal hook..."
    mkdir -p "$(dirname "${RENEWAL_HOOK}")"
    cat > "${RENEWAL_HOOK}" <<'HOOK'
#!/usr/bin/env bash
systemctl restart shenan-relay
HOOK
    chmod +x "${RENEWAL_HOOK}"
    ok "renewal hook installed at ${RENEWAL_HOOK}"

    # ── Enable and start ───────────────────────────────────────────────────────

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"

    echo ""
    ok "shenan-relay is running on ${BIND}"
    ok "TLS cert: ${cert_file}"
    ok "Logs:     journalctl -u ${SERVICE_NAME} -f"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────

require_root

if "${UNINSTALL}"; then
    do_uninstall
else
    do_install
fi
