#!/usr/bin/env bash
# Build, sign, verify, and install the development package in one step.
#
# Every step is one from the README's Installation section, run in order and
# skipped when already done. The signing-key ceremony is one-time setup that is
# easy to half-complete and tedious to repeat, and repeating it is exactly what
# a disposable acceptance system asks for: reset the VM, run this, get a
# verified package installed.
#
# What it will not do by default: edit /etc/pacman.conf or the system pacman
# keyring. The package is verified against its private development key home,
# and the same key home is passed only to the final pacman invocation.
set -euo pipefail
umask 022

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
data_home=${XDG_DATA_HOME:-${HOME:?HOME is required}/.local/share}
# Same resolution order as build-arch-package.sh, so both agree on the key.
key_home=${PROLEWATCH_DEV_GNUPGHOME:-${data_home}/prolewatch/dev-signing-gnupg}
fingerprint_file=${key_home}/fingerprint
dist_dir=${PROLEWATCH_ARCH_DIST_DIR:-${project_dir}/dist/arch}

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf 'dev-install: %s\n' "$1" >&2; exit 1; }

[[ ${EUID} -ne 0 ]] || fail 'run as the normal yay user; makepkg refuses to run as root'
command -v makepkg >/dev/null || fail 'makepkg is missing; install base-devel'

# 1. The local signing key. It authenticates this build artifact to pacman; it
#    establishes nothing about the source it was built from.
if [[ -s ${fingerprint_file} && ! -L ${fingerprint_file} ]]; then
  read -r fingerprint <"${fingerprint_file}"
  step "Signing key already present: ${fingerprint}"
else
  step 'Creating the local development signing key'
  [[ -t 0 && -t 1 ]] || fail 'key generation needs an interactive terminal for pinentry'
  # pinentry-tty, not pinentry-curses. Both ship in the pinentry package, but
  # the curses dialog needs a minimum terminal size and fails with "Screen or
  # window too small" on a small ssh window or a serial console - which is
  # precisely the disposable acceptance system this is meant to be easy on.
  # pinentry-tty is line-based and has no such requirement.
  pinentry=/usr/bin/pinentry-tty
  [[ -x ${pinentry} ]] || pinentry=/usr/bin/pinentry-curses
  install -d -m 0700 "${key_home}"
  printf 'pinentry-program %s\n' "${pinentry}" >"${key_home}/gpg-agent.conf"
  chmod 0600 "${key_home}/gpg-agent.conf"
  GPG_TTY=$(tty)
  export GPG_TTY
  gpgconf --homedir "${key_home}" --kill gpg-agent >/dev/null 2>&1 || true
  gpg --homedir "${key_home}" \
    --quick-generate-key 'Prolewatch local development package' ed25519 sign 1y
  fingerprint=$(gpg --homedir "${key_home}" --with-colons --list-secret-keys |
    awk -F: '/^fpr:/{print $10; exit}')
  [[ ${fingerprint} =~ ^[0-9A-F]{40}$ ]] || fail 'could not read the generated fingerprint'
  printf '%s\n' "${fingerprint}" >"${fingerprint_file}"
  gpg --homedir "${key_home}" --armor --export "${fingerprint}" >"${key_home}/public-key.asc"
  printf 'Created %s\n' "${fingerprint}"
fi

# 2. LocalFileSigLevel is a system-wide policy, not a prerequisite for direct
#    verification. Preserve the old explicit opt-in for administrators who want
#    it, but never make the default installation depend on that choice.
siglevel_ok() {
  local policy
  policy=$(pacman-conf LocalFileSigLevel 2>/dev/null || true)
  [[ ${policy} == *Required* && ${policy} == *TrustedOnly* &&
    ${policy} != *Optional* && ${policy} != *TrustAll* && ${policy} != *Never* ]]
}

if ! siglevel_ok && [[ ${PROLEWATCH_SET_PACMAN_SIGLEVEL:-0} == 1 ]]; then
  step 'Setting LocalFileSigLevel = Required TrustedOnly (needs sudo)'
  if grep -qE '^[[:space:]]*#?[[:space:]]*LocalFileSigLevel' /etc/pacman.conf; then
    sudo sed -i.prolewatch-bak -E \
      's|^[[:space:]]*#?[[:space:]]*LocalFileSigLevel.*|LocalFileSigLevel = Required TrustedOnly|' \
      /etc/pacman.conf
  else
    sudo sed -i.prolewatch-bak \
      '0,/^\[options\]/s//[options]\nLocalFileSigLevel = Required TrustedOnly/' \
      /etc/pacman.conf
  fi
  printf 'Previous file kept at /etc/pacman.conf.prolewatch-bak\n'
  siglevel_ok || fail 'the edit did not take; set LocalFileSigLevel by hand'
fi

step 'Building the signed development package'
"${project_dir}/scripts/build-arch-package.sh"

package=$(find "${dist_dir}" -maxdepth 1 -type f -name 'prolewatch-dev-*.pkg.tar.zst' \
  -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
[[ -n ${package} && -f ${package} ]] || fail "no package found in ${dist_dir}"

step "Verifying ${package##*/}"
"${project_dir}/scripts/verify-arch-package.sh" "${package}"

step 'Installing (needs sudo)'
sudo pacman --gpgdir "${key_home}" -U --noconfirm -- "${package}"

step 'Installed'
cat <<EOF
Next, from a login session with a systemd user manager - a normal TTY, desktop,
or SSH login, not su or sudo -iu:

  prolewatch doctor --no-probe
  prolewatch setup

'prolewatch doctor' without --no-probe additionally spends a hosted-provider
request and renews its attestation. Ollama's longer local assessment is explicit:
'prolewatch doctor --probe-llm-quality'. AI review remains off until the active
provider has a valid stored attestation.
EOF
