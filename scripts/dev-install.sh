#!/usr/bin/env bash
# Build, sign, verify, and install the development package in one step.
#
# Every step is one from the README's Installation section, run in order and
# skipped when already done. The signing-key ceremony is one-time setup that is
# easy to half-complete and tedious to repeat, and repeating it is exactly what
# a disposable acceptance system asks for: reset the VM, run this, get a
# verified package installed.
#
# What it will not do: edit /etc/pacman.conf. LocalFileSigLevel is a system
# trust policy, and a script that quietly relaxes the check that makes its own
# output trustworthy has defeated the point. It reports and stops instead.
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

# 2. Trust it in the pacman keyring. Local to this machine, and the reason
#    pacman will accept the package built below.
if sudo pacman-key --list-keys "${fingerprint}" >/dev/null 2>&1; then
  step 'Key already trusted by the pacman keyring'
else
  step 'Trusting the key in the pacman keyring (needs sudo)'
  [[ -f ${key_home}/public-key.asc ]] ||
    gpg --homedir "${key_home}" --armor --export "${fingerprint}" >"${key_home}/public-key.asc"
  sudo pacman-key --add "${key_home}/public-key.asc"
  sudo pacman-key --lsign-key "${fingerprint}"
fi

# 3. Fail here rather than after a full build. Same condition
#    verify-arch-package.sh enforces, checked before spending the time.
siglevel_ok() {
  local policy
  policy=$(pacman-conf LocalFileSigLevel 2>/dev/null || true)
  [[ ${policy} == *Required* && ${policy} == *TrustedOnly* &&
    ${policy} != *Optional* && ${policy} != *TrustAll* && ${policy} != *Never* ]]
}

if ! siglevel_ok; then
  # Note the direction: stock Arch ships LocalFileSigLevel = Optional, which
  # installs an unsigned local package without complaint. Required TrustedOnly
  # is strictly tighter, and it is what makes the signature created above mean
  # anything at all. This still is not done silently - it is a system-wide
  # policy affecting every later `pacman -U`, so it is the administrator's call.
  printf 'Pacman does not require trusted signatures for local files: %s\n\n' \
    "$(pacman-conf LocalFileSigLevel 2>/dev/null | tr '\n' ' ')" >&2
  if [[ ${PROLEWATCH_SET_PACMAN_SIGLEVEL:-0} == 1 ]]; then
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
  else
    cat >&2 <<'HINT'
This tightens the system rather than relaxing it: the default accepts unsigned
local packages, and Required TrustedOnly is what makes a signature mean
anything. It affects every later `pacman -U`, so it is not changed for you
unless you ask.

Either edit /etc/pacman.conf by hand:

  LocalFileSigLevel = Required TrustedOnly

or re-run and let this do it, keeping a backup beside the original:

  PROLEWATCH_SET_PACMAN_SIGLEVEL=1 make dev-install

HINT
    fail 'refusing to build a package pacman would install unverified'
  fi
fi

step 'Building the signed development package'
"${project_dir}/scripts/build-arch-package.sh"

package=$(find "${dist_dir}" -maxdepth 1 -type f -name 'prolewatch-dev-*.pkg.tar.zst' \
  -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
[[ -n ${package} && -f ${package} ]] || fail "no package found in ${dist_dir}"

step "Verifying ${package##*/}"
"${project_dir}/scripts/verify-arch-package.sh" "${package}"

step 'Installing (needs sudo)'
sudo pacman -U --noconfirm -- "${package}"

step 'Installed'
cat <<EOF
Next, from a login session with a systemd user manager - a normal TTY, desktop,
or SSH login, not su or sudo -iu:

  prolewatch doctor --no-probe
  prolewatch setup

'prolewatch doctor' without --no-probe additionally spends one provider request
and renews the provider attestation, which AI review needs.
EOF
