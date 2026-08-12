#!/bin/bash
set -euo pipefail
export PATH=/usr/bin

if [[ ${EUID} -ne 0 || ! -t 0 || ! -t 2 ]]; then
  echo "Run interactively with sudo." >&2
  exit 1
fi
echo "This removes installed binaries, shared files, configuration, and the sudoers rule."
echo "The prolewatch home, credentials, reports, quarantine, backups, and user hook are preserved."
echo "Run 'prolewatch uninstall-hook' as the normal yay user before continuing if desired."
read -r -p "Type UNINSTALL to continue: " confirmation
[[ ${confirmation} == UNINSTALL ]] || { echo "Cancelled."; exit 1; }

rm -f -- /usr/bin/prolewatch /usr/bin/prolewatch-makepkg /usr/bin/prolewatch-gpg /usr/bin/prolewatch-net
rm -f -- /usr/libexec/prolewatch/provider-dispatch /usr/libexec/prolewatch/build-dispatch
rm -f -- /etc/sudoers.d/prolewatch /etc/prolewatch/config.json
rm -rf -- /usr/share/prolewatch
rmdir --ignore-fail-on-non-empty /usr/libexec/prolewatch /etc/prolewatch 2>/dev/null || true
echo "System files removed; provider credentials, user state, and the user hook were preserved."
