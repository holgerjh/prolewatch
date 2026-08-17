#!/bin/bash
set -euo pipefail
export PATH=/usr/bin

style_reset=
style_bold=
style_dim=
style_green=
style_yellow=
style_blue=
style_red=
style_muted=
error_reset=
error_style=
brand_enabled=false
glyph_anchor='#'
glyph_bullet='*'
glyph_branch='\-'
glyph_separator='-'
glyph_code='|'

configure_terminal() {
  style_reset= style_bold= style_dim= style_green= style_yellow= style_blue= style_red= style_muted=
  error_reset= error_style=
  brand_enabled=false
  glyph_anchor='#' glyph_bullet='*' glyph_branch='\-' glyph_separator='-' glyph_code='|'
  if [[ ${terminal_style} != brand || ! -t 1 || ${TERM:-dumb} == dumb ]]; then
    return
  fi
  brand_enabled=true
  if [[ ${LC_ALL:-${LC_CTYPE:-${LANG:-}}} =~ ([Uu][Tt][Ff]-?8) ]]; then
    glyph_anchor='◆' glyph_bullet='•' glyph_branch='└─' glyph_separator='·' glyph_code='│'
  fi
  if [[ -z ${NO_COLOR+x} ]]; then
    style_reset=$'\033[0m'
    style_bold=$'\033[1m'
    style_dim=$'\033[2m'
    if [[ ${COLORTERM:-} == truecolor || ${COLORTERM:-} == 24bit || ${TERM:-} == *direct* ]]; then
      style_green=$'\033[38;2;120;170;130m'
      style_yellow=$'\033[38;2;208;163;91m'
      style_blue=$'\033[38;2;23;147;209m'
      style_red=$'\033[1;38;2;224;90;95m'
      style_muted=$'\033[38;2;170;162;154m'
    elif [[ ${TERM:-} == *256color* ]]; then
      style_green=$'\033[38;5;108m'
      style_yellow=$'\033[38;5;179m'
      style_blue=$'\033[38;5;32m'
      style_red=$'\033[1;38;5;167m'
      style_muted=$'\033[38;5;145m'
    else
      style_green=$'\033[32m'
      style_yellow=$'\033[33m'
      style_blue=$'\033[36m'
      style_red=$'\033[1;31m'
      style_muted=$'\033[2m'
    fi
  fi
  if [[ -t 2 && -n ${style_red} ]]; then
    error_reset=${style_reset}
    error_style=${style_red}
  fi
}

print_usage() {
  printf '%s\n' \
    'Usage: sudo ./scripts/install-system.sh [options]' \
    '' \
    'Options:' \
    '  --review-mode MODE   Select ai or deterministic-only review mode.' \
	'  --minimum-confidence LEVEL  Require low, medium, or high AI confidence.' \
    '  --provider PROVIDER  Seed codex or anthropic on a new installation.' \
	'  --terminal-style STYLE  Select brand or plain terminal presentation.' \
    '  --update-clean-root  Create a new shared clean-root generation.' \
    '  -y, --assume-yes     Skip confirmation and permit non-interactive use.' \
    '  -h, --help           Show this help and exit.'
}

usage() {
  local status=${1:-1}
  if (( status == 0 )); then
    print_usage
  else
    print_usage >&2
  fi
  exit "${status}"
}

error() {
  printf '%sError:%s %s\n' "${error_style}" "${error_reset}" "$*" >&2
}

die() {
  error "$*"
  exit 1
}

print_banner() {
  if [[ ${brand_enabled} == true ]]; then
    printf '%s%s%s %sPROLEWATCH%s %s%s SYSTEM INSTALLER%s\n' "${style_blue}" "${glyph_anchor}" "${style_reset}" "${style_bold}" "${style_reset}" "${style_dim}" "${glyph_separator}" "${style_reset}"
    printf '%s%s%s review and containment for AUR builds\n' "${style_dim}" "${glyph_branch}" "${style_reset}"
  else
    printf 'PROLEWATCH - SYSTEM INSTALLER\n'
  fi
}

section() {
  if [[ ${brand_enabled} == true ]]; then
    printf '\n%s%s%s %s%s/4 %s %s%s\n' "${style_blue}" "${glyph_anchor}" "${style_reset}" "${style_bold}" "$1" "${glyph_separator}" "$2" "${style_reset}"
  else
    printf '\n== [%s/4] %s ==\n' "$1" "$2"
  fi
}

subheading() {
  if [[ ${brand_enabled} == true ]]; then
    printf '\n%s%s%s %s%s%s\n' "${style_blue}" "${glyph_anchor}" "${style_reset}" "${style_bold}" "$*" "${style_reset}"
  else
    printf '\n%s\n' "$*"
  fi
}

bullet() {
  printf '  %s%s%s %s\n' "${style_muted}" "${glyph_bullet}" "${style_reset}" "$*"
}

detail() {
  if [[ ${brand_enabled} == true ]]; then
    printf '    %s%s%s %s\n' "${style_muted}" "${glyph_branch}" "${style_reset}" "$*"
  else
    printf '    %s\n' "$*"
  fi
}

warning() {
  printf '  %s%s [ HOLD ]%s %s\n' "${style_yellow}" "${glyph_anchor}" "${style_reset}" "$*"
}

success() {
  printf '  %s%s%s %s  %s[ READY ]%s\n' "${style_green}" "${glyph_bullet}" "${style_reset}" "$*" "${style_green}" "${style_reset}"
}

next_step() {
  printf '  %s%s NEXT%s %s%s%s %s%s%s %s\n' \
    "${style_yellow}" "${glyph_anchor}" "${style_reset}" \
    "${style_bold}" "$1" "${style_reset}" \
    "${style_muted}" "${glyph_separator}" "${style_reset}" "$2"
}

run_with_spinner() {
  local label=$1
  local command_display=$2
  shift 2
  if [[ ${brand_enabled} != true || ! -t 1 || ${TERM:-dumb} == dumb ]]; then
    bullet "${label}: ${command_display}"
    "$@"
    return
  fi

  active_step_log=$(mktemp /tmp/prolewatch-install-step.XXXXXX)
  "$@" >"${active_step_log}" 2>&1 &
  active_step_pid=$!
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  if [[ ${glyph_anchor} == '#' ]]; then
    frames=('-' '\' '|' '/')
  fi
  local frame=0
  while kill -0 "${active_step_pid}" 2>/dev/null; do
    printf '\r\033[2K  %s%s%s %s%s%s  %s%s%s' \
      "${style_bold}" "${style_blue}" "${frames[frame]}" \
      "${style_bold}" "${label}" "${style_reset}" \
      "${style_dim}" "${command_display}" "${style_reset}"
    frame=$(( (frame + 1) % ${#frames[@]} ))
    sleep 0.1
  done

  local command_status=0
  wait "${active_step_pid}" || command_status=$?
  active_step_pid=
  printf '\r\033[2K'
  if (( command_status != 0 )); then
    error "${label} failed (exit status ${command_status}): ${command_display}"
    if [[ -s ${active_step_log} ]]; then
      sed 's/^/    /' "${active_step_log}" >&2
    fi
    rm -f -- "${active_step_log}"
    active_step_log=
    return "${command_status}"
  fi
  success "${label}"
  if [[ -s ${active_step_log} ]]; then
    sed 's/^/    /' "${active_step_log}"
  fi
  rm -f -- "${active_step_log}"
  active_step_log=
}

code_block_start() {
  printf '  %s+-- %s%s\n' "${style_dim}" "$*" "${style_reset}"
}

code_line() {
  printf '  %s|%s %s%s%s\n' "${style_dim}" "${style_reset}" "${style_bold}" "$*" "${style_reset}"
}

copy_command() {
  local line
  for line in "$@"; do
    printf '    %s%s%s %s%s%s\n' "${style_muted}" "${glyph_code}" "${style_reset}" "${style_bold}" "${line}" "${style_reset}"
  done
}

code_block_end() {
  printf '  %s+--------------------------------------------------------------%s\n' "${style_dim}" "${style_reset}"
}

provider=codex
review_mode=ai
review_mode_set=false
minimum_confidence=high
minimum_confidence_set=false
terminal_style=brand
terminal_style_set=false
update_clean_root=false
assume_yes=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --review-mode)
      [[ $# -ge 2 ]] || usage
      review_mode=$2
      review_mode_set=true
      shift 2
      ;;
    --provider)
      [[ $# -ge 2 ]] || usage
      provider=$2
      shift 2
      ;;
	--minimum-confidence)
	  [[ $# -ge 2 ]] || usage
	  minimum_confidence=$2
	  minimum_confidence_set=true
	  shift 2
	  ;;
	--terminal-style)
	  [[ $# -ge 2 ]] || usage
	  terminal_style=$2
	  terminal_style_set=true
	  shift 2
	  ;;
    --update-clean-root)
      update_clean_root=true
      shift
      ;;
    -y|--assume-yes)
      assume_yes=true
      shift
      ;;
    -h|--help)
      usage 0
      ;;
    *)
      usage
      ;;
  esac
done
[[ ${provider} == codex || ${provider} == anthropic ]] || usage
[[ ${review_mode} == ai || ${review_mode} == deterministic-only ]] || usage
[[ ${minimum_confidence} == low || ${minimum_confidence} == medium || ${minimum_confidence} == high ]] || usage
[[ ${terminal_style} == brand || ${terminal_style} == plain ]] || usage
configure_terminal
print_banner
section 1 "Preflight"
if [[ ${EUID} -ne 0 ]]; then
  die "Run this installer with sudo."
fi
if [[ ${assume_yes} == false && ( ! -t 0 || ! -t 2 ) ]]; then
  die "Run interactively with sudo, or pass --assume-yes for reviewed automation."
fi

install_user=${SUDO_USER:-}
if [[ -z ${install_user} || ${install_user} == root || ! ${install_user} =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  die "Cannot identify the non-root user who invoked sudo."
fi
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
config_tmp=
sudoers_tmp=
sandbox_sentinel=
active_step_pid=
active_step_log=
cleanup() {
  if [[ -n ${active_step_pid} ]]; then
    kill "${active_step_pid}" 2>/dev/null || true
    wait "${active_step_pid}" 2>/dev/null || true
  fi
  [[ -z ${config_tmp} ]] || rm -f -- "${config_tmp}"
  [[ -z ${sudoers_tmp} ]] || rm -f -- "${sudoers_tmp}"
  [[ -z ${sandbox_sentinel} ]] || rm -f -- "${sandbox_sentinel}"
  [[ -z ${active_step_log} ]] || rm -f -- "${active_step_log}"
}
trap cleanup EXIT

requirements=(
  "bash:bash sh"
  "bubblewrap:bwrap"
  "coreutils:chmod cmp cp date dirname id install mktemp rm sleep stat"
  "devtools:mkarchroot"
  "findutils:find"
  "gnupg:gpg"
  "libarchive:bsdtar"
  "pacman:makepkg pacman pacman-conf"
  "sed:sed"
  "sudo:sudo visudo"
  "systemd:systemctl systemd-run"
  "yay:yay"
)
missing=()
for requirement in "${requirements[@]}"; do
  package=${requirement%%:*}
  read -r -a commands <<<"${requirement#*:}"
  for command in "${commands[@]}"; do
    [[ -x /usr/bin/${command} ]] || missing+=("${command} (${package})")
  done
done
if (( ${#missing[@]} )); then
  error "Missing required commands (Arch package):"
  printf '  %s\n' "${missing[@]}" >&2
  echo "Install the listed official packages with pacman; yay is installed separately from the AUR." >&2
  exit 1
fi
id "${install_user}" &>/dev/null || die "The invoking user does not exist: ${install_user}"

sandbox_sentinel=$(mktemp /run/prolewatch-install-sentinel.XXXXXX)
if ! /usr/bin/bwrap \
  --die-with-parent --new-session --unshare-all --unshare-user \
  --disable-userns --assert-userns-disabled \
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib /lib64 \
  --proc /proc --dev /dev --tmpfs /run --tmpfs /tmp --clearenv \
  /usr/bin/sh -c 'test ! -e "$1" && test ! -e /run/systemd && test ! -e /run/dbus && : > /run/prolewatch-canary' sh "${sandbox_sentinel}"; then
  die "Bubblewrap cannot establish the required private user, mount, PID, network, and /run boundary."
fi
rm -f -- "${sandbox_sentinel}"
sandbox_sentinel=

public_binaries=(prolewatch prolewatch-makepkg prolewatch-gpg prolewatch-net)
common_dispatchers=(prolewatch-build-dispatch)
for binary in "${public_binaries[@]}" "${common_dispatchers[@]}"; do
  [[ -f ${project_dir}/build/${binary} && -x ${project_dir}/build/${binary} && ! -L ${project_dir}/build/${binary} ]] || {
    die "Missing or unsafe build/${binary}. Run 'make build' as your normal user first."
  }
done
fingerprint_script=${project_dir}/scripts/source-fingerprint.sh
fingerprint_file=${project_dir}/build/.source-fingerprint
[[ -f ${fingerprint_script} && -x ${fingerprint_script} && ! -L ${fingerprint_script} ]] || {
  die "Missing or unsafe scripts/source-fingerprint.sh."
}
[[ -f ${fingerprint_file} && ! -L ${fingerprint_file} ]] || {
  die "Build provenance is missing. Run 'make build' as your normal user first."
}
expected_source_fingerprint=$("${fingerprint_script}") || die "Cannot fingerprint the current source tree."
read -r built_source_fingerprint <"${fingerprint_file}" || die "Cannot read build provenance."
if [[ ! ${built_source_fingerprint} =~ ^[0-9a-f]{64}$ || ${built_source_fingerprint} != "${expected_source_fingerprint}" ]]; then
  die "Build binaries are older than or do not match this checkout. Run 'make build' as your normal user first."
fi
unset expected_source_fingerprint built_source_fingerprint fingerprint_file fingerprint_script
common_share_files=(default-config.json prolewatch.lua)
for file in "${common_share_files[@]}"; do
  [[ -f ${project_dir}/share/${file} && ! -L ${project_dir}/share/${file} ]] || {
    die "Missing or unsafe share/${file}."
  }
done
config_check_help=$("${project_dir}/build/prolewatch" config-check --help 2>&1 || true)
config_migrate_help=$("${project_dir}/build/prolewatch" config-migrate --help 2>&1 || true)
if [[ ${config_check_help} != *'-terminal-style-only'* || ${config_migrate_help} != *'-terminal-style'* ]]; then
  die "build/prolewatch does not match this checkout. Run 'make build' as your normal user, then run the installer again."
fi
unset config_check_help config_migrate_help

version_at_least() {
  local actual_major=$1 actual_minor=$2 actual_patch=$3
  local minimum_major=$4 minimum_minor=$5 minimum_patch=$6
  (( actual_major > minimum_major
    || (actual_major == minimum_major && actual_minor > minimum_minor)
    || (actual_major == minimum_major && actual_minor == minimum_minor && actual_patch >= minimum_patch) ))
}
version_before() {
  ! version_at_least "$1" "$2" "$3" "$4" "$5" "$6"
}
extract_version() {
  local value=$1
  [[ ${value} =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]] || return 1
  printf '%s %s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
}

read -r yay_major yay_minor yay_patch < <(extract_version "$(/usr/bin/yay --version 2>/dev/null)") || {
  die "Cannot parse yay version."
}
version_at_least "${yay_major}" "${yay_minor}" "${yay_patch}" 13 0 1 || {
  die "yay 13.0.1 or newer is required."
}

managed_dirs=(
  /etc/prolewatch
  /usr/libexec/prolewatch
  /usr/share/prolewatch
  /var/lib/prolewatch
  /var/lib/prolewatch/providers
  /var/lib/prolewatch/providers/codex
  /var/lib/prolewatch/providers/anthropic
  /var/lib/prolewatch/build-roots
  /var/lib/prolewatch/build-roots/generations
  /var/lib/prolewatch/build-jobs
  /var/lib/prolewatch/artifact-pool
)
for managed_dir in "${managed_dirs[@]}"; do
  if [[ -L ${managed_dir} || ( -e ${managed_dir} && ! -d ${managed_dir} ) ]]; then
    die "Refusing unsafe managed directory: ${managed_dir}"
  fi
done
for managed_file in /etc/prolewatch/config.json /etc/sudoers.d/prolewatch /var/lib/prolewatch/build-roots/active.json; do
  if [[ -L ${managed_file} || ( -e ${managed_file} && ! -f ${managed_file} ) ]]; then
    die "Refusing unsafe managed file: ${managed_file}"
  fi
done

account_exists=false

config_tmp=$(mktemp /tmp/prolewatch-config.XXXXXX)
config_action=new
config_path=/etc/prolewatch/config.json
if [[ ! -e ${config_path} ]]; then
  sed -e "0,/\"provider\": \"codex\"/s//\"provider\": \"${provider}\"/" \
      -e "0,/\"mode\": \"ai\"/s//\"mode\": \"${review_mode}\"/" \
	  -e "0,/\"minimum_confidence\": \"high\"/s//\"minimum_confidence\": \"${minimum_confidence}\"/" \
	  -e "0,/\"style\": \"brand\"/s//\"style\": \"${terminal_style}\"/" \
      "${project_dir}/share/default-config.json" >"${config_tmp}"
else
  if [[ ! -f ${config_path} || $(stat -c %u "${config_path}") -ne 0 || $((8#$(stat -c %a "${config_path}") & 8#022)) -ne 0 ]]; then
    die "Existing config.json must be a root-owned regular file that is not group/world writable."
  fi
  migrate_args=(config-migrate --path "${config_path}")
  if [[ ${review_mode_set} == true ]]; then
    migrate_args+=(--review-mode "${review_mode}")
  fi
	if [[ ${minimum_confidence_set} == true ]]; then
	  migrate_args+=(--minimum-confidence "${minimum_confidence}")
	fi
	if [[ ${terminal_style_set} == true ]]; then
	  migrate_args+=(--terminal-style "${terminal_style}")
	fi
  "${project_dir}/build/prolewatch" "${migrate_args[@]}" >"${config_tmp}"
  config_action=unchanged
  cmp -s "${config_path}" "${config_tmp}" || config_action=migrate
fi
"${project_dir}/build/prolewatch" config-check --path "${config_tmp}"
active_provider=$("${project_dir}/build/prolewatch" config-check --provider-only --path "${config_tmp}")
review_mode=$("${project_dir}/build/prolewatch" config-check --review-mode-only --path "${config_tmp}")
minimum_confidence=$("${project_dir}/build/prolewatch" config-check --minimum-confidence-only --path "${config_tmp}")
unsafe_overrides=$("${project_dir}/build/prolewatch" config-check --unsafe-overrides-only --path "${config_tmp}")
configured_terminal_style=$("${project_dir}/build/prolewatch" config-check --terminal-style-only --path "${config_tmp}")
if [[ ${active_provider} != ${provider} ]]; then
  warning "Existing configuration selects '${active_provider}'; --provider only seeds new installations."
fi
if [[ ${unsafe_overrides} == true ]]; then
  warning "UNSAFE overrides are enabled in the installed configuration. Explicit BYPASS can continue without a positive security decision."
fi
if [[ ${configured_terminal_style} != ${terminal_style} ]]; then
  warning "Existing configuration keeps terminal style '${configured_terminal_style}'; --terminal-style only changes it when explicitly supplied."
fi
provider=${active_provider}

if [[ ${review_mode} == ai ]]; then
  for command in getent useradd nologin; do
    [[ -x /usr/bin/${command} ]] || die "AI review mode requires /usr/bin/${command}."
  done
  for file in provider-dispatch; do
    [[ -f ${project_dir}/build/${file} && -x ${project_dir}/build/${file} && ! -L ${project_dir}/build/${file} ]] || {
      die "Missing or unsafe build/${file}. Run 'make build' as your normal user first."
    }
  done
  for file in review-prompt.md verdict.schema.json; do
    [[ -f ${project_dir}/share/${file} && ! -L ${project_dir}/share/${file} ]] || {
      die "Missing or unsafe share/${file}."
    }
  done
  if id prolewatch &>/dev/null; then
    account_record=$(getent passwd prolewatch) || die "Cannot read the existing prolewatch account."
    IFS=: read -r _ _ _ _ _ audit_home audit_shell <<<"${account_record}"
    [[ ${audit_home} == /var/lib/prolewatch && ${audit_shell} == /usr/bin/nologin ]] || {
      die "Existing prolewatch account has an unexpected home or shell."
    }
    account_exists=true
  fi
fi

if [[ ${review_mode} == ai && ${provider} == codex ]]; then
  [[ -x /usr/bin/codex ]] || die "Install the Arch openai-codex package first."
  read -r major minor patch < <(extract_version "$(/usr/bin/codex --version 2>/dev/null)") || die "Cannot parse Codex version."
  version_at_least "${major}" "${minor}" "${patch}" 0 146 1 && version_before "${major}" "${minor}" "${patch}" 0 147 0 || {
    die "Codex CLI >=0.146.1 and <0.147.0 is required."
  }
elif [[ ${review_mode} == ai ]]; then
  [[ -x /usr/bin/claude ]] || die "Install Claude Code >=2.1.205 and <3.0.0 first."
  read -r major minor patch < <(extract_version "$(/usr/bin/claude --version 2>/dev/null)") || die "Cannot parse Claude Code version."
  version_at_least "${major}" "${minor}" "${patch}" 2 1 205 && version_before "${major}" "${minor}" "${patch}" 3 0 0 || {
    die "Claude Code >=2.1.205 and <3.0.0 is required."
  }
fi

sudoers_tmp=$(mktemp /tmp/prolewatch-sudoers.XXXXXX)
printf '%s ALL=(root) NOPASSWD: /usr/libexec/prolewatch/build-dispatch ""\n' "${install_user}" >"${sudoers_tmp}"
if [[ ${review_mode} == ai ]]; then
  printf '%s ALL=(prolewatch) NOPASSWD: /usr/libexec/prolewatch/provider-dispatch ""\n' "${install_user}" >>"${sudoers_tmp}"
fi
chmod 0440 "${sudoers_tmp}"
visudo -cf "${sudoers_tmp}"

clean_root_action=status
clean_root_summary="Reuse the active root-owned base-devel clean root."
if [[ ! -e /var/lib/prolewatch/build-roots/active.json ]]; then
  clean_root_action=init
  clean_root_summary="Initialize a root-owned base-devel clean root."
elif [[ ${update_clean_root} == true ]]; then
  clean_root_action=update
  clean_root_summary="Create a new root-owned base-devel clean-root generation."
fi

success "Preflight checks passed."
section 2 "Plan"
case ${config_action} in
  new) config_summary="create the system configuration" ;;
  migrate) config_summary="migrate the system configuration with a timestamped backup" ;;
  unchanged) config_summary="keep the existing system configuration" ;;
esac
bullet "Install root-owned binaries and policy files; ${config_summary}."
if [[ ${review_mode} == ai ]]; then
  bullet "Mode: AI review via ${provider} as the locked prolewatch user."
else
  bullet "Mode: deterministic-only review."
fi
bullet "${clean_root_summary}"
bullet "Provider login and the user's yay configuration stay untouched."

subheading "Passwordless sudo rules"
code_block_start "/etc/sudoers.d/prolewatch"
code_line "${install_user} ALL=(root) NOPASSWD: /usr/libexec/prolewatch/build-dispatch \"\""
if [[ ${review_mode} == ai ]]; then
  code_line "${install_user} ALL=(prolewatch) NOPASSWD: /usr/libexec/prolewatch/provider-dispatch \"\""
fi
code_block_end

subheading "Security boundaries"
if [[ ${review_mode} == ai ]]; then
  bullet "AI requests use the locked prolewatch user and a bounded dispatcher."
fi
bullet "Root dispatcher: caller-bound roots and content-addressed artifacts; no package code."
bullet "AUR staging: Bubblewrap-isolated; AUR scriptlets and custom or transaction hooks disabled."
bullet "Repository packages keep pacman verification and hooks; fingerprints only scope cache reuse."

if [[ ${assume_yes} == true ]]; then
  printf '\n'
  warning "Confirmation skipped because --assume-yes was provided."
else
  printf '\n'
  read -r -p "${style_yellow}${glyph_anchor} CONFIRM${style_reset} ${style_bold}Type INSTALL to continue:${style_reset} " confirmation
  if [[ ${confirmation} != INSTALL ]]; then
    warning "Cancelled."
    exit 1
  fi
fi

section 3 "Installing"

bullet "Installing root-owned binaries and policy files."

if [[ ${review_mode} == ai && ${account_exists} == false ]]; then
  useradd --system --home-dir /var/lib/prolewatch --create-home --shell /usr/bin/nologin prolewatch
fi

for binary in "${public_binaries[@]}"; do
  install -o root -g root -m 0755 "${project_dir}/build/${binary}" "/usr/bin/${binary}"
done
install -d -o root -g root -m 0755 /usr/libexec/prolewatch
install -o root -g root -m 0755 "${project_dir}/build/prolewatch-build-dispatch" /usr/libexec/prolewatch/build-dispatch
install -d -o root -g root -m 0755 /usr/share/prolewatch
for file in "${common_share_files[@]}"; do
  install -o root -g root -m 0644 "${project_dir}/share/${file}" "/usr/share/prolewatch/${file}"
done
if [[ ${review_mode} == ai ]]; then
  install -o root -g root -m 0755 "${project_dir}/build/provider-dispatch" /usr/libexec/prolewatch/provider-dispatch
  for file in review-prompt.md verdict.schema.json; do
    install -o root -g root -m 0644 "${project_dir}/share/${file}" "/usr/share/prolewatch/${file}"
  done
else
  rm -f -- /usr/libexec/prolewatch/provider-dispatch /usr/share/prolewatch/review-prompt.md /usr/share/prolewatch/verdict.schema.json
fi

install -d -o root -g root -m 0755 /etc/prolewatch
if [[ ${config_action} == migrate ]]; then
  config_backup="/etc/prolewatch/config.json.backup-$(date -u +%Y%m%dT%H%M%SZ)"
  install -o root -g root -m 0600 "${config_path}" "${config_backup}"
  bullet "Migrated configuration; backup: ${config_backup}"
fi
if [[ ${config_action} != unchanged ]]; then
  install -o root -g root -m 0644 "${config_tmp}" "${config_path}"
fi

install -d -o root -g root -m 0711 /var/lib/prolewatch
if [[ ${review_mode} == ai ]]; then
  install -d -o prolewatch -g prolewatch -m 0700 /var/lib/prolewatch/providers
  install -d -o prolewatch -g prolewatch -m 0700 /var/lib/prolewatch/providers/codex
  install -d -o prolewatch -g prolewatch -m 0700 /var/lib/prolewatch/providers/anthropic
fi
install -o root -g root -m 0440 "${sudoers_tmp}" /etc/sudoers.d/prolewatch

case ${clean_root_action} in
  init)
    detail "mkarchroot now downloads and installs base-devel; the first run can take several minutes."
    run_with_spinner "Creating clean-root generation" "/usr/bin/prolewatch clean-root init" /usr/bin/prolewatch clean-root init
    ;;
  update)
    detail "mkarchroot now downloads and installs the current base-devel generation."
    run_with_spinner "Updating clean-root generation" "/usr/bin/prolewatch clean-root update" /usr/bin/prolewatch clean-root update
    ;;
  status)
    run_with_spinner "Checking clean-root generation" "/usr/bin/prolewatch clean-root status" /usr/bin/prolewatch clean-root status
    ;;
esac

section 4 "Complete"
if [[ ${review_mode} == ai ]]; then
  success "System components installed in AI review mode."
  printf '\n'
  if [[ ${provider} == codex ]]; then
    next_step "1/3" "Authenticate Codex as the locked prolewatch account."
    detail "Copy and run this command block:"
    copy_command \
      "sudo -u prolewatch env \\" \
      "  HOME=/var/lib/prolewatch/providers/codex \\" \
      "  CODEX_HOME=/var/lib/prolewatch/providers/codex \\" \
      "  /usr/bin/codex login --device-auth"
  else
    next_step "1/3" "Authenticate Anthropic as the locked prolewatch account."
    detail "Copy and run this command block:"
    copy_command \
      "sudo -u prolewatch env \\" \
      "  HOME=/var/lib/prolewatch/providers/anthropic \\" \
      "  CLAUDE_CONFIG_DIR=/var/lib/prolewatch/providers/anthropic \\" \
      "  /usr/bin/claude auth login"
  fi
  detail "This keeps provider credentials separate from your normal user account."
  printf '\n'
  next_step "2/3" "Return to ${install_user} and connect Prolewatch to yay."
else
  success "System components installed in deterministic-only mode."
  detail "No provider login is required in deterministic-only mode."
  printf '\n'
  next_step "1/2" "Return to ${install_user} and connect Prolewatch to yay."
fi
detail "Copy and run:"
copy_command "prolewatch install-hook"
detail "install-hook adds the managed Prolewatch integration to your yay configuration."
printf '\n'
if [[ ${review_mode} == ai ]]; then
  next_step "3/3" "Verify the complete installation and provider boundary."
else
  next_step "2/2" "Verify the complete deterministic installation."
fi
detail "Copy and run:"
copy_command "prolewatch doctor"
if [[ ${review_mode} == ai ]]; then
  detail "doctor performs one isolated provider probe and may consume a small amount of quota."
  detail "This step is required after installation or updates; AI gates stay fail-closed until doctor renews the provider attestation."
else
  detail "doctor verifies the local sandbox and clean-root boundary without a provider request."
fi
if [[ ${review_mode} == deterministic-only ]]; then
  bullet "Re-run this installer with --review-mode ai to enable AI review."
fi
