#!/usr/bin/env bash
# Run Prolewatch's installed acceptance suite in a disposable Arch Linux VM.
#
# The VM is persistent until `stop` or `reset` is requested, so failed runs can
# be inspected. The first connection asks for the basic image's `arch` password
# once; the SSH control connection carries the remaining commands and prompts.
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
vm_dir=${PROLEWATCH_ACCEPTANCE_VM_DIR:-${XDG_CACHE_HOME:-${HOME:?HOME is required}/.cache}/prolewatch/acceptance-vm}
base_image=${vm_dir}/Arch-Linux-x86_64-basic.qcow2
overlay=${vm_dir}/prolewatch-test.qcow2
pid_file=${vm_dir}/qemu.pid
serial_log=${vm_dir}/serial.log
known_hosts=${vm_dir}/known_hosts
ssh_port=${PROLEWATCH_ACCEPTANCE_SSH_PORT:-2222}
control_socket=${TMPDIR:-/tmp}/prolewatch-acceptance-${UID}-${ssh_port}.sock
image_url=${PROLEWATCH_ACCEPTANCE_IMAGE_URL:-https://fastly.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-basic.qcow2}
guest=arch@localhost
action=${1:-run}

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf 'acceptance-vm: %s\n' "$1" >&2; exit 1; }

case ${ssh_port} in
  ''|*[!0-9]*) fail "invalid SSH port: ${ssh_port}" ;;
esac

ssh_options=(
  -p "${ssh_port}"
  -o "UserKnownHostsFile=${known_hosts}"
  -o StrictHostKeyChecking=accept-new
  -o "ControlPath=${control_socket}"
)

vm_running() {
  [[ -s ${pid_file} ]] || return 1
  local pid
  read -r pid <"${pid_file}"
  [[ ${pid} =~ ^[0-9]+$ ]] && kill -0 "${pid}" 2>/dev/null
}

close_control_connection() {
  ssh "${ssh_options[@]}" -O exit "${guest}" >/dev/null 2>&1 || true
}

wait_for_ssh() {
  step "Waiting for SSH on localhost:${ssh_port}"
  local attempt
  for attempt in $(seq 1 180); do
    if ssh_ready; then
      printf 'SSH is ready.\n'
      return
    fi
    sleep 1
  done
  fail "SSH did not become ready; inspect ${serial_log}"
}

ssh_ready() {
  local banner
  banner=$(timeout 2 bash -c \
    "exec 3<>/dev/tcp/127.0.0.1/${ssh_port}; IFS= read -r -t 1 line <&3; printf '%s' \"\$line\"" \
    2>/dev/null || true)
  [[ ${banner} == SSH-* ]]
}

start_control_connection() {
  if ssh "${ssh_options[@]}" -O check "${guest}" >/dev/null 2>&1; then
    return
  fi
  wait_for_ssh
  rm -f -- "${control_socket}"
  step 'Opening the VM connection (basic-image password: arch)'
  ssh "${ssh_options[@]}" -M -o ControlPersist=10m -fNT "${guest}"
}

start_vm() {
  if vm_running; then
    printf 'Acceptance VM is already running.\n'
    return
  fi
  rm -f -- "${pid_file}"
  step 'Starting the acceptance VM'
  qemu-system-x86_64 \
    -enable-kvm \
    -m "${PROLEWATCH_ACCEPTANCE_VM_MEMORY:-8G}" \
    -smp "${PROLEWATCH_ACCEPTANCE_VM_CPUS:-4}" \
    -drive "file=${overlay},if=virtio" \
    -nic "user,hostfwd=tcp::${ssh_port}-:22" \
    -display none \
    -serial "file:${serial_log}" \
    -pidfile "${pid_file}" \
    -daemonize
}

prepare_images() {
  mkdir -p -- "${vm_dir}"
  if [[ ! -f ${base_image} ]]; then
    step 'Downloading the Arch Linux basic image'
    curl --fail --location --continue-at - --output "${base_image}.part" "${image_url}"
    curl --fail --location --output "${base_image}.SHA256" "${image_url}.SHA256"
    expected=$(awk 'NR == 1 { print $1 }' "${base_image}.SHA256")
    [[ ${expected} =~ ^[[:xdigit:]]{64}$ ]] || fail 'the image checksum response is invalid'
    printf '%s  %s\n' "${expected}" "${base_image}.part" | sha256sum --check --status - ||
      fail "image checksum verification failed; remove ${base_image}.part before retrying"
    mv -- "${base_image}.part" "${base_image}"
  fi
  if [[ ! -f ${overlay} ]]; then
    step 'Creating the disposable VM overlay'
    # Inherit the base image's virtual size. Arch's published image size can
    # change, and a smaller overlay truncates its partition table.
    qemu-img create -f qcow2 -F qcow2 -b "${base_image}" "${overlay}"
  fi
}

prepare_guest() {
  step 'Installing acceptance dependencies'
  ssh -tt "${ssh_options[@]}" "${guest}" \
    'set -euo pipefail
     sudo pacman -Syu --needed --noconfirm base-devel git go jq python bubblewrap rsync
     if ! command -v yay >/dev/null; then
       yay_build=$(mktemp -d "$HOME/yay-bin.XXXXXX")
       trap '\''rm -rf -- "$yay_build"'\'' EXIT
       git clone https://aur.archlinux.org/yay-bin.git "$yay_build"
       (cd "$yay_build" && makepkg -si --noconfirm)
     fi
     if ! grep -q "^$(id -un):" /etc/subuid; then
       sudo usermod --add-subids -- "$(id -un)"
     fi
     mkdir -p "$HOME/tmp"'
}

copy_checkout() {
  step 'Copying the current checkout into the VM'
  local rsync_shell
  printf -v rsync_shell 'ssh -p %q -S %q -o UserKnownHostsFile=%q -o StrictHostKeyChecking=accept-new' \
    "${ssh_port}" "${control_socket}" "${known_hosts}"
  rsync -a --delete \
    --exclude=/build/ \
    --exclude=/dist/ \
    -e "${rsync_shell}" \
    "${project_dir}/" "${guest}:prolewatch/"
}

run_acceptance() {
  step 'Running installed acceptance and the real yay transaction'
  ssh -tt "${ssh_options[@]}" "${guest}" \
    'set -euo pipefail
     cd "$HOME/prolewatch"
     export TMPDIR="$HOME/tmp"
     make dev-install
     prolewatch setup
     prolewatch doctor
     make installed-scenarios
     make acceptance-probes'
}

stop_vm() {
  if ! vm_running; then
    printf 'Acceptance VM is not running.\n'
    return
  fi
  if ssh_ready; then
    start_control_connection
    step 'Shutting down the acceptance VM'
    # OpenSSH may report 255 when the guest closes the connection during
    # shutdown. The QEMU process below is the authoritative completion signal.
    ssh -tt "${ssh_options[@]}" "${guest}" 'sudo poweroff' || true
    close_control_connection
  else
    local pid
    read -r pid <"${pid_file}"
    step 'SSH is unavailable; terminating the disposable VM'
    kill "${pid}" 2>/dev/null || true
  fi
  local attempt
  for attempt in $(seq 1 60); do
    vm_running || {
      printf 'Acceptance VM stopped.\n'
      return
    }
    sleep 1
  done
  fail "VM did not stop within 60 seconds; inspect ${serial_log}"
}

reset_vm() {
  if vm_running; then
    fail "VM is running; use '$0 stop' before reset"
  fi
  rm -f -- "${overlay}" "${pid_file}" "${serial_log}" "${known_hosts}"
  printf 'Removed the VM overlay and its local connection state. The base image was kept.\n'
}

case ${action} in
  run)
    for command in awk curl qemu-img qemu-system-x86_64 rsync sha256sum ssh timeout; do
      command -v "${command}" >/dev/null || fail "host command is missing: ${command}"
    done
    [[ -r /dev/kvm && -w /dev/kvm ]] || fail '/dev/kvm is not accessible to the current user'
    prepare_images
    start_vm
    start_control_connection
    trap close_control_connection EXIT
    prepare_guest
    copy_checkout
    run_acceptance
    step 'Acceptance passed'
    printf 'The VM remains running for inspection. Stop it with:\n  %s stop\n' "$0"
    ;;
  stop)
    for command in ssh timeout; do
      command -v "${command}" >/dev/null || fail "host command is missing: ${command}"
    done
    stop_vm
    ;;
  reset)
    reset_vm
    ;;
  *)
    fail "usage: $0 [run|stop|reset]"
    ;;
esac
