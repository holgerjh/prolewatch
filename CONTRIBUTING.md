# Contributing to Prolewatch

Security reports, reproducible bug reports, design feedback, and other issue
discussion are welcome. Follow [SECURITY.md](SECURITY.md) for private
vulnerability reporting.

## Contributing code

Prolewatch is `AGPL-3.0-only` and every release stays available under it.

**External code contributions are paused for now.** The licensing arrangement for
outside patches is not settled yet, and merging code before it is settled is the
one decision here that cannot be undone later: once third-party patches are in,
the licence of the combined work cannot be changed again without agreement from
every person who contributed to it. So the pause stays until there is something
concrete to point at rather than an intention.

**Issues need no agreement of any kind.** Bug reports, security reports,
reproductions, and design arguments are often worth more to this project than a
patch, and nothing is asked of you for them.

## What is most useful

The claims in [docs/architecture.md](docs/architecture.md) and
[docs/aur-threat-model.md](docs/aur-threat-model.md) are meant to be checkable.
A patch that shows one of them is wrong is the most valuable thing you can
send, and `scripts/probes/` is where that kind of argument belongs: a claim
about how a tool behaves is a hypothesis until a probe runs, however
confidently anyone can explain the mechanism.

Concretely, the most useful contributions are a build escaping containment, a
prompt that package-controlled output can forge, an approval crossing a
structural finding, a root-execution surface reaching an install unenumerated,
or a documented claim that does not survive measurement. For anything with
security impact, follow [SECURITY.md](SECURITY.md) first.

Run `make release-check` before opening a pull request.

## Development workflow

Use the source tree for the normal edit-test loop:

```bash
go test ./internal/audit      # or the package you changed
make build
make scenarios
```

`make build` writes the four executables to `build/`. This is suitable for
testing code that does not depend on the installed filesystem layout. Run
`make release-check` before committing or after changing a security boundary;
it is the complete local gate used by CI.

Use the signed `prolewatch-dev` package when testing `/usr/bin` payloads,
`doctor`, `setup`, the `yay` hook, or a complete contained transaction.
`make arch-package` deliberately does not create or trust a signing identity.
Create one before the first package build as the normal `yay` user from an
interactive shell; `tty` must print a device path, not `not a tty`.

End-to-end transaction tests also require a reachable systemd user manager,
because the cgroup resource envelope is mandatory. Prefer a real TTY, desktop,
or SSH login and confirm it with `systemctl --user show --property=Version`.
For a dedicated headless test account, follow the README's documented
`loginctl enable-linger` procedure and its security caveats; do not merely
export `XDG_RUNTIME_DIR`. Run `prolewatch doctor --no-probe` in the same kind of
session that will later invoke `yay`.

```bash
dev_key_dir="${XDG_DATA_HOME:-$HOME/.local/share}/prolewatch/dev-signing-gnupg"
install -d -m 0700 "$dev_key_dir"
printf '%s\n' 'pinentry-program /usr/bin/pinentry-tty' \
  > "$dev_key_dir/gpg-agent.conf"
chmod 0600 "$dev_key_dir/gpg-agent.conf"
export GPG_TTY="$(tty)"
gpgconf --homedir "$dev_key_dir" --kill gpg-agent
gpg --homedir "$dev_key_dir" \
  --quick-generate-key "Prolewatch local development package" ed25519 sign 1y
fingerprint="$(gpg --homedir "$dev_key_dir" --with-colons --list-secret-keys \
  | awk -F: '/^fpr:/{print $10; exit}')"
printf '%s\n' "$fingerprint" > "$dev_key_dir/fingerprint"
gpg --homedir "$dev_key_dir" --armor --export "$fingerprint" \
  > "$dev_key_dir/public-key.asc"
sudo pacman-key --add "$dev_key_dir/public-key.asc"
sudo pacman-key --lsign-key "$fingerprint"
```

The verifier also requires `LocalFileSigLevel = Required TrustedOnly` (which
`PROLEWATCH_SET_PACMAN_SIGLEVEL=1 make dev-install` will set, with a backup) in
`/etc/pacman.conf`. These steps match the installation instructions in the
[README](README.md#installation), and `make dev-install` runs all of them,
reusing an existing signing key — which is what makes it usable on a disposable
test system you reset often. Build and install subsequent
development revisions with:

```bash
make arch-package
make verify-arch-package PACKAGE=/absolute/path/to/prolewatch-dev-VERSION-x86_64.pkg.tar.zst
sudo pacman -U -- /absolute/path/to/prolewatch-dev-VERSION-x86_64.pkg.tar.zst
prolewatch setup
make installed-scenarios
```

Use the exact package path printed by `make arch-package`. Editing the checkout
does not update the installed commands; rebuild and reinstall before retesting
installed behavior. Because `setup` changes the invoking user's effective
`yay` configuration, run installed transaction tests on a disposable Arch
system. `prolewatch uninstall-hook` removes the integration afterward.

## End-to-end testing on a disposable Arch system

`setup` rewrites the invoking user's `yay` configuration and the acceptance
probe drives a real transaction, so this does not belong on a machine you care
about. It also cannot be faked: `probe-yay-interception.sh` is the only check
that proves the installed hook and both wrappers actually intercept `yay`,
because everything else in the suite exercises components through seams.

Containers are the wrong tool here. The build needs a systemd user manager,
which requires a real PAM login — `docker exec` does not create one — and
`newuidmap` needs file capabilities containers usually strip. A VM with an SSH
login gets both for nothing, and an acceptance record from a container you had
to grant extra privileges to is weaker evidence than one from a plain VM.

### The VM

Use the **basic** image, not the cloud image: it ships with the user `arch`
(password `arch`) and sshd already running, so there is no cloud-init, no seed
image, and no `cloud-localds`.

```bash
curl -LO https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-basic.qcow2

# the overlay is the disposability: delete it to reset, recreate in a second
qemu-img create -f qcow2 -F qcow2 -b Arch-Linux-x86_64-basic.qcow2 pw.qcow2 20G

qemu-system-x86_64 -enable-kvm -m 8G -smp 4 \
  -drive file=pw.qcow2,if=virtio \
  -nic user,hostfwd=tcp::2222-:22 -nographic
```

Then `ssh arch@localhost -p 2222`. **Use SSH, not the serial console** — that is
what creates the PAM session the resource envelope needs.

The first boot takes a while, and an early SSH looks like a network fault:

```text
kex_exchange_identification: read: Connection reset by peer
```

QEMU's `hostfwd` accepts on the host the moment it starts, so a reset means
sshd is not up in the guest **yet**. Wait; do not debug networking.

### Prerequisites in the guest

```bash
sudo pacman -Syu --needed --noconfirm base-devel git go jq python bubblewrap rsync

# yay is itself an AUR package, so it is built unprotected - the same bootstrap
# gap Prolewatch documents about its own installation
git clone https://aur.archlinux.org/yay-bin.git && (cd yay-bin && makepkg -si)

# the single most likely reason a fresh install fails, and it surfaces deep
# inside someone else's package() as an EINVAL from chown
grep -q "^$(id -un):" /etc/subuid ||
  sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$(id -un)"

# keep the build off tmpfs: /tmp is RAM-backed and the package's own check()
# puts TMPDIR inside the build directory
mkdir -p ~/tmp && export TMPDIR=~/tmp
```

`jq` is a probe prerequisite, not a convenience:
`probe-yay-interception.sh` checks for `yay git jq prolewatch` and skips if any
is missing — and under `make acceptance-probes` a skip is a failure. The VM
also needs outbound HTTPS to GitHub for the probe's checksum-bound source.

### Getting the tree in without pushing

```bash
rsync -a --delete --exclude=/build/ --exclude=/dist/ \
  -e 'ssh -p 2222' /path/to/prolewatch/ arch@localhost:prolewatch/
```

Keep `.git`. `build-arch-package.sh` derives the package version from
`git rev-list --count HEAD` and `git rev-parse`, and `source-archive.sh`
enumerates files with `git ls-files`; without it `make arch-package` fails.
`git bundle create … --all` plus `scp`, or `tar` piped over `ssh`, work when
rsync is not installed on both ends.

### Install and run the gate

```bash
cd ~/prolewatch
make dev-install
prolewatch doctor          # renews the provider attestation; --no-probe skips the request
prolewatch setup
make acceptance-probes
```

`make dev-install` will stop if `LocalFileSigLevel` does not require trusted
signatures. Add `PROLEWATCH_SET_PACMAN_SIGLEVEL=1` to let it make that one
change, keeping the original as `/etc/pacman.conf.prolewatch-bak`. It tightens
the system rather than relaxing it: stock Arch installs unsigned local packages
without complaint.

Run `setup` from a fresh SSH login. `su` and `sudo -iu` may not create the PAM
session even with lingering enabled, and `setup` fails before touching `yay`
when the session cannot enforce the resource envelope.

### The acceptance record

`make acceptance-probes` sets `PROLEWATCH_PROBE_STRICT=1`, under which a
skipped probe is a failure — a probe that never ran is not evidence. Keep the
output as the release record: the command, the package and version, the commit
hash, the `PASS:` line, and the paths of the reports and build log it produced.

Reset between attempts by deleting the overlay and recreating it.

## AI-assisted work

Disclose substantial AI assistance in the pull-request description, including
which parts of the change it materially affected. Review and test all submitted
material yourself and take responsibility for it. AI tools should not be listed
as human co-authors with a `Co-authored-by` trailer.
