package audit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var keyRE = regexp.MustCompile(`^[0-9A-Fa-f]{16,40}$`)

var gpgSandboxBinary = "/usr/bin/bwrap"

func ValidateGPGArguments(args []string) (string, []string, error) {
	if len(args) < 2 || (args[0] != "--list-keys" && args[0] != "--recv-keys") {
		return "", nil, fmt.Errorf("only yay key listing and receiving operations are supported")
	}
	if args[0] == "--list-keys" && len(args) != 2 {
		return "", nil, fmt.Errorf("--list-keys requires exactly one fingerprint")
	}
	keys := args[1:]
	if len(keys) > 64 {
		return "", nil, fmt.Errorf("too many PGP keys")
	}
	for index, key := range keys {
		if !keyRE.MatchString(key) {
			return "", nil, fmt.Errorf("PGP keys must be 16-40 hexadecimal fingerprint characters")
		}
		keys[index] = strings.ToUpper(key)
	}
	return args[0], keys, nil
}
func GPGSandboxCommand(keyring, action string, keys []string) []string {
	args := []string{"--die-with-parent", "--new-session", "--unshare-all", "--share-net", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--dir", "/etc", "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf", "--ro-bind-try", "/etc/hosts", "/etc/hosts", "--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf", "--ro-bind-try", "/etc/ssl", "/etc/ssl", "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/run", "--tmpfs", "/tmp", "--tmpfs", "/home", "--tmpfs", "/root", "--dir", "/gnupg", "--bind", keyring, "/gnupg", "--clearenv", "--setenv", "HOME", "/tmp", "--setenv", "GNUPGHOME", "/gnupg", "--setenv", "PATH", "/usr/bin", "/usr/bin/gpg", "--batch", "--homedir", "/gnupg", action}
	return append(args, keys...)
}
func RunGPG(args []string) int {
	action, keys, err := ValidateGPGArguments(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prolewatch-gpg:", err)
		return 20
	}
	keyring := filepath.Join(StateRoot(), "gnupg-public")
	if err := EnsurePrivateDir(keyring); err != nil {
		fmt.Fprintln(os.Stderr, "prolewatch-gpg:", err)
		return 20
	}
	command := exec.Command(gpgSandboxBinary, GPGSandboxCommand(keyring, action, keys)...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = []string{"PATH=/usr/bin", "LANG=" + valueOr(os.Getenv("LANG"), "C.UTF-8")}
	if err := command.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "prolewatch-gpg:", err)
		return 24
	}
	return 0
}
