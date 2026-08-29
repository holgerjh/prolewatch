package audit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const hookBegin = "-- BEGIN prolewatch"
const hookEnd = "-- END prolewatch"
const hookBlock = hookBegin + "\nrequire(\"prolewatch\")\n" + hookEnd + "\n"

func YayConfigDir() string {
	if root := os.Getenv("XDG_CONFIG_HOME"); root != "" {
		return filepath.Join(root, "yay")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "yay")
}

func InstallHook() (string, string, error) {
	// Manage one clearly delimited init.lua block while preserving all unrelated
	// user configuration. Existing modified modules are backed up, never silently
	// overwritten without a recoverable copy.
	config := YayConfigDir()
	if err := os.MkdirAll(config, 0o700); err != nil {
		return "", "", err
	}
	initPath := filepath.Join(config, "init.lua")
	modulePath := filepath.Join(config, "prolewatch.lua")
	for _, candidate := range []string{initPath, modulePath} {
		if info, err := os.Lstat(candidate); err == nil && !info.Mode().IsRegular() {
			return "", "", fmt.Errorf("refusing unsafe yay configuration entry: %s", candidate)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", "", err
		}
	}
	existing, err := os.ReadFile(initPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	text := string(existing)
	if err := validateManagedHook(text, hookBegin, hookEnd); err != nil {
		return "", "", errors.New("existing init.lua contains malformed managed markers")
	}
	updated := append([]byte(nil), existing...)
	if !strings.Contains(string(updated), hookBegin) {
		separator := ""
		if len(updated) > 0 && !bytes.HasSuffix(updated, []byte("\n")) {
			separator = "\n"
		}
		updated = append(updated, []byte(separator+hookBlock)...)
	}
	source := filepath.Join(ShareRoot(), "prolewatch.lua")
	sourceRaw, err := os.ReadFile(source)
	if err != nil {
		return "", "", err
	}
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	if current, err := os.ReadFile(modulePath); err == nil && !bytes.Equal(current, sourceRaw) {
		moduleBackup := filepath.Join(config, "prolewatch.lua.backup-"+timestamp)
		if err := copyRegular(modulePath, moduleBackup, 0o600); err != nil {
			return "", "", err
		}
	}
	if err := atomicUserWrite(modulePath, sourceRaw, 0o600); err != nil {
		return "", "", err
	}
	backup := ""
	if !bytes.Equal(existing, updated) {
		if len(existing) > 0 {
			backup = filepath.Join(config, "init.lua.backup-"+timestamp)
			if err := copyRegular(initPath, backup, 0o600); err != nil {
				return "", "", err
			}
		}
		if err := atomicUserWrite(initPath, updated, 0o600); err != nil {
			return "", "", err
		}
	}
	return modulePath, backup, nil
}

func validateManagedHook(text, begin, end string) error {
	// Exactly one complete marker pair is manageable. Ambiguous/nested fragments
	// are left untouched so an installer cannot delete unrelated Lua text.
	begins, ends := strings.Count(text, begin), strings.Count(text, end)
	if begins == 0 && ends == 0 {
		return nil
	}
	if begins != 1 || ends != 1 || len(managedHookPattern(begin, end).FindAllStringIndex(text, -1)) != 1 {
		return errors.New("malformed managed hook")
	}
	return nil
}

func managedHookPattern(begin, end string) *regexp.Regexp {
	return regexp.MustCompile(regexp.QuoteMeta(begin) + `(?s:\n.*?)` + regexp.QuoteMeta(end) + `\n?`)
}

func UninstallHook() error {
	// Remove the module only when it still matches the packaged source. A user
	// edit changes ownership of that content and is deliberately preserved.
	config := YayConfigDir()
	initPath := filepath.Join(config, "init.lua")
	modulePath := filepath.Join(config, "prolewatch.lua")
	if raw, err := os.ReadFile(initPath); err == nil {
		pattern := managedHookPattern(hookBegin, hookEnd)
		matches := pattern.FindAllIndex(raw, -1)
		if len(matches) > 1 {
			return errors.New("multiple managed hook blocks found")
		}
		if len(matches) == 1 {
			updated := pattern.ReplaceAll(raw, nil)
			if err := atomicUserWrite(initPath, updated, 0o600); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if info, err := os.Lstat(modulePath); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("refusing to remove unsafe hook module")
		}
		source, sourceErr := os.ReadFile(filepath.Join(ShareRoot(), "prolewatch.lua"))
		current, currentErr := os.ReadFile(modulePath)
		if sourceErr != nil || currentErr != nil || !bytes.Equal(source, current) {
			return errors.New("managed hook module was modified; preserving it")
		}
		return os.Remove(modulePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func atomicUserWrite(path string, data []byte, mode os.FileMode) error {
	// Refuse a symlink at the final user-controlled path and replace via a
	// same-directory rename so yay never observes a partially written hook.
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink: %s", path)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func copyRegular(source, target string, mode os.FileMode) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("copy source is not regular")
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return atomicUserWrite(target, raw, mode)
}
