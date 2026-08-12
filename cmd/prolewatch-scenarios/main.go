package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/holgerjh/prolewatch/internal/audit"
	"github.com/holgerjh/prolewatch/internal/scenarios"
)

const installedProlewatch = "/usr/bin/prolewatch"

var (
	effectiveUID            = os.Geteuid
	validateInstalledBinary = checkInstalledBinary
	installedOutput         = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
	installedRun = func(stdout, stderr io.Writer, name string, args ...string) error {
		command := exec.Command(name, args...)
		command.Stdout = stdout
		command.Stderr = stderr
		return command.Run()
	}
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("prolewatch-scenarios", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "testdata/security-scenarios", "security scenario corpus root")
	only := flags.String("scenario", "", "run one scenario by id")
	installed := flags.Bool("installed", false, "run the suite through the installed prolewatch system")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "prolewatch-scenarios accepts flags only")
		return 2
	}
	if *installed {
		return runInstalled(*root, *only, stdout, stderr)
	}
	return scenarios.RunAndRender(*root, *only, stdout, stderr)
}

func runInstalled(root, only string, stdout, stderr io.Writer) int {
	if effectiveUID() == 0 {
		fmt.Fprintln(stderr, "installed scenario suite: run as the normal yay user, not root")
		return 1
	}
	if err := validateInstalledBinary(installedProlewatch); err != nil {
		fmt.Fprintln(stderr, "installed scenario suite:", err)
		return 1
	}
	version, err := installedOutput(installedProlewatch, "version")
	if err != nil {
		fmt.Fprintf(stderr, "installed scenario suite: read installed version: %v: %s\n", err, strings.TrimSpace(string(version)))
		return 1
	}
	wantVersion := "prolewatch " + audit.ApplicationVersion
	if gotVersion := strings.TrimSpace(string(version)); gotVersion != wantVersion {
		fmt.Fprintf(stderr, "installed scenario suite: installed version %q does not match checkout version %q; update the installation first\n", gotVersion, wantVersion)
		return 1
	}
	fmt.Fprintf(stdout, "Installed Prolewatch version matches checkout: %s\n", audit.ApplicationVersion)
	if err := installedRun(stdout, stderr, installedProlewatch, "doctor", "--no-probe"); err != nil {
		fmt.Fprintln(stderr, "installed scenario suite: doctor --no-probe failed:", err)
		return 1
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintln(stderr, "installed scenario suite: resolve scenario root:", err)
		return 1
	}
	commandArgs := []string{"security-scenarios", "--root", absoluteRoot}
	if only != "" {
		commandArgs = append(commandArgs, "--scenario", only)
	}
	if err := installedRun(stdout, stderr, installedProlewatch, commandArgs...); err != nil {
		fmt.Fprintln(stderr, "installed scenario suite: security scenarios failed:", err)
		return 1
	}
	return 0
}

func checkInstalledBinary(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify ownership of %s", path)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must be a root-owned regular file that is not group/world writable", path)
	}
	return nil
}
