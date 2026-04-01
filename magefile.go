//go:build mage

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// Lint runs golangci-lint on the codebase.
func Lint() error {
	return sh("golangci-lint", "run", "./...")
}

// Test runs all tests with race detection.
func Test() error {
	return sh("go", "test", "-race", "-count=1", "-timeout=120s", "./...")
}

// Bench runs all benchmarks.
func Bench() error {
	return sh("go", "test", "-bench=.", "-benchmem", "-run=^$", "-timeout=300s", "./...")
}

// BenchCmp runs cross-framework comparison benchmarks.
func BenchCmp() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	defer os.Chdir(wd)
	if err := os.Chdir("test/benchcmp"); err != nil {
		return fmt.Errorf("test/benchcmp not found: %w", err)
	}
	return sh("go", "test", "-bench=.", "-benchmem", "-run=^$", "-count=5", "-timeout=600s", "./...")
}

// All runs lint, test, and bench in sequence.
func All() error {
	if err := Lint(); err != nil {
		return err
	}
	if err := Test(); err != nil {
		return err
	}
	return Bench()
}

func sh(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
