//go:build mage

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// Lint runs golangci-lint on the codebase (root module + sub-modules).
func Lint() error {
	if err := sh("golangci-lint", "run", "./..."); err != nil {
		return err
	}
	for _, mod := range []string{"metrics", "otel"} {
		wd, _ := os.Getwd()
		if err := os.Chdir(mod); err != nil {
			return fmt.Errorf("%s: %w", mod, err)
		}
		err := sh("golangci-lint", "run", "./...")
		os.Chdir(wd)
		if err != nil {
			return fmt.Errorf("%s lint failed: %w", mod, err)
		}
	}
	return nil
}

// Test runs all tests with race detection (root module + sub-modules).
func Test() error {
	if err := sh("go", "test", "-race", "-count=1", "-timeout=120s", "./..."); err != nil {
		return err
	}
	for _, mod := range []string{"metrics", "otel"} {
		wd, _ := os.Getwd()
		if err := os.Chdir(mod); err != nil {
			return fmt.Errorf("%s: %w", mod, err)
		}
		err := sh("go", "test", "-race", "-count=1", "-timeout=120s", "./...")
		os.Chdir(wd)
		if err != nil {
			return fmt.Errorf("%s tests failed: %w", mod, err)
		}
	}
	return nil
}

// Bench runs all benchmarks (root module + sub-modules).
func Bench() error {
	if err := sh("go", "test", "-bench=.", "-benchmem", "-run=^$", "-timeout=300s", "./..."); err != nil {
		return err
	}
	for _, mod := range []string{"metrics", "otel"} {
		wd, _ := os.Getwd()
		if err := os.Chdir(mod); err != nil {
			return fmt.Errorf("%s: %w", mod, err)
		}
		err := sh("go", "test", "-bench=.", "-benchmem", "-run=^$", "-timeout=300s", "./...")
		os.Chdir(wd)
		if err != nil {
			return fmt.Errorf("%s benchmarks failed: %w", mod, err)
		}
	}
	return nil
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
