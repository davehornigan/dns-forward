package main

import (
	"path/filepath"
	"testing"
)

func TestResolveConfigPath(t *testing.T) {
	t.Run("flag wins over the environment", func(t *testing.T) {
		t.Setenv("CONFIG_DIR", "/from/env")
		if got := resolveConfigPath("config.yaml", "/from/flag"); got != filepath.Join("/from/flag", "config.yaml") {
			t.Errorf("unexpected path %q", got)
		}
	})

	t.Run("environment is the fallback", func(t *testing.T) {
		t.Setenv("CONFIG_DIR", "/etc/dns-forward")
		if got := resolveConfigPath("config.yaml", ""); got != filepath.Join("/etc/dns-forward", "config.yaml") {
			t.Errorf("unexpected path %q", got)
		}
	})

	t.Run("current directory by default", func(t *testing.T) {
		t.Setenv("CONFIG_DIR", "")
		if got := resolveConfigPath("config.yaml", ""); got != "config.yaml" {
			t.Errorf("unexpected path %q", got)
		}
	})

	t.Run("absolute config wins over any directory", func(t *testing.T) {
		t.Setenv("CONFIG_DIR", "/from/env")
		if got := resolveConfigPath("/etc/other/config.yaml", "/from/flag"); got != "/etc/other/config.yaml" {
			t.Errorf("unexpected path %q", got)
		}
	})

	t.Run("relative config keeps its own subpath", func(t *testing.T) {
		t.Setenv("CONFIG_DIR", "")
		if got := resolveConfigPath("conf/config.yaml", "/base"); got != filepath.Join("/base", "conf/config.yaml") {
			t.Errorf("unexpected path %q", got)
		}
	})
}
