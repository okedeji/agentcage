package config

import (
	"testing"

	"github.com/okedeji/mcpvessel/internal/env"
)

const knob = "VESSEL_TEST_KNOB"

func storeEnv(t *testing.T, name, value string) {
	t.Helper()
	t.Setenv(env.Home, t.TempDir())
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	c.SetEnv(name, value)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestLookupEnv_EnvWinsOverConfig(t *testing.T) {
	storeEnv(t, knob, "from-config")
	t.Setenv(knob, "from-shell")
	if got := LookupEnv(knob); got != "from-shell" {
		t.Errorf("LookupEnv = %q, want the shell value to win", got)
	}
}

func TestLookupEnv_ConfigWhenEnvUnset(t *testing.T) {
	storeEnv(t, knob, "from-config")
	// knob is not exported, so the stored value applies.
	if got := LookupEnv(knob); got != "from-config" {
		t.Errorf("LookupEnv = %q, want the stored config value", got)
	}
}

func TestLookupEnv_BlankEnvFallsThrough(t *testing.T) {
	storeEnv(t, knob, "from-config")
	t.Setenv(knob, "   ")
	if got := LookupEnv(knob); got != "from-config" {
		t.Errorf("LookupEnv = %q, want a blank env to count as unset and fall through", got)
	}
}

func TestLookupEnvOr_Default(t *testing.T) {
	t.Setenv(env.Home, t.TempDir())
	if got := LookupEnvOr(knob, "the-default"); got != "the-default" {
		t.Errorf("LookupEnvOr = %q, want the default when nothing is set", got)
	}
}

func TestSetRemoveEnv(t *testing.T) {
	t.Setenv(env.Home, t.TempDir())
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	c.SetEnv(knob, "v")
	if c.Env[knob] != "v" {
		t.Fatalf("SetEnv did not store the value: %v", c.Env)
	}
	if !c.RemoveEnv(knob) {
		t.Error("RemoveEnv reported not-present for a set knob")
	}
	if _, ok := c.Env[knob]; ok {
		t.Error("RemoveEnv left the knob in place")
	}
	if c.RemoveEnv(knob) {
		t.Error("RemoveEnv reported present for an absent knob")
	}
}

func TestParseByteSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"1024", 1024, true},
		{"16M", 16 << 20, true},
		{"16MiB", 16 << 20, true},
		{"16mb", 16 << 20, true},
		{"8g", 8 << 30, true},
		{"512k", 512 << 10, true},
		{"2T", 2 << 40, true},
		{"  32MiB ", 32 << 20, true},
		{"", 0, false},
		{"abc", 0, false},
		{"10x", 0, false},
	}
	for _, c := range cases {
		got, err := ParseByteSize(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("ParseByteSize(%q) errored: %v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("ParseByteSize(%q) = %d, want %d", c.in, got, c.want)
			}
		} else if err == nil {
			t.Errorf("ParseByteSize(%q) = %d, want error", c.in, got)
		}
	}
}

func TestByteSizeEnv_FallsBackOnUnsetOrGarbage(t *testing.T) {
	const def = 1 << 20
	// Unset: the default holds.
	if got := ByteSizeEnv(knob, def); got != def {
		t.Errorf("unset ByteSizeEnv = %d, want default %d", got, def)
	}
	// A garbage value must not blow up or zero the cap; it falls back.
	storeEnv(t, knob, "not-a-size")
	if got := ByteSizeEnv(knob, def); got != def {
		t.Errorf("garbage ByteSizeEnv = %d, want default %d", got, def)
	}
	// A good value wins.
	storeEnv(t, knob, "4MiB")
	if got := ByteSizeEnv(knob, def); got != 4<<20 {
		t.Errorf("ByteSizeEnv = %d, want %d", got, 4<<20)
	}
}
