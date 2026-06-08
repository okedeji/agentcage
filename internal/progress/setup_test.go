package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSetupPlain_PrintsTitleThenPhases(t *testing.T) {
	var buf bytes.Buffer
	ui := NewSetupPlain(&buf, "Setup", "Tip line", []string{"alpha", "beta"})
	ui.Start("alpha")
	ui.SetDetail("downloading")
	ui.Start("beta")
	ui.Done()

	out := buf.String()
	for _, want := range []string{
		"Setup",
		"-> alpha",
		"downloading",
		"-> beta",
		"Setup complete in",
		"Tip line",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plain output missing %q:\n%s", want, out)
		}
	}
}

func TestSetupPlain_StartCompletesPrevious(t *testing.T) {
	var buf bytes.Buffer
	ui := NewSetupPlain(&buf, "", "", []string{"a", "b"})
	ui.Start("a")
	ui.Start("b")
	ui.Done()

	out := buf.String()
	// Expect a "done in" line emitted when transitioning a -> b,
	// and another when Done is called for b.
	if got := strings.Count(out, "done in"); got != 2 {
		t.Errorf("got %d 'done in' lines, want 2:\n%s", got, out)
	}
}

func TestSetupPlain_SkippedPhasesAreAutoCompleted(t *testing.T) {
	// Lima's Ubuntu-image-already-cached path skips the "Preparing"
	// phase: our tap sees Booting markers but no Pulling markers.
	// The renderer must still mark Preparing done so it doesn't sit
	// as a dot forever in the final output.
	var buf bytes.Buffer
	ui := NewSetupPlain(&buf, "", "", []string{"alpha", "beta", "gamma"})
	ui.Start("alpha")
	ui.Start("gamma") // skips beta
	ui.Done()

	out := buf.String()
	if !strings.Contains(out, "-> beta (skipped — nothing to do)") {
		t.Errorf("skipped phase 'beta' was not auto-completed:\n%s", out)
	}
	if !strings.Contains(out, "-> gamma") {
		t.Errorf("explicit phase 'gamma' missing:\n%s", out)
	}
}

func TestSetupPlain_UnknownPhaseIsNoop(t *testing.T) {
	var buf bytes.Buffer
	ui := NewSetupPlain(&buf, "", "", []string{"a"})
	ui.Start("not-in-list")
	ui.Done()
	// Should not have started anything; no "-> not-in-list" line.
	if strings.Contains(buf.String(), "not-in-list") {
		t.Errorf("plain output should ignore unknown phase names:\n%s", buf.String())
	}
}

func TestSetupPlain_StartIsIdempotentForActivePhase(t *testing.T) {
	// The Lima tap fires many "downloading" / "[hostagent]" lines
	// per phase. Each call to Start for the already-active phase
	// must NOT print a duplicate "-> name" header or otherwise
	// disturb the active state.
	var buf bytes.Buffer
	ui := NewSetupPlain(&buf, "", "", []string{"alpha"})
	ui.Start("alpha")
	ui.Start("alpha")
	ui.Start("alpha")
	ui.Done()

	out := buf.String()
	if got := strings.Count(out, "-> alpha"); got != 1 {
		t.Errorf("got %d '-> alpha' lines, want 1 (idempotent Start):\n%s", got, out)
	}
}

func TestSetupPlain_FailReportsError(t *testing.T) {
	var buf bytes.Buffer
	ui := NewSetupPlain(&buf, "", "", []string{"a"})
	ui.Start("a")
	ui.Fail(errTest("disk full"))
	out := buf.String()
	if !strings.Contains(out, "failed: disk full") {
		t.Errorf("Fail did not surface error:\n%s", out)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{500 * time.Millisecond, "0.5s"},
		{9*time.Second + 700*time.Millisecond, "9.7s"},
		{59 * time.Second, "59.0s"},
		{60 * time.Second, "1m 00s"},
		{90 * time.Second, "1m 30s"},
		{3*time.Minute + 8*time.Second, "3m 08s"},
	}
	for _, tc := range cases {
		if got := humanDuration(tc.in); got != tc.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDisplayLen_CountsRunes(t *testing.T) {
	// The spinner glyphs and checkmark are multi-byte; alignment
	// would break if we counted bytes.
	cases := map[string]int{
		"":      0,
		"abc":   3,
		"✓ foo": 5,
		"⠼ bar": 5,
	}
	for in, want := range cases {
		if got := displayLen(in); got != want {
			t.Errorf("displayLen(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestFormatTwoColumn_PadsAndTruncates(t *testing.T) {
	short := formatTwoColumn("left", "right")
	if !strings.HasPrefix(short, "left") || !strings.HasSuffix(short, "right") {
		t.Errorf("two-column output should keep both ends: %q", short)
	}
	// When left+right exceeds width, left gets truncated and right
	// is preserved.
	wide := strings.Repeat("x", 100)
	got := formatTwoColumn(wide, "right")
	if !strings.HasSuffix(got, "right") {
		t.Errorf("right side dropped on overflow: %q", got)
	}
}

// errTest is a small string-error type so we do not import "errors"
// just for this file.
type errTest string

func (e errTest) Error() string { return string(e) }
