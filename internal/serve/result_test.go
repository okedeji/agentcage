package serve

import "testing"

func TestResultValue(t *testing.T) {
	// JSON objects and arrays unwrap to real JSON; everything else, including
	// scalars that would parse, stays the literal text the tool produced.
	obj := resultValue(`{"a": 1}`)
	if m, ok := obj.(map[string]any); !ok || m["a"] != float64(1) {
		t.Errorf("object result not unwrapped: %#v", obj)
	}
	arr := resultValue(` [1, 2] `)
	if _, ok := arr.([]any); !ok {
		t.Errorf("array result not unwrapped: %#v", arr)
	}
	for _, text := range []string{"plain text", "42", "true", `"quoted"`, "{not json", ""} {
		if got := resultValue(text); got != text {
			t.Errorf("resultValue(%q) = %#v, want the literal text", text, got)
		}
	}
}
