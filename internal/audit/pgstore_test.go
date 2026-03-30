package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntryTypeRoundTrip(t *testing.T) {
	for et := EntryTypeUnspecified; et <= EntryTypeLLMResponse; et++ {
		name := et.String()
		got := entryTypeFromString(name)
		assert.Equal(t, et, got, "round trip failed for %s", name)
	}
}

func TestEntryTypeFromStringUnknown(t *testing.T) {
	got := entryTypeFromString("nonexistent_type")
	assert.Equal(t, EntryTypeUnspecified, got)
}

func TestNewPGStore(t *testing.T) {
	store := NewPGStore(nil)
	require.NotNil(t, store)
}
