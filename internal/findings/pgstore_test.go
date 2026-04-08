package findings

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPGStore(t *testing.T) {
	store := NewPGStore(nil)
	require.NotNil(t, store)
	assert.Nil(t, store.db)
}
