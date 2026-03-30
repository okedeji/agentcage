package findings

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPGFindingStore(t *testing.T) {
	store := NewPGFindingStore(nil)
	require.NotNil(t, store)
	assert.Nil(t, store.db)
}
