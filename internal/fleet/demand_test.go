package fleet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDemandLedger_AddAndGet(t *testing.T) {
	dl := NewDemandLedger()
	dl.AddDemand("assess-1", 10)

	assert.Equal(t, int32(10), dl.GetDemand("assess-1"))
}

func TestDemandLedger_CurrentDemand_Multiple(t *testing.T) {
	dl := NewDemandLedger()
	dl.AddDemand("assess-1", 10)
	dl.AddDemand("assess-2", 25)
	dl.AddDemand("assess-3", 5)

	assert.Equal(t, int32(40), dl.CurrentDemand())
}

func TestDemandLedger_Update(t *testing.T) {
	dl := NewDemandLedger()
	dl.AddDemand("assess-1", 10)
	dl.AddDemand("assess-1", 20)

	assert.Equal(t, int32(20), dl.GetDemand("assess-1"))
	assert.Equal(t, int32(20), dl.CurrentDemand())
}

func TestDemandLedger_Remove(t *testing.T) {
	dl := NewDemandLedger()
	dl.AddDemand("assess-1", 10)
	dl.AddDemand("assess-2", 20)
	dl.RemoveDemand("assess-1")

	assert.Equal(t, int32(0), dl.GetDemand("assess-1"))
	assert.Equal(t, int32(20), dl.CurrentDemand())
}

func TestDemandLedger_RemoveUnknown(t *testing.T) {
	dl := NewDemandLedger()
	dl.RemoveDemand("nonexistent")

	assert.Equal(t, int32(0), dl.CurrentDemand())
}

func TestDemandLedger_CurrentDemand_Empty(t *testing.T) {
	dl := NewDemandLedger()

	assert.Equal(t, int32(0), dl.CurrentDemand())
}
