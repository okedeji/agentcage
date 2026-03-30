package findings

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBloomFilter_AddAndCheck(t *testing.T) {
	bf := NewBloomFilter(1000, 5)
	bf.Add("finding-001")
	assert.True(t, bf.MayContain("finding-001"))
}

func TestBloomFilter_CheckWithoutAdd(t *testing.T) {
	bf := NewBloomFilter(1000, 5)
	assert.False(t, bf.MayContain("finding-001"))
}

func TestBloomFilter_MultipleAdds(t *testing.T) {
	bf := NewBloomFilter(10000, 5)
	keys := []string{"f-001", "f-002", "f-003", "f-100", "f-999"}
	for _, k := range keys {
		bf.Add(k)
	}
	for _, k := range keys {
		assert.True(t, bf.MayContain(k), "expected %s to be found", k)
	}
}

func TestBloomFilter_FalsePositiveRate(t *testing.T) {
	bf := NewBloomFilter(10000, 5)

	for i := 0; i < 1000; i++ {
		bf.Add(fmt.Sprintf("added-%d", i))
	}

	falsePositives := 0
	for i := 0; i < 1000; i++ {
		if bf.MayContain(fmt.Sprintf("notadded-%d", i)) {
			falsePositives++
		}
	}

	rate := float64(falsePositives) / 1000.0
	assert.Less(t, rate, 0.10, "false positive rate %f exceeds 10%%", rate)
}

func TestBloomFilter_ConcurrentAccess(t *testing.T) {
	bf := NewBloomFilter(10000, 5)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", n)
			bf.Add(key)
			bf.MayContain(key)
		}(i)
	}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			bf.MayContain(fmt.Sprintf("check-%d", n))
		}(i)
	}

	wg.Wait()

	for i := 0; i < 100; i++ {
		assert.True(t, bf.MayContain(fmt.Sprintf("key-%d", i)))
	}
}
