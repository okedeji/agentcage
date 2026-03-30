package findings

import (
	"hash/fnv"
	"sync"
)

type BloomFilter struct {
	mu        sync.RWMutex
	bits      []bool
	size      uint
	hashCount uint
}

func NewBloomFilter(size, hashCount uint) *BloomFilter {
	return &BloomFilter{
		bits:      make([]bool, size),
		size:      size,
		hashCount: hashCount,
	}
}

func (bf *BloomFilter) Add(key string) {
	h1, h2 := bf.hashes(key)
	bf.mu.Lock()
	for i := uint(0); i < bf.hashCount; i++ {
		pos := (h1 + i*h2) % bf.size
		bf.bits[pos] = true
	}
	bf.mu.Unlock()
}

func (bf *BloomFilter) MayContain(key string) bool {
	h1, h2 := bf.hashes(key)
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	for i := uint(0); i < bf.hashCount; i++ {
		pos := (h1 + i*h2) % bf.size
		if !bf.bits[pos] {
			return false
		}
	}
	return true
}

func (bf *BloomFilter) hashes(key string) (uint, uint) {
	fnv1a := fnv.New64a()
	fnv1a.Write([]byte(key))
	h1 := uint(fnv1a.Sum64())

	fnv1 := fnv.New64()
	fnv1.Write([]byte(key))
	h2 := uint(fnv1.Sum64())

	// Ensure h2 is odd so (h1 + i*h2) % size cycles through more positions
	if h2%2 == 0 {
		h2++
	}

	return h1, h2
}
