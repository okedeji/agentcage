package enforcement

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPayloadBatcher_SinglePayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ClassificationResponse{
			Results: []ClassificationResult{
				{Safe: true, Confidence: 0.9, Reason: ""},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClassificationClient(srv.URL, 5*time.Second)
	batcher := NewPayloadBatcher(client, 100*time.Millisecond, 10)
	defer batcher.Close()

	ch := batcher.Submit(ClassificationPayload{VulnClass: "sqli", Method: "POST", URL: "http://t.com", Body: "x"})

	select {
	case result := <-ch:
		assert.True(t, result.Safe)
		assert.InDelta(t, 0.9, result.Confidence, 0.001)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for result")
	}
}

func TestPayloadBatcher_MaxBatchFlushesImmediately(t *testing.T) {
	var receivedAt time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAt = time.Now()
		var req ClassificationRequest
		json.NewDecoder(r.Body).Decode(&req)
		results := make([]ClassificationResult, len(req.Payloads))
		for i := range results {
			results[i] = ClassificationResult{Safe: true, Confidence: 0.85, Reason: ""}
		}
		json.NewEncoder(w).Encode(ClassificationResponse{Results: results})
	}))
	defer srv.Close()

	client := NewClassificationClient(srv.URL, 5*time.Second)
	batcher := NewPayloadBatcher(client, 5*time.Second, 3)
	defer batcher.Close()

	start := time.Now()
	channels := make([]<-chan ClassificationResult, 3)
	for i := 0; i < 3; i++ {
		channels[i] = batcher.Submit(ClassificationPayload{VulnClass: "sqli", Method: "POST", URL: "http://t.com", Body: "x"})
	}

	for i, ch := range channels {
		select {
		case result := <-ch:
			assert.True(t, result.Safe, "result %d should be safe", i)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for result %d", i)
		}
	}

	// Should have flushed well before the 5s window
	assert.Less(t, receivedAt.Sub(start), 1*time.Second)
}

func TestPayloadBatcher_WindowFlush(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ClassificationRequest
		json.NewDecoder(r.Body).Decode(&req)
		results := make([]ClassificationResult, len(req.Payloads))
		for i := range results {
			results[i] = ClassificationResult{Safe: true, Confidence: 0.9, Reason: ""}
		}
		json.NewEncoder(w).Encode(ClassificationResponse{Results: results})
	}))
	defer srv.Close()

	client := NewClassificationClient(srv.URL, 5*time.Second)
	batcher := NewPayloadBatcher(client, 100*time.Millisecond, 100)
	defer batcher.Close()

	ch := batcher.Submit(ClassificationPayload{VulnClass: "sqli", Method: "POST", URL: "http://t.com", Body: "x"})

	select {
	case result := <-ch:
		assert.True(t, result.Safe)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for window flush")
	}
}

func TestPayloadBatcher_ConcurrentSubmits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ClassificationRequest
		json.NewDecoder(r.Body).Decode(&req)
		results := make([]ClassificationResult, len(req.Payloads))
		for i := range results {
			results[i] = ClassificationResult{Safe: true, Confidence: 0.88, Reason: ""}
		}
		json.NewEncoder(w).Encode(ClassificationResponse{Results: results})
	}))
	defer srv.Close()

	client := NewClassificationClient(srv.URL, 5*time.Second)
	batcher := NewPayloadBatcher(client, 50*time.Millisecond, 50)
	defer batcher.Close()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ch := batcher.Submit(ClassificationPayload{VulnClass: "sqli", Method: "POST", URL: "http://t.com", Body: "x"})
			select {
			case result := <-ch:
				assert.True(t, result.Safe)
			case <-time.After(5 * time.Second):
				t.Error("timed out waiting for concurrent result")
			}
		}()
	}
	wg.Wait()
}

func TestPayloadBatcher_ClassificationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	client := NewClassificationClient(srv.URL, 5*time.Second)
	batcher := NewPayloadBatcher(client, 50*time.Millisecond, 10)
	defer batcher.Close()

	ch := batcher.Submit(ClassificationPayload{VulnClass: "sqli", Method: "POST", URL: "http://t.com", Body: "x"})

	select {
	case result := <-ch:
		require.False(t, result.Safe)
		assert.InDelta(t, 0.0, result.Confidence, 0.001)
		assert.NotEmpty(t, result.Reason)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for error result")
	}
}
