package enforcement

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassificationClient_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ClassificationRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Len(t, req.Payloads, 2)

		resp := ClassificationResponse{
			Results: []ClassificationResult{
				{Safe: true, Confidence: 0.95, Reason: ""},
				{Safe: false, Confidence: 0.4, Reason: "suspicious"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClassificationClient(srv.URL, 5*time.Second)
	results, err := client.Classify(context.Background(), []ClassificationPayload{
		{VulnClass: "sqli", Method: "POST", URL: "http://target.com", Body: "safe"},
		{VulnClass: "sqli", Method: "POST", URL: "http://target.com", Body: "bad"},
	})
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.True(t, results[0].Safe)
	assert.InDelta(t, 0.95, results[0].Confidence, 0.001)
	assert.False(t, results[1].Safe)
	assert.Equal(t, "suspicious", results[1].Reason)
}

func TestClassificationClient_MissingResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := NewClassificationClient(srv.URL, 5*time.Second)
	_, err := client.Classify(context.Background(), []ClassificationPayload{
		{VulnClass: "sqli", Method: "POST", URL: "http://target.com", Body: "test"},
	})
	assert.ErrorIs(t, err, ErrNoClassificationData)
}

func TestClassificationClient_ResultCountMismatch(t *testing.T) {
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
	_, err := client.Classify(context.Background(), []ClassificationPayload{
		{VulnClass: "sqli", Method: "POST", URL: "http://a.com", Body: "1"},
		{VulnClass: "sqli", Method: "POST", URL: "http://b.com", Body: "2"},
	})
	assert.ErrorIs(t, err, ErrResultCountMismatch)
}

func TestClassificationClient_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	client := NewClassificationClient(srv.URL, 100*time.Millisecond)
	_, err := client.Classify(context.Background(), []ClassificationPayload{
		{VulnClass: "sqli", Method: "POST", URL: "http://target.com", Body: "slow"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sending classification request")
}

func TestClassificationClient_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	client := NewClassificationClient(srv.URL, 5*time.Second)
	_, err := client.Classify(context.Background(), []ClassificationPayload{
		{VulnClass: "sqli", Method: "POST", URL: "http://target.com", Body: "test"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshaling classification response")
}
