package egress

import (
	"reflect"
	"testing"
)

func TestParseScopedAndHostsFor(t *testing.T) {
	scoped := ParseScoped([]string{
		"shared.example.com",                       // broadcast
		"github:api.github.com,uploads.github.com", // scoped, multi-host
		"brave:api.search.brave.com",
	})
	// github gets its own hosts plus the broadcast one, sorted and deduped.
	got := HostsFor(scoped, "github")
	want := []string{"api.github.com", "shared.example.com", "uploads.github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("HostsFor(github) = %v, want %v", got, want)
	}
	// An agent with no scope still gets the broadcast set.
	if got := HostsFor(scoped, "unmentioned"); !reflect.DeepEqual(got, []string{"shared.example.com"}) {
		t.Errorf("HostsFor(unmentioned) = %v, want the broadcast only", got)
	}
	if got := ScopedNames(scoped); !reflect.DeepEqual(got, []string{"brave", "github"}) {
		t.Errorf("ScopedNames = %v", got)
	}
}
