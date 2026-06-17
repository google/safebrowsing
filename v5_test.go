package safebrowsing

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"reflect"
	"testing"
	"time"
)

type mockAPI struct {
	listUpdate func(context.Context, []string, map[string][]byte) (*hashListsResponse, error)
	hashLookup func(context.Context, []hashPrefix) (*hashSearchResponse, error)
}

func (m *mockAPI) ListUpdate(ctx context.Context, names []string, versions map[string][]byte) (*hashListsResponse, error) {
	return m.listUpdate(ctx, names, versions)
}

func (m *mockAPI) HashLookup(ctx context.Context, prefixes []hashPrefix) (*hashSearchResponse, error) {
	return m.hashLookup(ctx, prefixes)
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	buf, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return buf
}

func newHashSet(phs hashPrefixes) (hs hashSet) {
	hs.Import(phs)
	return hs
}

func TestDecodeRice32HashesUsesBigEndian(t *testing.T) {
	hashes, err := decodeRice32Hashes(&rice32{FirstValue: 0x01020304})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := []byte(hashes[0]), []byte{0x01, 0x02, 0x03, 0x04}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hash mismatch: got %x, want %x", got, want)
	}
}

func TestCacheUpdateAndLookup(t *testing.T) {
	now := time.Unix(1000, 0)
	c := cache{now: func() time.Time { return now }}
	full := hashPrefix("aaaabbbbccccddddeeeeffffgggghhhh")
	resp := &hashSearchResponse{
		CacheDuration: "60s",
		FullHashes: []fullHash{{
			FullHash:        base64.StdEncoding.EncodeToString([]byte(full)),
			FullHashDetails: []fullHashDetail{{ThreatType: ThreatTypeMalware}},
		}},
	}
	c.Update([]hashPrefix{"aaaa"}, resp)

	threats, result := c.Lookup(full)
	if result != positiveCacheHit || !threats[ThreatTypeMalware] {
		t.Fatalf("positive cache mismatch: got %v %v", threats, result)
	}
	_, result = c.Lookup(hashPrefix("aaaaccccddddeeeeffffgggghhhhzzzz"))
	if result != negativeCacheHit {
		t.Fatalf("negative cache mismatch: got %v", result)
	}
}

func TestCacheIgnoresNonEnforceableAndUnknownDetails(t *testing.T) {
	now := time.Unix(1000, 0)
	c := cache{now: func() time.Time { return now }}
	full := hashPrefix("aaaabbbbccccddddeeeeffffgggghhhh")
	resp := &hashSearchResponse{
		CacheDuration: "60s",
		FullHashes: []fullHash{{
			FullHash: base64.StdEncoding.EncodeToString([]byte(full)),
			FullHashDetails: []fullHashDetail{
				{ThreatType: ThreatTypeMalware, Attributes: []string{"CANARY"}},
				{ThreatType: ThreatTypeMalware, Attributes: []string{"FRAME_ONLY"}},
				{ThreatType: ThreatTypeMalware, Attributes: []string{"THREAT_ATTRIBUTE_UNSPECIFIED"}},
			},
		}},
	}
	c.Update([]hashPrefix{"aaaa"}, resp)

	if _, result := c.Lookup(full); result != negativeCacheHit {
		t.Fatalf("non-enforceable details were cached as threats: %v", result)
	}
}

func TestEnforceableThreatDetail(t *testing.T) {
	tests := []struct {
		name   string
		detail fullHashDetail
		want   bool
	}{
		{name: "plain threat", detail: fullHashDetail{ThreatType: ThreatTypeMalware}, want: true},
		{name: "unknown threat", detail: fullHashDetail{ThreatType: ThreatTypeUnspecified}, want: false},
		{name: "canary", detail: fullHashDetail{ThreatType: ThreatTypeMalware, Attributes: []string{"CANARY"}}, want: false},
		{name: "frame only", detail: fullHashDetail{ThreatType: ThreatTypeMalware, Attributes: []string{"FRAME_ONLY"}}, want: false},
		{name: "unknown attribute", detail: fullHashDetail{ThreatType: ThreatTypeMalware, Attributes: []string{"NEW_ATTRIBUTE"}}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := enforceableThreatDetail(test.detail); got != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestDatabaseUpdate(t *testing.T) {
	now := time.Unix(1000, 0)
	config := &Config{
		HashLists:    []HashList{{Name: "mw-4b", ThreatType: ThreatTypeMalware}},
		UpdatePeriod: time.Hour,
		now:          func() time.Time { return now },
	}
	db := &database{config: config, log: log.New(testWriter{}, "", 0)}
	resp := &hashListsResponse{HashLists: []hashList{{
		Name:                "mw-4b",
		Version:             base64.StdEncoding.EncodeToString([]byte("v1")),
		MinimumWaitDuration: "20m",
		SHA256Checksum:      base64.StdEncoding.EncodeToString(mustDecodeHex(t, "61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4")),
		AdditionsFourBytes:  &rice32{FirstValue: 0x61616161},
	}}}

	delay, ok := db.Update(context.Background(), &mockAPI{
		listUpdate: func(context.Context, []string, map[string][]byte) (*hashListsResponse, error) {
			return resp, nil
		},
	})
	if !ok || delay != 20*time.Minute {
		t.Fatalf("unexpected update result: ok=%v delay=%v err=%v", ok, delay, db.err)
	}
	got := db.tfl["mw-4b"]
	want := newHashSet([]hashPrefix{"aaaa"})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lookup table mismatch: got %+v, want %+v", got, want)
	}
	health := db.Health()
	if !health.Healthy || health.LastUpdate != now || !health.NextUpdate.After(now) || !health.FreshUntil.After(health.NextUpdate) {
		t.Fatalf("unexpected health after update: %+v", health)
	}
}

func TestDatabaseBecomesStaleAfterFreshnessDeadline(t *testing.T) {
	now := time.Unix(1000, 0)
	config := &Config{
		UpdatePeriod: time.Minute,
		now:          func() time.Time { return now },
	}
	db := &database{
		config:     config,
		log:        log.New(testWriter{}, "", 0),
		readyCh:    make(chan struct{}),
		last:       now.Add(-2 * time.Minute),
		next:       now.Add(-time.Minute),
		freshUntil: now.Add(time.Second),
	}

	if health := db.Health(); !health.Healthy {
		t.Fatalf("database became stale too early: %+v", health)
	}
	now = now.Add(2 * time.Second)
	if health := db.Health(); health.Healthy || health.Error == "" {
		t.Fatalf("database did not become stale: %+v", health)
	}
}

func TestUpdateFailureKeepsFreshDatabaseAvailable(t *testing.T) {
	now := time.Unix(1000, 0)
	config := &Config{
		HashLists:    []HashList{{Name: "mw-4b", ThreatType: ThreatTypeMalware}},
		UpdatePeriod: time.Minute,
		now:          func() time.Time { return now },
	}
	db := &database{
		config:     config,
		log:        log.New(testWriter{}, "", 0),
		readyCh:    make(chan struct{}),
		tfl:        threatsForLookup{"mw-4b": newHashSet([]hashPrefix{"aaaa"})},
		last:       now.Add(-time.Minute),
		next:       now,
		freshUntil: now.Add(time.Minute),
	}

	_, ok := db.Update(context.Background(), &mockAPI{
		listUpdate: func(context.Context, []string, map[string][]byte) (*hashListsResponse, error) {
			return nil, errors.New("temporary failure")
		},
	})
	if ok {
		t.Fatal("unexpected update success")
	}
	health := db.Health()
	if !health.Healthy || health.LastUpdateError != "temporary failure" {
		t.Fatalf("fresh database should remain available after transient failure: %+v", health)
	}
	if _, lists := db.Lookup(hashPrefix("aaaabbbbccccddddeeeeffffgggghhhh")); len(lists) != 1 {
		t.Fatalf("lookup database was discarded after transient failure: %v", lists)
	}
}

type testWriter struct{}

func (testWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
