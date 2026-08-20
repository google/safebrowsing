// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safebrowsing

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/google/safebrowsing/internal/safebrowsing_proto"
)

// TestLookupURLsHashLookupBatching checks that LookupURLsContext splits the
// fullHashes.find request into multiple API calls when more than
// maxHashPrefixesPerRequest hash prefixes are queried, and that matches
// returned from any of the requests are surfaced to the caller.
func TestLookupURLsHashLookupBatching(t *testing.T) {
	now := time.Unix(1451436338, 951473000)
	mockNow := func() time.Time { return now }

	// Build a set of URLs that produce more than maxHashPrefixesPerRequest
	// distinct hash prefixes. Every generated prefix is inserted into the
	// database below so that each full hash is "unsure" and gets queued for
	// the API.
	const numURLs = maxHashPrefixesPerRequest + 100
	urls := make([]string, numURLs)
	var prefixes hashPrefixes
	allHashes := make(map[hashPrefix]bool)
	for i := 0; i < numURLs; i++ {
		urls[i] = fmt.Sprintf("http://www%d.example.com/", i)
		hashes, err := generateHashes(urls[i])
		if err != nil {
			t.Fatalf("unexpected generateHashes error: %v", err)
		}
		for h := range hashes {
			allHashes[h] = true
			prefixes = append(prefixes, h[:minHashPrefixLength])
		}
	}
	sort.Sort(prefixes)
	hs := newHashSet(prefixes)

	// Choose a few URL-specific hashes to return as matches from the mock
	// API. This verifies that matches from different requests are all merged
	// into the final result.
	matchPrefixes := make(map[string]pb.ThreatEntry)
	matchURLs := []int{0, numURLs / 2, numURLs - 1}
	for _, i := range matchURLs {
		hashes, err := generateHashes(urls[i])
		if err != nil {
			t.Fatalf("unexpected generateHashes error: %v", err)
		}
		host := fmt.Sprintf("www%d.example.com", i)
		for h, pat := range hashes {
			if strings.HasPrefix(pat, host) {
				matchPrefixes[string(h[:minHashPrefixLength])] = pb.ThreatEntry{Hash: []byte(h)}
				break
			}
		}
	}
	if len(matchPrefixes) != len(matchURLs) {
		t.Fatalf("failed to pick a URL-specific hash for every match URL")
	}

	var mu sync.Mutex
	var numRequests, totalEntries, maxBatch int
	mock := &mockAPI{
		hashLookup: func(_ context.Context, req *pb.FindFullHashesRequest) (*pb.FindFullHashesResponse, error) {
			mu.Lock()
			defer mu.Unlock()
			numRequests++
			n := len(req.ThreatInfo.GetThreatEntries())
			totalEntries += n
			if n > maxBatch {
				maxBatch = n
			}
			var matches []*pb.ThreatMatch
			for _, te := range req.ThreatInfo.GetThreatEntries() {
				fullEntry, ok := matchPrefixes[string(te.Hash)]
				if !ok {
					continue
				}
				matches = append(matches, &pb.ThreatMatch{
					ThreatType:      pb.ThreatType(DefaultThreatLists[0].ThreatType),
					PlatformType:    pb.PlatformType(DefaultThreatLists[0].PlatformType),
					ThreatEntryType: pb.ThreatEntryType(DefaultThreatLists[0].ThreatEntryType),
					Threat:          &fullEntry,
				})
			}
			return &pb.FindFullHashesResponse{Matches: matches}, nil
		},
	}

	config := &Config{
		ThreatLists:    DefaultThreatLists,
		UpdatePeriod:   DefaultUpdatePeriod,
		RequestTimeout: DefaultRequestTimeout,
		now:            mockNow,
	}
	sb := &SafeBrowser{
		config: *config,
		api:    mock,
		lists:  make(map[ThreatDescriptor]bool),
		db: database{
			config:  config,
			log:     log.New(ioutil.Discard, "", 0),
			tfl:     threatsForLookup{DefaultThreatLists[0]: hs},
			last:    now,
			readyCh: make(chan struct{}),
		},
		c:   cache{now: mockNow},
		log: log.New(ioutil.Discard, "", 0),
	}
	for _, td := range DefaultThreatLists {
		sb.lists[td] = true
	}

	threats, err := sb.LookupURLsContext(context.Background(), urls)
	if err != nil {
		t.Fatalf("unexpected LookupURLsContext error: %v", err)
	}

	if numRequests < 2 {
		t.Errorf("LookupURLsContext made %d API requests, want at least 2", numRequests)
	}
	if maxBatch > maxHashPrefixesPerRequest {
		t.Errorf("largest request contained %d hash prefixes, want at most %d", maxBatch, maxHashPrefixesPerRequest)
	}
	if totalEntries != len(allHashes) {
		t.Errorf("API requests contained %d hash prefixes in total, want %d", totalEntries, len(allHashes))
	}
	if got, want := len(threats), len(urls); got != want {
		t.Fatalf("len(threats) = %d, want %d", got, want)
	}
	for i := range urls {
		wantMatch := false
		for _, j := range matchURLs {
			if i == j {
				wantMatch = true
			}
		}
		if wantMatch && len(threats[i]) == 0 {
			t.Errorf("threats[%d] = empty, want a match to be reported", i)
		}
		if !wantMatch && len(threats[i]) != 0 {
			t.Errorf("threats[%d] = %v, want empty", i, threats[i])
		}
	}
}
