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
	"reflect"
	"testing"
	"time"

	pb "github.com/google/safebrowsing/internal/safebrowsing_proto"
)

func TestCacheLookup(t *testing.T) {
	now := time.Unix(1451436338, 951473000)
	mockNow := func() time.Time { return now }

	type cacheLookup struct {
		h   hashPrefix
		tds map[ThreatDescriptor]bool
		r   cacheResult
	}
	vectors := []struct {
		gotCache  *cache // The cache to apply the Purge and Lookup on
		wantCache *cache // The cache expected after Purge
		lookups   []cacheLookup
	}{{
		gotCache: &cache{
			pttls: map[hashPrefix]map[ThreatDescriptor]time.Time{
				"AAAABBBBBBBBBBBBBBBBBBBBBBBBBBBB": {
					{1, 2, 3}: now.Add(DefaultUpdatePeriod),
				},
				"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ": {
					{2, 2, 2}: now.Add(-time.Minute),
					{1, 1, 1}: now.Add(-DefaultUpdatePeriod),
				},
			},
			nttls: map[hashPrefix]time.Time{
				"AAAA": now.Add(DefaultUpdatePeriod),
				"BBBB": now.Add(-time.Minute),
			},
			now: mockNow,
		},
		wantCache: &cache{
			pttls: map[hashPrefix]map[ThreatDescriptor]time.Time{
				"AAAABBBBBBBBBBBBBBBBBBBBBBBBBBBB": {
					{1, 2, 3}: now.Add(DefaultUpdatePeriod),
				},
			},
			nttls: map[hashPrefix]time.Time{
				"AAAA": now.Add(DefaultUpdatePeriod),
			},
			now: mockNow,
		},
		lookups: []cacheLookup{{
			h:   "AAAABBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			tds: map[ThreatDescriptor]bool{{1, 2, 3}: true},
			r:   positiveCacheHit,
		}, {
			h:   "AAAACDCDCDCDCDCDCDCDCDCDCDCDCDCD",
			tds: nil,
			r:   negativeCacheHit,
		}, {
			h:   "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
			tds: nil,
			r:   cacheMiss,
		}},
	}, {
		gotCache: &cache{
			pttls: map[hashPrefix]map[ThreatDescriptor]time.Time{
				"AAAABBBBBBBBBBBBBBBBBBBBBBBBBBBB": {
					{1, 2, 3}: now.Add(DefaultUpdatePeriod),
					{1, 1, 1}: now.Add(-DefaultUpdatePeriod),
				},
				"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ": {
					{2, 2, 2}: now.Add(-time.Minute),
					{1, 1, 1}: now.Add(-DefaultUpdatePeriod),
				},
			},
			nttls: map[hashPrefix]time.Time{
				"AAAA": now.Add(DefaultUpdatePeriod * 2),
				"BBBB": now.Add(-time.Minute),
			},
			now: mockNow,
		},
		wantCache: &cache{
			pttls: map[hashPrefix]map[ThreatDescriptor]time.Time{
				"AAAABBBBBBBBBBBBBBBBBBBBBBBBBBBB": {
					{1, 2, 3}: now.Add(DefaultUpdatePeriod),
					{1, 1, 1}: now.Add(-DefaultUpdatePeriod),
				},
			},
			nttls: map[hashPrefix]time.Time{
				"AAAA": now.Add(DefaultUpdatePeriod * 2),
			},
			now: mockNow,
		},
		lookups: []cacheLookup{{
			h:   "AAAABBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			tds: nil,
			r:   cacheMiss,
		}, {
			h:   "AAAACDCDCDCDCDCDCDCDCDCDCDCDCDCD",
			tds: nil,
			r:   negativeCacheHit,
		}, {
			h:   "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
			tds: nil,
			r:   cacheMiss,
		}},
	}, {
		gotCache:  &cache{now: mockNow},
		wantCache: &cache{now: mockNow},
		lookups: []cacheLookup{{
			h:   "AAAABBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			tds: nil,
			r:   cacheMiss,
		}, {
			h:   "AAAACDCDCDCDCDCDCDCDCDCDCDCDCDCD",
			tds: nil,
			r:   cacheMiss,
		}},
	}}

	for i, v := range vectors {
		for j, l := range v.lookups {
			gotTDs, gotR := v.gotCache.Lookup(l.h)
			if !reflect.DeepEqual(gotTDs, l.tds) {
				t.Errorf("test %d, lookup %d, threats mismatch:\ngot  %+v\nwant %+v", i, j, gotTDs, l.tds)
			}
			if gotR != l.r {
				t.Errorf("test %d, lookup %d, result mismatch: got %d, want %d", i, j, gotR, l.r)

			}
		}
		v.gotCache.Purge()
		if !reflect.DeepEqual(v.wantCache.pttls, v.gotCache.pttls) {
			t.Errorf("purge test %d, mismatching cache contents: PTTLS\ngot  %+v\nwant %+v", i, v.gotCache.pttls, v.wantCache.pttls)
		}
		if !reflect.DeepEqual(v.wantCache.nttls, v.gotCache.nttls) {
			t.Errorf("purge test %d, mismatching cache contents: NTTLS\ngot  %+v\nwant %+v", i, v.gotCache.nttls, v.wantCache.nttls)
		}
		for j, l := range v.lookups {
			gotTDs, gotR := v.gotCache.Lookup(l.h)
			if !reflect.DeepEqual(gotTDs, l.tds) {
				t.Errorf("purge test %d, lookup %d, threats mismatch:\ngot  %+v\nwant %+v", i, j, gotTDs, l.tds)
			}
			if gotR != l.r {
				t.Errorf("purge test %d, lookup %d, result mismatch: got %d, want %d", i, j, gotR, l.r)
			}
		}
	}
}

func TestCacheUpdate(t *testing.T) {
	now := time.Unix(1451436338, 951473000)
	mockNow := func() time.Time { return now }

	vectors := []struct {
		req       *pb.FindFullHashesRequest
		resp      *pb.FindFullHashesResponse
		gotCache  *cache
		wantCache *cache
	}{{
		req:  &pb.FindFullHashesRequest{},
		resp: &pb.FindFullHashesResponse{},
		gotCache: &cache{
			now: mockNow,
		},
		wantCache: &cache{pttls: map[hashPrefix]map[ThreatDescriptor]time.Time{},
			nttls: map[hashPrefix]time.Time{},
			now:   mockNow,
		},
	}, {
		req: &pb.FindFullHashesRequest{
			ThreatInfo: &pb.ThreatInfo{
				ThreatTypes:      []pb.ThreatType{0, 1, 2},
				PlatformTypes:    []pb.PlatformType{1, 2, 3},
				ThreatEntryTypes: []pb.ThreatEntryType{2, 3, 4},
				ThreatEntries:    []*pb.ThreatEntry{{Hash: []byte("aaaa")}},
			}},
		resp: &pb.FindFullHashesResponse{
			Matches: []*pb.ThreatMatch{{
				ThreatType:      0,
				PlatformType:    1,
				ThreatEntryType: 2,
				Threat:          &pb.ThreatEntry{Hash: []byte("aaaabbbbccccddddeeeeffffgggghhhh")},
				CacheDuration:   &pb.Duration{Seconds: 1000, Nanos: 0},
			}, {
				ThreatType:      1,
				PlatformType:    2,
				ThreatEntryType: 3,
				Threat:          &pb.ThreatEntry{Hash: []byte("aaaaaaaaccccddddeeeeffffgggghhhh")},
				CacheDuration:   &pb.Duration{Seconds: 1000, Nanos: 0},
			}, {
				ThreatType:      2,
				PlatformType:    3,
				ThreatEntryType: 4,
				Threat:          &pb.ThreatEntry{Hash: []byte("aaaaccccccccddddeeeeffffgggghhhh")},
				CacheDuration:   &pb.Duration{Seconds: 1000, Nanos: 0},
			}},
			NegativeCacheDuration: &pb.Duration{Seconds: 1000, Nanos: 0},
		},
		gotCache: &cache{
			now: mockNow,
		},
		wantCache: &cache{
			pttls: map[hashPrefix]map[ThreatDescriptor]time.Time{
				"aaaabbbbccccddddeeeeffffgggghhhh": {
					{0, 1, 2}: now.Add(1000 * time.Second),
				},
				"aaaaaaaaccccddddeeeeffffgggghhhh": {
					{1, 2, 3}: now.Add(1000 * time.Second),
				},
				"aaaaccccccccddddeeeeffffgggghhhh": {
					{2, 3, 4}: now.Add(1000 * time.Second),
				},
			},
			nttls: map[hashPrefix]time.Time{
				"aaaa": now.Add(1000 * time.Second),
			},
			now: mockNow,
		},
	}}

	for i, v := range vectors {
		v.gotCache.Update(v.req, v.resp)
		if !reflect.DeepEqual(v.wantCache.pttls, v.gotCache.pttls) {
			t.Errorf("test %d, mismatching cache contents: PTTLS\ngot  %+v\nwant %+v", i, v.gotCache.pttls, v.wantCache.pttls)
		}
		if !reflect.DeepEqual(v.wantCache.nttls, v.gotCache.nttls) {
			t.Errorf("test %d, mismatching cache contents: NTTLS\ngot  %+v\nwant %+v", i, v.gotCache.nttls, v.wantCache.nttls)
		}
	}
}
