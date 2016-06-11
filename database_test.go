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
	"encoding/hex"
	"io"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	pb "github.com/google/safebrowsing/internal/safebrowsing_proto"
)

func mustGetTempFile(t *testing.T) string {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return path
}

func mustDecodeHex(t *testing.T, s string) []byte {
	buf, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return buf
}

type ByThreatDescriptors []ThreatDescriptor

func (slice ByThreatDescriptors) Len() int {
	return len(slice)
}

func (slice ByThreatDescriptors) Less(i, j int) bool {
	if slice[i].ThreatType != slice[j].ThreatType {
		return slice[i].ThreatType < slice[j].ThreatType
	}

	if slice[i].PlatformType != slice[j].PlatformType {
		return slice[i].PlatformType < slice[j].PlatformType
	}
	return slice[i].ThreatEntryType < slice[j].ThreatEntryType
}

func (slice ByThreatDescriptors) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func Equal(tbh1, tbh2 threatsByHash) bool {
	if len(tbh1) != len(tbh2) {
		return false
	}
	for h, tds1 := range tbh1 {
		t1 := tds1
		sort.Sort(ByThreatDescriptors(t1))
		tds2, ok := tbh2[h]
		if !ok {
			return false
		}
		t2 := tds2
		sort.Sort(ByThreatDescriptors(t2))
		if !reflect.DeepEqual(t1, t2) {
			log.Println("%v \n%v", h, t1, t2)
			return false
		}
	}
	return true
}

func TestDatabaseInit(t *testing.T) {
	path := mustGetTempFile(t)
	defer os.Remove(path)

	now := time.Unix(1451436338, 951473000)
	mockNow := func() time.Time { return now }

	vectors := []struct {
		config *Config   // Input configuration
		oldDB  *database // The old database (before export)
		newDB  *database // The expected new database (after import)
		fail   bool      // Expected failure
	}{{
		// Load from a valid database file.
		config: &Config{
			ThreatLists: []ThreatDescriptor{
				{0, 2, 3},
				{1, 2, 3},
			},
			UpdatePeriod: DefaultUpdatePeriod,
		},
		oldDB: &database{
			last: now.Add(-DefaultUpdatePeriod + time.Minute),
			tbd: threatsByDescriptor{
				{0, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"aaa", "bbb"},
					SHA256: mustDecodeHex(t, "2ce109e9d0faf820b2434e166297934e6177b65ab9951dbc3e204cad4689b39c"),
					State:  []byte("state1"),
				},
				{1, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"bbb", "ccc"},
					SHA256: mustDecodeHex(t, "b0c834406bff3cc7a40bf117469aff269f2c0f8c53a8c248c5da72daa2794f57"),
					State:  []byte("state2"),
				},
			},
		},
		newDB: &database{
			last: now.Add(-DefaultUpdatePeriod + time.Minute),
			tbd: threatsByDescriptor{
				{0, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"aaa", "bbb"},
					SHA256: mustDecodeHex(t, "2ce109e9d0faf820b2434e166297934e6177b65ab9951dbc3e204cad4689b39c"),
					State:  []byte("state1"),
				},
				{1, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"bbb", "ccc"},
					SHA256: mustDecodeHex(t, "b0c834406bff3cc7a40bf117469aff269f2c0f8c53a8c248c5da72daa2794f57"),
					State:  []byte("state2"),
				},
			},
			tbh: threatsByHash{
				"aaa": []ThreatDescriptor{{0, 2, 3}},
				"bbb": []ThreatDescriptor{{0, 2, 3}, {1, 2, 3}},
				"ccc": []ThreatDescriptor{{1, 2, 3}},
			},
		},
	}, {
		// Load from a valid database file with more descriptors than in configuration.
		config: &Config{
			ThreatLists: []ThreatDescriptor{{0, 2, 3}},
		},
		oldDB: &database{
			last: now,
			tbd: threatsByDescriptor{
				{0, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"aaa", "bbb"},
					SHA256: mustDecodeHex(t, "2ce109e9d0faf820b2434e166297934e6177b65ab9951dbc3e204cad4689b39c"),
					State:  []byte("state1"),
				},
				{1, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"bbb", "ccc"},
					SHA256: mustDecodeHex(t, "b0c834406bff3cc7a40bf117469aff269f2c0f8c53a8c248c5da72daa2794f57"),
					State:  []byte("state2"),
				},
				{3, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"xxx", "yyy", "zzz"},
					SHA256: mustDecodeHex(t, "cc6c955cadf2cc09442c0848ce8e165b8f9aa5974916de7186a9e1b6c4e7937e"),
				},
			},
		},
		newDB: &database{
			last: now,
			tbd: threatsByDescriptor{
				{0, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"aaa", "bbb"},
					SHA256: mustDecodeHex(t, "2ce109e9d0faf820b2434e166297934e6177b65ab9951dbc3e204cad4689b39c"),
					State:  []byte("state1"),
				},
			},
			tbh: threatsByHash{
				"aaa": []ThreatDescriptor{{0, 2, 3}},
				"bbb": []ThreatDescriptor{{0, 2, 3}},
			},
		},
	}, {
		// Load from a invalid database file with fewer descriptors than in configuration.
		config: &Config{
			ThreatLists: []ThreatDescriptor{
				{0, 1, 3},
				{0, 2, 3},
				{1, 1, 3},
				{1, 2, 3},
			},
		},
		oldDB: &database{
			last: now,
			tbd: threatsByDescriptor{
				{0, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"aaa", "bbb"},
					SHA256: mustDecodeHex(t, "2ce109e9d0faf820b2434e166297934e6177b65ab9951dbc3e204cad4689b39c"),
					State:  []byte("state1"),
				},
				{1, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"bbb", "ccc"},
					SHA256: mustDecodeHex(t, "b0c834406bff3cc7a40bf117469aff269f2c0f8c53a8c248c5da72daa2794f57"),
					State:  []byte("state2"),
				},
				{0, 1, 3}: partialHashes{
					Hashes: []hashPrefix{"xxx", "yyy", "zzz"},
					SHA256: mustDecodeHex(t, "cc6c955cadf2cc09442c0848ce8e165b8f9aa5974916de7186a9e1b6c4e7937e"),
				},
			},
		},
		newDB: &database{},
		fail:  true,
	}, {
		// Load from a stale database file.
		config: &Config{
			ThreatLists: []ThreatDescriptor{
				{0, 2, 3},
				{1, 2, 3},
			},
			UpdatePeriod: DefaultUpdatePeriod,
		},
		oldDB: &database{
			last: now.Add(-DefaultUpdatePeriod - time.Minute),
			tbd: threatsByDescriptor{
				{0, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"aaa", "bbb"},
					SHA256: mustDecodeHex(t, "2ce109e9d0faf820b2434e166297934e6177b65ab9951dbc3e204cad4689b39c"),
					State:  []byte("state1"),
				},
				{1, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"bbb", "ccc"},
					SHA256: mustDecodeHex(t, "b0c834406bff3cc7a40bf117469aff269f2c0f8c53a8c248c5da72daa2794f57"),
					State:  []byte("state2"),
				},
			},
		},
		newDB: &database{},
		fail:  true,
	}, {
		// Load from a corrupted database file (has bad SHA256 checksums).
		config: &Config{
			ThreatLists: []ThreatDescriptor{
				{0, 2, 3},
				{1, 2, 3},
			},
		},
		oldDB: &database{
			last: now,
			tbd: threatsByDescriptor{
				{0, 2, 3}: partialHashes{
					Hashes: []hashPrefix{"aaa", "bbb"},
					State:  []byte("state1"),
					SHA256: []byte("bad checksum"),
				},
			},
		},
		newDB: &database{},
		fail:  true,
	}}

	logger := log.New(ioutil.Discard, "", 0)
	for i, v := range vectors {
		v.config.DBPath = path

		db1 := v.oldDB
		db1.config = v.config
		if err := db1.save(); err != nil {
			t.Errorf("test %d, unexpected save error: %v", i, err)
		}

		db2 := new(database)
		v.config.now = mockNow
		if fail := !db2.Init(v.config, logger); fail != v.fail {
			t.Errorf("test %d, mismatching status:\ngot  %v\nwant %v", i, fail, v.fail)
		}
		if !reflect.DeepEqual(db2.tbd, v.newDB.tbd) {
			t.Errorf("test %d, mismatching database contents:\ngot  %+v\nwant %+v", i, db2, v.newDB)
		}
		if !Equal(db2.tbh, v.newDB.tbh) {
			t.Errorf("test %d, mismatching database contents:\ngot  %+v\nwant %+v", i, db2, v.newDB)
		}
	}
}

func TestDatabaseUpdate(t *testing.T) {
	var (
		td013 = ThreatDescriptor{0, 1, 3}
		td014 = ThreatDescriptor{0, 1, 4}
		td113 = ThreatDescriptor{1, 1, 3}
		td114 = ThreatDescriptor{1, 1, 4}

		full    = int(pb.FetchThreatListUpdatesResponse_ListUpdateResponse_FULL_UPDATE)
		partial = int(pb.FetchThreatListUpdatesResponse_ListUpdateResponse_PARTIAL_UPDATE)

		config = &Config{
			ThreatLists: []ThreatDescriptor{
				{0, 2, 3},
				{0, 2, 4},
				{1, 2, 3},
				{1, 2, 4},
			},
		}
		logger = log.New(ioutil.Discard, "", 0)
	)

	// Helper function to aid in the construction on responses.
	newResp := func(td ThreatDescriptor, rtype int, dels []int32, adds []string, state string, chksum string) *pb.FetchThreatListUpdatesResponse_ListUpdateResponse {
		resp := &pb.FetchThreatListUpdatesResponse_ListUpdateResponse{
			ThreatType:      pb.ThreatType(td.ThreatType),
			PlatformType:    pb.PlatformType(td.PlatformType),
			ThreatEntryType: pb.ThreatEntryType(td.ThreatEntryType),
			ResponseType:    pb.FetchThreatListUpdatesResponse_ListUpdateResponse_ResponseType(rtype),
			NewClientState:  []byte(state),
			Checksum:        &pb.Checksum{Sha256: mustDecodeHex(t, chksum)},
		}
		if dels != nil {
			resp.Removals = []*pb.ThreatEntrySet{{
				CompressionType: pb.CompressionType_RAW,
				RawIndices:      &pb.RawIndices{Indices: dels},
			}}
		}
		if adds != nil {
			bySize := make(map[int][]string)
			for _, s := range adds {
				bySize[len(s)] = append(bySize[len(s)], s)
			}
			for n, hs := range bySize {
				sort.Strings(hs)
				resp.Additions = append(resp.Additions, &pb.ThreatEntrySet{
					CompressionType: pb.CompressionType_RAW,
					RawHashes: &pb.RawHashes{
						PrefixSize: int32(n),
						RawHashes:  []byte(strings.Join(hs, "")),
					},
				})
			}
		}
		return resp
	}

	// Setup mocking objects.
	var now time.Time
	mockNow := func() time.Time { return now }
	config.now = mockNow

	var resp pb.FetchThreatListUpdatesResponse
	mockAPI := &mockAPI{
		listUpdate: func(*pb.FetchThreatListUpdatesRequest) (*pb.FetchThreatListUpdatesResponse, error) {
			return &resp, nil
		},
	}

	// Setup the database under test.
	var gotDB, wantDB *database
	db := &database{config: config, log: logger}

	// Update 0: partial update on empty database.
	now = now.Add(time.Hour)
	resp = pb.FetchThreatListUpdatesResponse{
		ListUpdateResponses: []*pb.FetchThreatListUpdatesResponse_ListUpdateResponse{
			newResp(td013, full, nil, nil,
				"a0", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			newResp(td113, full, nil, nil,
				"b0", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			newResp(td014, full, nil, nil,
				"c0", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			newResp(td114, partial, []int32{0, 1, 2, 3}, nil,
				"d0", "0000000000000000000000000000000000000000000000000000000000000000"),
		},
	}
	db.Update(mockAPI)
	if db.err == nil {
		t.Fatalf("update 0, unexpected update success")
	}

	// Update 1: full update to all values.
	now = now.Add(time.Hour)
	resp = pb.FetchThreatListUpdatesResponse{
		ListUpdateResponses: []*pb.FetchThreatListUpdatesResponse_ListUpdateResponse{
			newResp(td013, full, nil, []string{"aaaa", "bbbb", "cccc", "0421e", "0421f", "a64392f6f89487"},
				"a1", "6a2480447ff0715d5c28090c3333fba69bd918faad4e9e0f977f3cc76f422ad6"),
			newResp(td113, full, nil, nil,
				"b1", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			newResp(td014, full, nil, []string{"aaaa", "bbbb", "cccc", "dddd"},
				"c1", "147eb9dcde0e090429c01dbf634fd9b69a7f141f005c387a9c00498908499dde"),
			newResp(td114, full, nil, []string{"aaaa", "0421e", "666666", "7777777", "88888888"},
				"d1", "a3b93fac424834c2447e2dbe5db3ec8553519777523907ea310e207f556a7637"),
		},
	}
	db.Update(mockAPI)
	if db.err != nil {
		t.Fatalf("update 1, unexpected update error: %v", db.err)
	}
	gotDB = &database{last: db.last, tbd: db.tbd, tbh: db.tbh}
	wantDB = &database{
		last: now,
		tbd: threatsByDescriptor{
			td013: {
				Hashes: []hashPrefix{"0421e", "0421f", "a64392f6f89487", "aaaa", "bbbb", "cccc"},
				SHA256: gotDB.tbd[td013].SHA256,
				State:  []byte{0x61, 0x31},
			},
			td113: {
				SHA256: gotDB.tbd[td113].SHA256,
				State:  []byte{0x62, 0x31},
			},
			td014: {
				Hashes: []hashPrefix{"aaaa", "bbbb", "cccc", "dddd"},
				SHA256: gotDB.tbd[td014].SHA256,
				State:  []byte{0x63, 0x31},
			},
			td114: {
				Hashes: []hashPrefix{"0421e", "666666", "7777777", "88888888", "aaaa"},
				SHA256: gotDB.tbd[td114].SHA256,
				State:  []byte{0x64, 0x31},
			},
		},
		tbh: threatsByHash{
			"0421e":          []ThreatDescriptor{td114, td013},
			"0421f":          []ThreatDescriptor{td013},
			"666666":         []ThreatDescriptor{td114},
			"7777777":        []ThreatDescriptor{td114},
			"88888888":       []ThreatDescriptor{td114},
			"a64392f6f89487": []ThreatDescriptor{td013},
			"aaaa":           []ThreatDescriptor{td114, td014, td013},
			"bbbb":           []ThreatDescriptor{td014, td013},
			"cccc":           []ThreatDescriptor{td014, td013},
			"dddd":           []ThreatDescriptor{td014},
		},
	}
	if !reflect.DeepEqual(gotDB.tbd, wantDB.tbd) {
		t.Errorf("update 1, database by descriptor state mismatch:\ngot  %+v\nwant %+v", gotDB.tbd, wantDB.tbd)
	}
	if !Equal(gotDB.tbh, wantDB.tbh) {
		t.Fatalf("update 1, database by hash state mismatch:\ngot  %+v\nwant %+v", gotDB.tbh, wantDB.tbh)
	}

	// Update 2: partial update with no changes.
	now = now.Add(time.Hour)
	resp = pb.FetchThreatListUpdatesResponse{
		ListUpdateResponses: []*pb.FetchThreatListUpdatesResponse_ListUpdateResponse{
			newResp(td013, partial, nil, nil,
				"a1", "6a2480447ff0715d5c28090c3333fba69bd918faad4e9e0f977f3cc76f422ad6"),
			newResp(td113, partial, nil, nil,
				"b1", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			newResp(td014, partial, nil, nil,
				"c1", "147eb9dcde0e090429c01dbf634fd9b69a7f141f005c387a9c00498908499dde"),
			newResp(td114, partial, nil, nil,
				"d1", "a3b93fac424834c2447e2dbe5db3ec8553519777523907ea310e207f556a7637"),
		},
	}
	db.Update(mockAPI)
	if db.err != nil {
		t.Fatalf("update 2, unexpected update error: %v", db.err)
	}
	gotDB = &database{last: db.last, tbd: db.tbd, tbh: db.tbh}
	wantDB.last = now

	if !reflect.DeepEqual(gotDB.tbd, wantDB.tbd) {
		t.Errorf("update 2, database by descriptor state mismatch:\ngot  %+v\nwant %+v", gotDB.tbd, wantDB.tbd)
	}
	if !Equal(gotDB.tbh, wantDB.tbh) {
		t.Fatalf("update 2, database by hash state mismatch:\ngot  %+v\nwant %+v", gotDB.tbh, wantDB.tbh)
	}

	// Update 3: full update and partial update with removals and additions.
	now = now.Add(time.Hour)
	resp = pb.FetchThreatListUpdatesResponse{
		ListUpdateResponses: []*pb.FetchThreatListUpdatesResponse_ListUpdateResponse{
			newResp(td013, partial, []int32{0, 2, 4}, nil,
				"a2", "bd3291e0b4fc7522ee3363376ded7801b316184722d83d224948889dfcf12465"),
			newResp(td113, partial, nil, []string{"aaaa", "bbbb", "cccc"},
				"b2", "11c85195ae99540ac07f80e2905e6e39aaefc4ac94cd380f366e79ba83560566"),
			newResp(td014, partial, []int32{1, 3}, []string{"eeee", "ffff"},
				"c2", "d8b19bc1d972cae450d65494565d2c04653894618faf9b37148e2c78ea3807e5"),
			newResp(td114, full, nil, []string{"AAAA", "0421E"},
				"d2", "b742965b7a759ba0254685bfc6edae3b1ba54d0168fb86f526d6c79c3d44c753"),
		},
	}
	db.Update(mockAPI)
	if db.err != nil {
		t.Fatalf("update 3, unexpected update error: %v", db.err)
	}
	gotDB = &database{last: db.last, tbd: db.tbd, tbh: db.tbh}
	wantDB = &database{
		last: now,
		tbd: threatsByDescriptor{
			td013: {
				Hashes: []hashPrefix{"0421f", "aaaa", "cccc"},
				SHA256: gotDB.tbd[td013].SHA256,
				State:  []byte{0x61, 0x32},
			},
			td113: {
				Hashes: []hashPrefix{"aaaa", "bbbb", "cccc"},
				SHA256: gotDB.tbd[td113].SHA256,
				State:  []byte{0x62, 0x32},
			},
			td014: {
				Hashes: []hashPrefix{"aaaa", "cccc", "eeee", "ffff"},
				SHA256: gotDB.tbd[td014].SHA256,
				State:  []byte{0x63, 0x32},
			},
			td114: {
				Hashes: []hashPrefix{"0421E", "AAAA"},
				SHA256: gotDB.tbd[td114].SHA256,
				State:  []byte{0x64, 0x32},
			},
		},
		tbh: threatsByHash{
			"0421E": []ThreatDescriptor{td114},
			"0421f": []ThreatDescriptor{td013},
			"aaaa":  []ThreatDescriptor{td013, td113, td014},
			"AAAA":  []ThreatDescriptor{td114},
			"bbbb":  []ThreatDescriptor{td113},
			"cccc":  []ThreatDescriptor{td013, td113, td014},
			"eeee":  []ThreatDescriptor{td014},
			"ffff":  []ThreatDescriptor{td014},
		},
	}
	if !reflect.DeepEqual(gotDB.tbd, wantDB.tbd) {
		t.Errorf("update 3, database by descriptor state mismatch:\ngot  %+v\nwant %+v", gotDB.tbd, wantDB.tbd)
	}
	if !Equal(gotDB.tbh, wantDB.tbh) {
		t.Fatalf("update 3, database by hash state mismatch:\ngot  %+v\nwant %+v", gotDB.tbh, wantDB.tbh)
	}
	// Update 4: invalid SHA256 checksum.
	now = now.Add(time.Hour)
	resp = pb.FetchThreatListUpdatesResponse{
		ListUpdateResponses: []*pb.FetchThreatListUpdatesResponse_ListUpdateResponse{
			newResp(td013, partial, []int32{0, 1}, []string{"fizz", "buzz"},
				"a3", "bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0"),
		},
	}
	db.Update(mockAPI)
	if db.err == nil {
		t.Fatalf("update 4, unexpected update success")
	}
	gotDB = &database{last: db.last, tbd: db.tbd, tbh: db.tbh}
	wantDB = &database{}
	if !reflect.DeepEqual(gotDB, wantDB) {
		t.Fatalf("update 4, database state mismatch:\ngot  %+v\nwant %+v", gotDB, wantDB)
	}

	// Update 5: removal index is out-of-bounds.
	now = now.Add(time.Hour)
	resp = pb.FetchThreatListUpdatesResponse{
		ListUpdateResponses: []*pb.FetchThreatListUpdatesResponse_ListUpdateResponse{
			newResp(td013, partial, []int32{9000}, []string{"fizz", "buzz"},
				"a4", "5d6506974928a003d2a0ccbd7a40b5341ad10578fd3f54527087c5ecbbd17a12"),
		},
	}
	db.Update(mockAPI)
	if db.err == nil {
		t.Fatalf("update 5, unexpected update success")
	}
	gotDB = &database{last: db.last, tbd: db.tbd, tbh: db.tbh}
	wantDB = &database{}
	if !reflect.DeepEqual(gotDB, wantDB) {
		t.Fatalf("update 5, database state mismatch:\ngot  %+v\nwant %+v", gotDB, wantDB)
	}
}

func TestDatabaseLookup(t *testing.T) {
	var (
		td000 = ThreatDescriptor{0, 0, 0}
		td001 = ThreatDescriptor{0, 0, 1}
		td012 = ThreatDescriptor{0, 1, 2}
		td123 = ThreatDescriptor{1, 2, 3}
		td234 = ThreatDescriptor{2, 3, 4}
		td456 = ThreatDescriptor{4, 5, 6}
		td567 = ThreatDescriptor{5, 6, 7}
		td678 = ThreatDescriptor{6, 7, 8}
	)

	db := &database{tbh: threatsByHash{
		"1e25395a9b1b8": []ThreatDescriptor{td123, td234, td567, td678},
		"26e307":        []ThreatDescriptor{td567, td001, td000},
		"3f93":          []ThreatDescriptor{td123, td012, td001},
		"524d":          []ThreatDescriptor{td000, td678, td456, td678, td567},
		"59b8":          []ThreatDescriptor{td456},
		"5c6655d2":      []ThreatDescriptor{td123},
		"5c6655d3":      []ThreatDescriptor{td012, td456},
		"5c6655d4":      []ThreatDescriptor{td001, td012, td000},
		"5c6655d5":      []ThreatDescriptor{td123, td567},
		"7294":          []ThreatDescriptor{td001, td678, td567, td012, td123},
		"cad78c1c":      []ThreatDescriptor{td456, td456, td123, td567},
		"cad78c628":     []ThreatDescriptor{td678, td234},
		"cad78c68":      []ThreatDescriptor{td234},
	}}

	vectors := []struct {
		input  hashPrefix // Input full hash
		output hashPrefix // Output partial hash
	}{{
		input:  "3db40718dad209613a1fd9dced74dc0e",
		output: "", // Not found
	}, {
		input:  "59b8332112b29950f594cf957f4d0e63",
		output: "59b8",
	}, {
		input:  "524dfa307ba397754a35dcce0ee5f54a",
		output: "524d",
	}, {
		input:  "524dea307ba397754a35dcce0ee5f54a",
		output: "524d",
	}, {
		input:  "5c6655d2096dd9ffb3c9e2bd5f86798f",
		output: "5c6655d2",
	}, {
		input:  "5c6655d33db40718dad209613a1fd9dc",
		output: "5c6655d3",
	}, {
		input:  "1e25395a9b1b87db129a7d85ee7cc0fd",
		output: "1e25395a9b1b8",
	}}

	for i, v := range vectors {
		ph, m := db.Lookup(v.input)
		if ph != v.output {
			t.Errorf("test %d, partial hash mismatch: got %s, want %s", i, ph, v.output)
		}
		if !reflect.DeepEqual(m, db.tbh[ph]) {
			t.Errorf("test %d, results mismatch: got %v, want %v", i, m, db.tbh[ph])
		}
	}
}

func TestDatabasePersistence(t *testing.T) {
	path := mustGetTempFile(t)
	defer os.Remove(path)

	vectors := []struct {
		last time.Time           // Input last update time
		tbd  threatsByDescriptor // Input threatsByDescriptor
	}{{
		last: time.Time{},
	}, {
		last: time.Now(),
	}, {
		last: time.Unix(123456, 789),
		tbd: threatsByDescriptor{
			{0, 1, 2}: partialHashes{
				SHA256: mustDecodeHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
		},
	}, {
		last: time.Unix(987654321, 0),
		tbd: threatsByDescriptor{
			{3, 4, 5}: partialHashes{
				Hashes: []hashPrefix{"aaaa", "bbbb", "cccc", "dddd"},
				State:  []byte("meow meow meow!!!"),
				SHA256: mustDecodeHex(t, "147eb9dcde0e090429c01dbf634fd9b69a7f141f005c387a9c00498908499dde"),
			},
			{7, 8, 9}: partialHashes{
				Hashes: []hashPrefix{"xxxx", "yyyy", "zzzz"},
				State:  []byte("rawr rawr rawr!!!"),
				SHA256: mustDecodeHex(t, "20ffb2c3e9532153b96b956845381adc06095f8342fa2db1aafba6b0e9594d68"),
			},
		},
	}}

	for i, v := range vectors {
		db1 := &database{config: &Config{DBPath: path}, last: v.last, tbd: v.tbd}
		if err := db1.save(); err != nil {
			t.Errorf("test %d, unexpected save error: %v", i, err)
			continue
		}

		db2 := &database{config: &Config{DBPath: path}}
		if err := db2.load(); err != nil {
			t.Errorf("test %d, unexpected load error: %v", i, err)
			continue
		}

		if !reflect.DeepEqual(&db1, &db2) {
			t.Errorf("test %d, mismatching database contents:\ngot  %v\nwant %v", i, db2, db1)
		}
	}
}

func TestDatabaseSaveErrors(t *testing.T) {
	path := mustGetTempFile(t)
	defer os.Remove(path)

	// Set mode to be unwritable.
	if err := os.Chmod(path, 0444); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	db := &database{
		config: &Config{DBPath: path},
		log:    log.New(ioutil.Discard, "", 0),
	}
	if err := db.save(); err == nil {
		t.Errorf("unexpected save success")
	}
}

func TestDatabaseLoadErrors(t *testing.T) {
	path := mustGetTempFile(t)
	defer os.Remove(path)

	db1 := &database{
		config: &Config{DBPath: path},
		tbd: threatsByDescriptor{
			{3, 4, 5}: partialHashes{
				Hashes: []hashPrefix{"aaaa", "bbbb", "cccc", "dddd"},
				State:  []byte("meow meow meow!!!"),
				SHA256: nil, // Intentionally leave this out
			},
		},
		log: log.New(ioutil.Discard, "", 0),
	}
	if err := db1.save(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	db2 := &database{config: &Config{DBPath: path}}
	if err := db2.load(); err == nil {
		t.Errorf("unexpected success")
	}

	if err := os.Truncate(path, 13); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	db3 := &database{config: &Config{DBPath: path}}
	if err := db3.load(); err != io.ErrUnexpectedEOF {
		t.Errorf("mismatching error: got %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestDatabaseComputeSHA256(t *testing.T) {
	vectors := []struct {
		hashes []hashPrefix
		sha256 string
	}{{
		hashes: nil,
		sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}, {
		hashes: []hashPrefix{"xxxx", "yyyy", "zzzz"},
		sha256: "20ffb2c3e9532153b96b956845381adc06095f8342fa2db1aafba6b0e9594d68",
	}, {
		hashes: []hashPrefix{"aaaa", "bbbb", "cccc", "dddd"},
		sha256: "147eb9dcde0e090429c01dbf634fd9b69a7f141f005c387a9c00498908499dde",
	}}

	for i, v := range vectors {
		phs := partialHashes{Hashes: v.hashes}
		sha256 := hex.EncodeToString(phs.computeSHA256())
		if sha256 != v.sha256 {
			t.Errorf("test %d, mismatching hash:\ngot  %s\nwant %s", i, sha256, v.sha256)
		}
	}
}
