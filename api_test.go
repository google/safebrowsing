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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	pb "github.com/google/safebrowsing/internal/safebrowsing_proto"

	"github.com/golang/protobuf/proto"
)

type mockAPI struct {
	listUpdate func(context.Context, *pb.FetchThreatListUpdatesRequest) (*pb.FetchThreatListUpdatesResponse, error)
	hashLookup func(context.Context, *pb.FindFullHashesRequest) (*pb.FindFullHashesResponse, error)
}

func (m *mockAPI) ListUpdate(ctx context.Context, req *pb.FetchThreatListUpdatesRequest) (*pb.FetchThreatListUpdatesResponse, error) {
	return m.listUpdate(ctx, req)
}

func (m *mockAPI) HashLookup(ctx context.Context, req *pb.FindFullHashesRequest) (*pb.FindFullHashesResponse, error) {
	return m.hashLookup(ctx, req)
}

func TestNetAPI(t *testing.T) {
	var gotReq, wantReq proto.Message
	var gotResp, wantResp proto.Message
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p []byte
		var err error
		if p, err = ioutil.ReadAll(r.Body); err != nil {
			t.Fatalf("unexpected ioutil.ReadAll error: %v", err)
		}
		if err := proto.Unmarshal(p, gotReq); err != nil {
			t.Fatalf("unexpected proto.Unmarshal error: %v", err)
		}
		if p, err = proto.Marshal(wantResp); err != nil {
			t.Fatalf("unexpected proto.Marshal error: %v", err)
		}
		if _, err := w.Write(p); err != nil {
			t.Fatalf("unexpected ResponseWriter.Write error: %v", err)
		}
	}))
	defer ts.Close()

	api, err := newNetAPI(ts.URL, "fizzbuzz", "")
	if err != nil {
		t.Errorf("unexpected newNetAPI error: %v", err)
	}

	// Test that ListUpdate marshal/unmarshal works.
	wantReq = &pb.FetchThreatListUpdatesRequest{ListUpdateRequests: []*pb.FetchThreatListUpdatesRequest_ListUpdateRequest{
		{ThreatType: 0, PlatformType: 1, ThreatEntryType: 2, State: []byte("meow")},
		{ThreatType: 1, PlatformType: 2, ThreatEntryType: 3, State: []byte("rawr")},
		{ThreatType: 3, PlatformType: 4, ThreatEntryType: 5,
			Constraints: &pb.FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints{
				SupportedCompressions: []pb.CompressionType{1, 2, 3}}},
	}}
	wantResp = &pb.FetchThreatListUpdatesResponse{ListUpdateResponses: []*pb.FetchThreatListUpdatesResponse_ListUpdateResponse{
		{ThreatType: 0, PlatformType: 1, ThreatEntryType: 2, NewClientState: []byte("meow")},
		{ThreatType: 1, PlatformType: 2, ThreatEntryType: 3, ResponseType: 1},
		{ThreatType: 2, PlatformType: 3, ThreatEntryType: 4, Checksum: &pb.Checksum{Sha256: []byte("abcd")}},
		{ThreatType: 3, PlatformType: 4, ThreatEntryType: 5, Removals: []*pb.ThreatEntrySet{{
			CompressionType: 1, RawIndices: &pb.RawIndices{Indices: []int32{1, 2, 3}},
		}}},
	}}
	gotReq = &pb.FetchThreatListUpdatesRequest{}
	resp1, err := api.ListUpdate(context.Background(), wantReq.(*pb.FetchThreatListUpdatesRequest))
	gotResp = resp1
	if err != nil {
		t.Errorf("unexpected ListUpdate error: %v", err)
	}
	if !reflect.DeepEqual(gotReq, wantReq) {
		t.Errorf("mismatching ListUpdate requests:\ngot  %+v\nwant %+v", gotReq, wantReq)
	}
	if !reflect.DeepEqual(gotResp, wantResp) {
		t.Errorf("mismatching ListUpdate responses:\ngot  %+v\nwant %+v", gotResp, wantResp)
	}

	// Test that HashLookup marshal/unmarshal works.
	wantReq = &pb.FindFullHashesRequest{ThreatInfo: &pb.ThreatInfo{
		ThreatEntries:    []*pb.ThreatEntry{{Hash: []byte("aaaa")}, {Hash: []byte("bbbbb")}, {Hash: []byte("cccccc")}},
		ThreatTypes:      []pb.ThreatType{1, 2, 3},
		PlatformTypes:    []pb.PlatformType{4, 5, 6},
		ThreatEntryTypes: []pb.ThreatEntryType{7, 8, 9},
	}}
	wantResp = &pb.FindFullHashesResponse{Matches: []*pb.ThreatMatch{
		{ThreatType: 0, PlatformType: 1, ThreatEntryType: 2, Threat: &pb.ThreatEntry{Hash: []byte("abcd")}},
		{ThreatType: 1, PlatformType: 2, ThreatEntryType: 3, Threat: &pb.ThreatEntry{Hash: []byte("efgh")}},
		{ThreatType: 2, PlatformType: 3, ThreatEntryType: 4, Threat: &pb.ThreatEntry{Hash: []byte("ijkl")}},
	}}
	gotReq = &pb.FindFullHashesRequest{}
	resp2, err := api.HashLookup(context.Background(), wantReq.(*pb.FindFullHashesRequest))
	gotResp = resp2
	if err != nil {
		t.Errorf("unexpected HashLookup error: %v", err)
	}
	if !reflect.DeepEqual(gotReq, wantReq) {
		t.Errorf("mismatching HashLookup requests:\ngot  %+v\nwant %+v", gotReq, wantReq)
	}
	if !reflect.DeepEqual(gotResp, wantResp) {
		t.Errorf("mismatching HashLookup responses:\ngot  %+v\nwant %+v", gotResp, wantResp)
	}

	// Test canceled Context returns an error.
	wantReq = &pb.FindFullHashesRequest{ThreatInfo: &pb.ThreatInfo{
		ThreatEntries:    []*pb.ThreatEntry{{Hash: []byte("aaaa")}, {Hash: []byte("bbbbb")}, {Hash: []byte("cccccc")}},
		ThreatTypes:      []pb.ThreatType{1, 2, 3},
		PlatformTypes:    []pb.PlatformType{4, 5, 6},
		ThreatEntryTypes: []pb.ThreatEntryType{7, 8, 9},
	}}
	wantResp = &pb.FindFullHashesResponse{Matches: []*pb.ThreatMatch{
		{ThreatType: 0, PlatformType: 1, ThreatEntryType: 2, Threat: &pb.ThreatEntry{Hash: []byte("abcd")}},
		{ThreatType: 1, PlatformType: 2, ThreatEntryType: 3, Threat: &pb.ThreatEntry{Hash: []byte("efgh")}},
		{ThreatType: 2, PlatformType: 3, ThreatEntryType: 4, Threat: &pb.ThreatEntry{Hash: []byte("ijkl")}},
	}}
	gotReq = &pb.FindFullHashesRequest{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = api.HashLookup(ctx, wantReq.(*pb.FindFullHashesRequest))
	if err == nil {
		t.Errorf("unexpected HashLookup success, wanted HTTP request canceled")
	}

	// Test for detection of incorrect protobufs.
	wantReq = &pb.FindFullHashesRequest{ThreatInfo: &pb.ThreatInfo{
		ThreatEntryTypes: []pb.ThreatEntryType{7, 8, 9},
	}}
	wantResp = &pb.FetchThreatListUpdatesResponse{ListUpdateResponses: []*pb.FetchThreatListUpdatesResponse_ListUpdateResponse{
		{ThreatType: 1, PlatformType: 2, ThreatEntryType: 3, ResponseType: 1},
	}}
	gotReq = &pb.FindFullHashesRequest{}
	_, err = api.HashLookup(context.Background(), wantReq.(*pb.FindFullHashesRequest))
	if err == nil {
		t.Errorf("unexpected HashLookup success")
	}
}
