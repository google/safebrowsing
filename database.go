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
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	pb "github.com/google/safebrowsing/internal/safebrowsing_proto"
)

// database tracks the state of the threat lists published by the Safe Browsing
// API. Since the global blacklist is constantly changing, the contents of the
// database needs to be periodically synced with the Safe Browsing servers in
// order to provide protection for the latest threats.
//
// The process for updating the database is as follows:
//	* At startup, if a database file is provided, then load it. If loaded
//	properly (not corrupted and not stale), then set tbd as the contents.
//	Otherwise, pull a new threat list from the Safe Browsing API.
//	* Periodically, synchronize the database with the Safe Browsing API.
//	This uses the State fields to update only parts of the threat list that have
//	changed since the last sync.
//	* Anytime tbd is updated, generate a new tbh.
//
// The processing for querying the database is as follows:
//	* Check if the requested full hash matches any partial hash in tbh.
//	If a match is found, return a set of ThreatDescriptors with a partial match.
type database struct {
	config *Config

	// threatsByDescriptor maps ThreatDescriptors to lists of partial hashes.
	// This data structure is in a format that is easily updated by the API.
	// It is also the form that is written to disk.
	tbd threatsByDescriptor
	md  sync.Mutex // Protects tbd

	// threatsByHash maps partial hashes to a set of ThreatDescriptors.
	// This data structure is in a format that is easily queried.
	tbh threatsByHash
	mh  sync.RWMutex // Protects tbh, err, and last

	err  error     // Last error encountered
	last time.Time // Last time the threat list were synced

	log *log.Logger
}

type threatsByDescriptor map[ThreatDescriptor]partialHashes
type partialHashes struct {
	Hashes []hashPrefix
	SHA256 []byte // The SHA256 over Hashes
	State  []byte // Arbitrary binary blob to synchronize state with API
}

type threatsByHash map[hashPrefix][]ThreatDescriptor

// databaseFormat is a light struct used only for gob encoding and decoding.
// As written to disk, the format of the database file is basically the gzip
// compressed version of the gob encoding of databaseFormat.
type databaseFormat struct {
	Table threatsByDescriptor
	Time  time.Time
}

// Init initializes the database from the specified file in config.DBPath.
// It reports true if the database was successfully loaded.
func (db *database) Init(config *Config, logger *log.Logger) bool {
	db.config = config
	db.log = logger
	if db.config.DBPath == "" {
		db.log.Printf("no database file specified")
		db.setError(errStale)
		return false
	}
	if err := db.load(); err != nil {
		db.log.Printf("load failure: %v", err)
		db.setError(err)
		return false
	}

	// Validate that the database threat list stored on disk is at least a
	// superset of the specified configuration.
	if db.config.now().Sub(db.last) > db.config.UpdatePeriod {
		db.log.Printf("database loaded is stale")
		db.setError(errStale)
		return false
	}
	tbdNew := make(threatsByDescriptor)
	for _, td := range db.config.ThreatLists {
		if row, ok := db.tbd[td]; ok {
			tbdNew[td] = row
		} else {
			db.log.Printf("database configuration mismatch")
			db.setError(errStale)
			return false
		}
	}
	db.tbd = tbdNew
	db.generateThreatsByHash(db.last)
	return true
}

// Status reports the health of the database. If in a faulted state, the db
// may repair itself on the next Update.
func (db *database) Status() error {
	db.mh.RLock()
	defer db.mh.RUnlock()

	if db.err != nil {
		return db.err
	}
	if db.config.now().Sub(db.last) > db.config.UpdatePeriod {
		return errStale
	}
	return nil
}

// Update synchronizes the local threat lists with those maintained by the
// global Safe Browsing API servers. If the update is successful, Status should
// report a nil error.
func (db *database) Update(api api) {
	db.md.Lock()
	defer db.md.Unlock()

	// Construct the request.
	var numTypes int
	var s []*pb.FetchThreatListUpdatesRequest_ListUpdateRequest
	for _, td := range db.config.ThreatLists {
		var state []byte
		if row, ok := db.tbd[td]; ok {
			state = row.State
		}

		s = append(s, &pb.FetchThreatListUpdatesRequest_ListUpdateRequest{
			ThreatType:      pb.ThreatType(td.ThreatType),
			PlatformType:    pb.PlatformType(td.PlatformType),
			ThreatEntryType: pb.ThreatEntryType(td.ThreatEntryType),
			Constraints: &pb.FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints{
				SupportedCompressions: db.config.compressionTypes},
			State: state,
		})
		numTypes++
	}
	req := &pb.FetchThreatListUpdatesRequest{
		Client: &pb.ClientInfo{
			ClientId:      db.config.ID,
			ClientVersion: db.config.Version,
		},
		ListUpdateRequests: s,
	}

	// Query the API for the threat list and update the database.
	last := db.config.now()
	resp, err := api.ListUpdate(req)
	if err != nil {
		db.log.Printf("ListUpdate failure: %v", err)
		db.setError(err)
		return
	}
	if len(resp.ListUpdateResponses) != numTypes {
		db.log.Printf("invalid server response: got %d, want %d threat lists",
			len(resp.ListUpdateResponses), numTypes)
		db.setError(errors.New("safebrowsing: threat list count mismatch"))
		return
	}

	// Update the threat database with the response.
	if db.tbd == nil {
		db.tbd = make(threatsByDescriptor)
	}
	if err := db.tbd.update(resp); err != nil {
		db.log.Printf("update failure: %v", err)
		db.setError(err)
		return
	}

	// Regenerate the database and store it.
	db.generateThreatsByHash(last)
	if db.config.DBPath != "" {
		// Semantically, we ignore save errors, but we do log them.
		if err := db.save(); err != nil {
			db.log.Printf("save failure: %v", err)
		}
	}
}

// Lookup looks up the full hash in the threat list and returns a partial
// hash and a set of ThreatDescriptors that may match the full hash.
//
// The ThreatDescriptor set must not be mutated.
func (db *database) Lookup(hash hashPrefix) (hashPrefix, []ThreatDescriptor) {
	if !hash.IsFull() {
		panic("hash is not full")
	}

	db.mh.RLock()
	defer db.mh.RUnlock()

	for i := minHashPrefixLength; i <= maxHashPrefixLength; i++ {
		if threats, ok := db.tbh[hash[:i]]; ok {
			return hash[:i], threats
		}
	}
	return "", nil
}

// setError clears the database state and sets the last error to be err.
//
// This assumes that the db.md lock is already held.
func (db *database) setError(err error) {
	db.tbd = nil

	db.mh.Lock()
	db.tbh, db.err, db.last = nil, err, time.Time{}
	db.mh.Unlock()
}

// generateThreatsByHash regenerates the threatsByHash data structure from the
// threatsByDescriptor data structure and stores the last timestamp.
//
// This assumes that the db.md lock is already held.
func (db *database) generateThreatsByHash(last time.Time) {
	tbh := make(threatsByHash)
	for td, phs := range db.tbd {
		for _, h := range phs.Hashes {
			tbh[h] = append(tbh[h], td)
		}
	}
	db.mh.Lock()
	wasBad := db.err != nil
	db.tbh, db.err, db.last = tbh, nil, last
	db.mh.Unlock()

	if wasBad {
		db.log.Printf("database is now healthy")
	}
}

// save saves the database threat list to a file.
//
// This assumes that the db.md lock is already held.
func (db *database) save() (err error) {
	var file *os.File
	file, err = os.Create(db.config.DBPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}()

	gz, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer func() {
		if zerr := gz.Close(); err == nil {
			err = zerr
		}
	}()

	encoder := gob.NewEncoder(gz)
	if err = encoder.Encode(&databaseFormat{db.tbd, db.last}); err != nil {
		return err
	}
	return nil
}

// load loads the database state from a file.
//
// This assumes that the db.md lock is already held.
func (db *database) load() (err error) {
	var file *os.File
	file, err = os.Open(db.config.DBPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer func() {
		if zerr := gz.Close(); err == nil {
			err = zerr
		}
	}()

	decoder := gob.NewDecoder(gz)
	dbState := new(databaseFormat)
	if err = decoder.Decode(&dbState); err != nil {
		return err
	}
	for _, dv := range dbState.Table {
		if !bytes.Equal(dv.SHA256, dv.computeSHA256()) {
			return errors.New("safebrowsing: threat list SHA256 mismatch")
		}
	}
	db.tbd = dbState.Table
	db.last = dbState.Time
	return nil
}

// update updates the threat list according to the API response.
func (tbd threatsByDescriptor) update(resp *pb.FetchThreatListUpdatesResponse) error {
	// For each update response do the removes and adds
	for _, m := range resp.GetListUpdateResponses() {
		td := ThreatDescriptor{
			PlatformType:    PlatformType(m.PlatformType),
			ThreatType:      ThreatType(m.ThreatType),
			ThreatEntryType: ThreatEntryType(m.ThreatEntryType),
		}

		phs, ok := tbd[td]
		switch m.ResponseType {
		case pb.FetchThreatListUpdatesResponse_ListUpdateResponse_PARTIAL_UPDATE:
			if !ok {
				return errors.New("safebrowsing: partial update received for non-existent key")
			}
		case pb.FetchThreatListUpdatesResponse_ListUpdateResponse_FULL_UPDATE:
			if len(m.Removals) > 0 {
				return errors.New("safebrowsing: indices to be removed included in a full update")
			}
			phs = partialHashes{}
		default:
			return errors.New("safebrowsing: unknown response type")
		}

		for _, removal := range m.Removals {
			idxs, err := decodeIndices(removal)
			if err != nil {
				return err
			}

			for _, i := range idxs {
				if i < 0 || i >= int32(len(phs.Hashes)) {
					return errors.New("safebrowsing: invalid removal index")
				}
				phs.Hashes[i] = ""
			}
		}

		// If any removal was performed, compact the list of hashes.
		if len(m.Removals) > 0 {
			compactHashes := phs.Hashes[:0]
			for _, h := range phs.Hashes {
				if h != "" {
					compactHashes = append(compactHashes, h)
				}
			}
			phs.Hashes = compactHashes
		}

		for _, addition := range m.Additions {
			hashes, err := decodeHashes(addition)
			if err != nil {
				return err
			}
			phs.Hashes = append(phs.Hashes, hashes...)
		}

		// We ensure that the hashes are sorted for the next update cycle.
		// The removal logic uses indices according to the sorted hashes.
		sortHashes(phs.Hashes)

		phs.SHA256 = m.GetChecksum().Sha256
		if !bytes.Equal(phs.SHA256, phs.computeSHA256()) {
			return errors.New("safebrowsing: threat list SHA256 mismatch")
		}

		phs.State = m.NewClientState
		tbd[td] = phs
	}
	return nil
}

// computeSHA256 computes the SHA256 for the hash prefixes.
func (phs partialHashes) computeSHA256() []byte {
	hash := sha256.New()
	for _, b := range phs.Hashes {
		hash.Write([]byte(b))
	}
	return hash.Sum(nil)
}
