// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

package safebrowsing

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"
)

const (
	maxRetryDelay  = 24 * time.Hour
	baseRetryDelay = 15 * time.Minute
	jitter         = 30 * time.Second
)

type database struct {
	config *Config
	tfu    threatsForUpdate
	mu     sync.Mutex
	tfl    threatsForLookup
	ml     sync.RWMutex

	err             error
	readyCh         chan struct{}
	last            time.Time
	next            time.Time
	freshUntil      time.Time
	lastAttempt     time.Time
	lastUpdateError string
	updateAPIErrors uint
	log             *log.Logger
}

type threatsForUpdate map[string]partialHashes

type partialHashes struct {
	Hashes     hashPrefixes
	SHA256     []byte
	Version    []byte
	ThreatType ThreatType
}

type threatsForLookup map[string]hashSet

type databaseFormat struct {
	Table      threatsForUpdate
	Time       time.Time
	NextUpdate time.Time
	FreshUntil time.Time
}

type DatabaseHealth struct {
	LastUpdate      time.Time
	NextUpdate      time.Time
	FreshUntil      time.Time
	LastAttempt     time.Time
	LastUpdateError string
	UpdatePeriod    time.Duration
	Age             time.Duration
	Healthy         bool
	Error           string
}

func (db *database) Init(config *Config, logger *log.Logger) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.setError(errors.New("not initialized"))
	db.config = config
	db.log = logger
	if db.readyCh == nil {
		db.readyCh = make(chan struct{})
	}
	if db.config.DBPath == "" {
		db.log.Printf("no database file specified")
		db.setError(errors.New("no database loaded"))
		return false
	}
	dbf, err := loadDatabase(db.config.DBPath)
	if err != nil {
		db.log.Printf("load failure: %v", err)
		db.setError(err)
		return false
	}
	nextUpdate := dbf.NextUpdate
	freshUntil := dbf.FreshUntil
	if nextUpdate.IsZero() {
		nextUpdate = dbf.Time.Add(db.config.UpdatePeriod)
	}
	if freshUntil.IsZero() {
		freshUntil = nextUpdate.Add(db.freshnessGrace())
	}
	if db.isStale(freshUntil) {
		db.log.Printf("database loaded is stale")
		db.ml.Lock()
		defer db.ml.Unlock()
		db.setStale()
		return false
	}

	tfuNew := make(threatsForUpdate)
	for _, list := range db.config.HashLists {
		row, ok := dbf.Table[list.Name]
		if !ok {
			db.log.Printf("database configuration mismatch, missing %v", list.Name)
			db.setError(errors.New("database configuration mismatch"))
			return false
		}
		row.ThreatType = list.ThreatType
		tfuNew[list.Name] = row
	}
	db.tfu = tfuNew
	db.generateThreatsForLookups(dbf.Time, nextUpdate, freshUntil)
	return true
}

func (db *database) Status() error {
	db.ml.RLock()
	if db.err != nil {
		err := db.err
		db.ml.RUnlock()
		return err
	}
	stale := db.isStale(db.freshUntil)
	db.ml.RUnlock()
	if stale {
		db.ml.Lock()
		db.setStale()
		err := db.err
		db.ml.Unlock()
		return err
	}
	return nil
}

func (db *database) UpdateLag() time.Duration {
	db.ml.RLock()
	next := db.next
	db.ml.RUnlock()
	if next.IsZero() || db.config.now().Before(next) {
		return 0
	}
	return db.config.now().Sub(next)
}

func (db *database) SinceLastUpdate() time.Duration {
	db.ml.RLock()
	defer db.ml.RUnlock()
	if db.last.IsZero() {
		return 0
	}
	return db.config.now().Sub(db.last)
}

func (db *database) UntilNextUpdate() time.Duration {
	db.ml.RLock()
	defer db.ml.RUnlock()
	if db.next.IsZero() || !db.config.now().Before(db.next) {
		return 0
	}
	return db.next.Sub(db.config.now())
}

func (db *database) Health() DatabaseHealth {
	err := db.Status()
	now := db.config.now()

	db.ml.RLock()
	health := DatabaseHealth{
		LastUpdate:      db.last,
		NextUpdate:      db.next,
		FreshUntil:      db.freshUntil,
		LastAttempt:     db.lastAttempt,
		LastUpdateError: db.lastUpdateError,
		UpdatePeriod:    db.config.UpdatePeriod,
		Healthy:         err == nil,
	}
	db.ml.RUnlock()
	if !health.LastUpdate.IsZero() {
		health.Age = now.Sub(health.LastUpdate)
	}
	if err != nil {
		health.Error = err.Error()
	}
	return health
}

func (db *database) Ready() <-chan struct{} {
	return db.readyCh
}

func (db *database) Update(ctx context.Context, api api) (time.Duration, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()

	names := make([]string, 0, len(db.config.HashLists))
	versions := make(map[string][]byte)
	for _, list := range db.config.HashLists {
		names = append(names, list.Name)
		if row, ok := db.tfu[list.Name]; ok {
			versions[list.Name] = row.Version
		}
	}

	last := db.config.now()
	db.recordUpdateAttempt(last)
	resp, err := api.ListUpdate(ctx, names, versions)
	if err != nil {
		db.log.Printf("ListUpdate failure (%d): %v", db.updateAPIErrors+1, err)
		db.recordUpdateFailure(err)
		n := 1 << db.updateAPIErrors
		delay := time.Duration(float64(n) * (rand.Float64() + 1) * float64(baseRetryDelay))
		if delay > maxRetryDelay {
			delay = maxRetryDelay
		}
		db.updateAPIErrors++
		return delay, false
	}
	db.updateAPIErrors = 0

	nextUpdateWait := db.config.UpdatePeriod + time.Duration(rand.Int31n(60)-30)*time.Second
	db.generateThreatsForUpdate()
	if db.tfu == nil {
		db.tfu = make(threatsForUpdate)
	}

	for _, list := range db.config.HashLists {
		row := db.tfu[list.Name]
		row.ThreatType = list.ThreatType
		db.tfu[list.Name] = row
	}
	if err := db.tfu.update(resp); err != nil {
		db.log.Printf("update failure: %v", err)
		db.recordUpdateFailure(err)
		db.tfu = nil
		return nextUpdateWait, false
	}

	for _, hl := range resp.HashLists {
		if wait := parseDuration(hl.MinimumWaitDuration); wait > nextUpdateWait {
			nextUpdateWait = wait
		}
	}

	nextUpdate := last.Add(nextUpdateWait)
	freshUntil := nextUpdate.Add(db.freshnessGrace())
	dbf := databaseFormat{
		Table:      make(threatsForUpdate),
		Time:       last,
		NextUpdate: nextUpdate,
		FreshUntil: freshUntil,
	}
	for name, phs := range db.tfu {
		dbf.Table[name] = phs
	}
	db.generateThreatsForLookups(last, nextUpdate, freshUntil)

	if db.config.DBPath != "" {
		if err := saveDatabase(db.config.DBPath, dbf); err != nil {
			db.log.Printf("save failure: %v", err)
		}
	}
	return nextUpdateWait, true
}

func (db *database) Lookup(hash hashPrefix) (hashPrefix, []HashList) {
	if !hash.IsFull() {
		panic("hash is not full")
	}

	var h hashPrefix
	var lists []HashList
	db.ml.RLock()
	for _, list := range db.config.HashLists {
		if hs, ok := db.tfl[list.Name]; ok {
			if n := hs.Lookup(hash); n > 0 {
				h = hash[:n]
				lists = append(lists, list)
			}
		}
	}
	db.ml.RUnlock()
	return h, lists
}

func (db *database) setError(err error) {
	db.tfu = nil
	db.ml.Lock()
	if db.err == nil {
		db.readyCh = make(chan struct{})
	}
	db.tfl, db.err, db.last = nil, err, time.Time{}
	db.next, db.freshUntil = time.Time{}, time.Time{}
	db.ml.Unlock()
}

func (db *database) isStale(freshUntil time.Time) bool {
	return freshUntil.IsZero() || db.config.now().After(freshUntil)
}

func (db *database) freshnessGrace() time.Duration {
	return db.config.UpdatePeriod + jitter
}

func (db *database) setStale() {
	if db.err == nil {
		db.readyCh = make(chan struct{})
	}
	if db.lastUpdateError != "" {
		db.err = errors.New(errStale.Error() + ": last update error: " + db.lastUpdateError)
	} else {
		db.err = errStale
	}
}

func (db *database) clearError() {
	db.ml.Lock()
	defer db.ml.Unlock()
	if db.err != nil {
		close(db.readyCh)
	}
	db.err = nil
	db.lastUpdateError = ""
}

func (db *database) recordUpdateAttempt(at time.Time) {
	db.ml.Lock()
	db.lastAttempt = at
	db.ml.Unlock()
}

func (db *database) recordUpdateFailure(err error) {
	db.ml.Lock()
	db.lastUpdateError = err.Error()
	db.ml.Unlock()
}

func (db *database) generateThreatsForUpdate() {
	if db.tfu == nil {
		db.tfu = make(threatsForUpdate)
	}
	db.ml.RLock()
	for name, hs := range db.tfl {
		phs := db.tfu[name]
		phs.Hashes = hs.Export()
		db.tfu[name] = phs
	}
	db.ml.RUnlock()
}

func (db *database) generateThreatsForLookups(last, next, freshUntil time.Time) {
	tfl := make(threatsForLookup)
	for name, phs := range db.tfu {
		var hs hashSet
		hs.Import(phs.Hashes)
		tfl[name] = hs
		phs.Hashes = nil
		db.tfu[name] = phs
	}

	db.ml.Lock()
	wasBad := db.err != nil
	db.tfl, db.last = tfl, last
	db.next, db.freshUntil = next, freshUntil
	db.lastUpdateError = ""
	db.ml.Unlock()
	if wasBad {
		db.clearError()
		db.log.Printf("database is now healthy")
	}
}

func saveDatabase(path string, db databaseFormat) (err error) {
	file, err := os.Create(path)
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
	return gob.NewEncoder(gz).Encode(db)
}

func loadDatabase(path string) (db databaseFormat, err error) {
	file, err := os.Open(path)
	if err != nil {
		return db, err
	}
	defer func() {
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return db, err
	}
	defer func() {
		if zerr := gz.Close(); err == nil {
			err = zerr
		}
	}()

	if err = gob.NewDecoder(gz).Decode(&db); err != nil {
		return db, err
	}
	for _, dv := range db.Table {
		if !bytes.Equal(dv.SHA256, dv.Hashes.SHA256()) {
			return db, errors.New("safebrowsing: threat list SHA256 mismatch")
		}
	}
	return db, nil
}

func (tfu threatsForUpdate) update(resp *hashListsResponse) error {
	for _, hl := range resp.HashLists {
		phs := tfu[hl.Name]
		if !hl.PartialUpdate {
			phs.Hashes = nil
			phs.SHA256 = nil
		} else if _, ok := tfu[hl.Name]; !ok {
			return errors.New("safebrowsing: partial update received for non-existent key")
		}

		phs.Hashes.Sort()
		if hl.CompressedRemovals != nil {
			idxs, err := decodeRice32(hl.CompressedRemovals)
			if err != nil {
				return err
			}
			for _, i := range idxs {
				if i >= uint32(len(phs.Hashes)) {
					return errors.New("safebrowsing: invalid removal index")
				}
				phs.Hashes[i] = ""
			}
			compactHashes := phs.Hashes[:0]
			for _, h := range phs.Hashes {
				if h != "" {
					compactHashes = append(compactHashes, h)
				}
			}
			phs.Hashes = compactHashes
		}

		if hl.AdditionsFourBytes != nil {
			hashes, err := decodeRice32Hashes(hl.AdditionsFourBytes)
			if err != nil {
				return err
			}
			phs.Hashes = append(phs.Hashes, hashes...)
		}

		phs.Hashes.Sort()
		if err := phs.Hashes.Validate(); err != nil {
			return err
		}
		if hl.SHA256Checksum != "" {
			checksum, err := base64.StdEncoding.DecodeString(hl.SHA256Checksum)
			if err != nil {
				return err
			}
			phs.SHA256 = checksum
		}
		if len(phs.SHA256) > 0 && !bytes.Equal(phs.SHA256, phs.Hashes.SHA256()) {
			return errors.New("safebrowsing: threat list SHA256 mismatch")
		}
		if hl.Version != "" {
			version, err := base64.StdEncoding.DecodeString(hl.Version)
			if err != nil {
				return err
			}
			phs.Version = version
		}
		tfu[hl.Name] = phs
	}
	return nil
}
