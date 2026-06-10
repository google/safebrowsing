// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

// Package safebrowsing implements a client for the Safe Browsing API v5 Local
// List Mode. It maintains a local hash-prefix database and only calls Google
// for full hashes after a local prefix hit.
package safebrowsing

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"sync/atomic"
	"time"
)

const (
	DefaultServerURL     = "safebrowsing.googleapis.com"
	DefaultUpdatePeriod  = 30 * time.Minute
	DefaultID            = "GoSafeBrowser"
	DefaultVersion       = "2.0.0"
	DefaultRequestTimeout = time.Minute
)

var (
	errClosed = errors.New("safebrowsing: handler is closed")
	errStale  = errors.New("safebrowsing: threat list is stale")
)

type ThreatType string

const (
	ThreatTypeUnspecified                   ThreatType = "THREAT_TYPE_UNSPECIFIED"
	ThreatTypeMalware                       ThreatType = "MALWARE"
	ThreatTypeSocialEngineering             ThreatType = "SOCIAL_ENGINEERING"
	ThreatTypeUnwantedSoftware              ThreatType = "UNWANTED_SOFTWARE"
	ThreatTypePotentiallyHarmfulApplication ThreatType = "POTENTIALLY_HARMFUL_APPLICATION"
)

func (tt ThreatType) String() string {
	if tt == "" {
		return string(ThreatTypeUnspecified)
	}
	return string(tt)
}

type HashList struct {
	Name       string
	ThreatType ThreatType
}

type URLThreat struct {
	Pattern string
	HashList
}

var DefaultHashLists = []HashList{
	{Name: "mw-4b", ThreatType: ThreatTypeMalware},
	{Name: "se-4b", ThreatType: ThreatTypeSocialEngineering},
	{Name: "uws-4b", ThreatType: ThreatTypeUnwantedSoftware},
}

type Config struct {
	ServerURL      string
	ProxyURL       string
	APIKey         string
	ID             string
	Version        string
	DBPath         string
	UpdatePeriod   time.Duration
	HashLists      []HashList
	RequestTimeout time.Duration
	Logger         io.Writer

	api api
	now func() time.Time
}

func (c *Config) setDefaults() bool {
	if c.ServerURL == "" {
		c.ServerURL = DefaultServerURL
	}
	if len(c.HashLists) == 0 {
		c.HashLists = DefaultHashLists
	}
	if c.UpdatePeriod <= 0 {
		c.UpdatePeriod = DefaultUpdatePeriod
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}
	if c.ID == "" {
		c.ID = DefaultID
	}
	if c.Version == "" {
		c.Version = DefaultVersion
	}
	return true
}

func (c Config) copy() Config {
	c2 := c
	c2.HashLists = append([]HashList(nil), c.HashLists...)
	return c2
}

func (c Config) userAgent() string {
	return c.ID + "/" + c.Version
}

type SafeBrowser struct {
	stats  Stats
	config Config
	api    api
	db     database
	c      cache
	lists  map[string]HashList
	log    *log.Logger
	closed uint32
	done   chan bool
}

type Stats struct {
	QueriesByDatabase int64
	QueriesByCache    int64
	QueriesByAPI      int64
	QueriesFail       int64
	DatabaseUpdateLag time.Duration
}

func NewSafeBrowser(conf Config) (*SafeBrowser, error) {
	conf = conf.copy()
	if !conf.setDefaults() {
		return nil, errors.New("safebrowsing: invalid configuration")
	}
	if conf.api == nil {
		var err error
		conf.api, err = newNetAPI(conf.ServerURL, conf.APIKey, conf.ProxyURL, conf.userAgent())
		if err != nil {
			return nil, err
		}
	}
	if conf.now == nil {
		conf.now = time.Now
	}

	sb := &SafeBrowser{
		config: conf,
		api:    conf.api,
		c:      cache{now: conf.now},
		lists:  make(map[string]HashList),
	}
	for _, list := range conf.HashLists {
		sb.lists[list.Name] = list
	}

	w := conf.Logger
	if w == nil {
		w = ioutil.Discard
	}
	sb.log = log.New(w, "safebrowsing: ", log.Ldate|log.Ltime|log.Lshortfile)

	delay := time.Duration(0)
	if !sb.db.Init(&sb.config, sb.log) {
		ctx, cancel := context.WithTimeout(context.Background(), sb.config.RequestTimeout)
		delay, _ = sb.db.Update(ctx, sb.api)
		cancel()
	} else {
		delay = sb.db.UntilNextUpdate()
	}

	sb.done = make(chan bool)
	go sb.updater(delay)
	return sb, nil
}

func (sb *SafeBrowser) Status() (Stats, error) {
	stats := Stats{
		QueriesByDatabase: atomic.LoadInt64(&sb.stats.QueriesByDatabase),
		QueriesByCache:    atomic.LoadInt64(&sb.stats.QueriesByCache),
		QueriesByAPI:      atomic.LoadInt64(&sb.stats.QueriesByAPI),
		QueriesFail:       atomic.LoadInt64(&sb.stats.QueriesFail),
		DatabaseUpdateLag: sb.db.UpdateLag(),
	}
	return stats, sb.db.Status()
}

func (sb *SafeBrowser) DatabaseHealth() DatabaseHealth {
	return sb.db.Health()
}

func (sb *SafeBrowser) WaitUntilReady(ctx context.Context) error {
	if atomic.LoadUint32(&sb.closed) == 1 {
		return errClosed
	}
	select {
	case <-sb.db.Ready():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-sb.done:
		return errClosed
	}
}

func (sb *SafeBrowser) LookupURLs(urls []string) ([][]URLThreat, error) {
	return sb.LookupURLsContext(context.Background(), urls)
}

func (sb *SafeBrowser) LookupURLsContext(ctx context.Context, urls []string) (threats [][]URLThreat, err error) {
	ctx, cancel := context.WithTimeout(ctx, sb.config.RequestTimeout)
	defer cancel()

	threats = make([][]URLThreat, len(urls))
	if atomic.LoadUint32(&sb.closed) != 0 {
		return threats, errClosed
	}
	if err := sb.db.Status(); err != nil {
		sb.log.Printf("inconsistent database: %v", err)
		atomic.AddInt64(&sb.stats.QueriesFail, int64(len(urls)))
		return threats, err
	}

	hashes := make(map[hashPrefix]string)
	hash2idxs := make(map[hashPrefix][]int)
	prefixes := make(map[hashPrefix]struct{})
	hashListsByHash := make(map[hashPrefix][]HashList)

	for i, rawURL := range urls {
		urlHashes, err := generateHashes(rawURL)
		if err != nil {
			sb.log.Printf("error generating urlhashes: %v", err)
			atomic.AddInt64(&sb.stats.QueriesFail, int64(len(urls)-i))
			return threats, err
		}

		for fullHash, pattern := range urlHashes {
			hash2idxs[fullHash] = append(hash2idxs[fullHash], i)
			hashes[fullHash] = pattern

			partialHash, possibleLists := sb.db.Lookup(fullHash)
			if len(possibleLists) == 0 {
				atomic.AddInt64(&sb.stats.QueriesByDatabase, 1)
				continue
			}
			hashListsByHash[fullHash] = possibleLists

			cachedThreats, cr := sb.c.Lookup(fullHash)
			switch cr {
			case positiveCacheHit:
				for _, list := range possibleLists {
					if cachedThreats[list.ThreatType] {
						threats[i] = append(threats[i], URLThreat{Pattern: pattern, HashList: list})
					}
				}
				atomic.AddInt64(&sb.stats.QueriesByCache, 1)
			case negativeCacheHit:
				atomic.AddInt64(&sb.stats.QueriesByCache, 1)
			default:
				prefixes[partialHash] = struct{}{}
			}
		}
	}

	if len(prefixes) == 0 {
		return threats, nil
	}

	reqPrefixes := make([]hashPrefix, 0, len(prefixes))
	for prefix := range prefixes {
		reqPrefixes = append(reqPrefixes, prefix)
	}
	resp, err := sb.api.HashLookup(ctx, reqPrefixes)
	if err != nil {
		sb.log.Printf("HashLookup failure: %v", err)
		atomic.AddInt64(&sb.stats.QueriesFail, 1)
		return threats, err
	}
	sb.c.Update(reqPrefixes, resp)

	for _, match := range resp.FullHashes {
		fullHashBytes, err := decodeBase64(match.FullHash)
		if err != nil {
			continue
		}
		fullHash := hashPrefix(fullHashBytes)
		if !fullHash.IsFull() {
			continue
		}
		pattern, ok := hashes[fullHash]
		idxs, foundIdxs := hash2idxs[fullHash]
		if !ok || !foundIdxs {
			continue
		}
		possibleLists := hashListsByHash[fullHash]
		for _, detail := range match.FullHashDetails {
			if !validThreatType(detail.ThreatType) {
				continue
			}
			for _, list := range possibleLists {
				if list.ThreatType != detail.ThreatType {
					continue
				}
				for _, idx := range idxs {
					threats[idx] = append(threats[idx], URLThreat{Pattern: pattern, HashList: list})
				}
			}
		}
	}

	atomic.AddInt64(&sb.stats.QueriesByAPI, 1)
	return threats, nil
}

func validThreatType(tt ThreatType) bool {
	switch tt {
	case ThreatTypeMalware, ThreatTypeSocialEngineering, ThreatTypeUnwantedSoftware, ThreatTypePotentiallyHarmfulApplication:
		return true
	default:
		return false
	}
}

func (sb *SafeBrowser) updater(delay time.Duration) {
	for {
		sb.log.Printf("Next update in %v", delay)
		select {
		case <-time.After(delay):
			var ok bool
			ctx, cancel := context.WithTimeout(context.Background(), sb.config.RequestTimeout)
			if delay, ok = sb.db.Update(ctx, sb.api); ok {
				sb.log.Printf("background threat list updated")
				sb.c.Purge()
			}
			cancel()
		case <-sb.done:
			return
		}
	}
}

func (sb *SafeBrowser) Close() error {
	if atomic.LoadUint32(&sb.closed) == 0 {
		atomic.StoreUint32(&sb.closed, 1)
		close(sb.done)
	}
	return nil
}
