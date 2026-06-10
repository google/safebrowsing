// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

package safebrowsing

import (
	"sync"
	"time"
)

type cacheResult int

const (
	positiveCacheHit cacheResult = iota
	negativeCacheHit
	cacheMiss
)

type cache struct {
	sync.RWMutex
	pttls map[hashPrefix]map[ThreatType]time.Time
	nttls map[hashPrefix]time.Time
	now   func() time.Time
}

func (c *cache) Update(prefixes []hashPrefix, resp *hashSearchResponse) {
	c.Lock()
	defer c.Unlock()

	if c.pttls == nil {
		c.pttls = make(map[hashPrefix]map[ThreatType]time.Time)
		c.nttls = make(map[hashPrefix]time.Time)
	}

	expiration := c.now().Add(parseDuration(resp.CacheDuration))
	for _, prefix := range prefixes {
		c.nttls[prefix] = expiration
	}

	for _, match := range resp.FullHashes {
		fullHashBytes, err := decodeBase64(match.FullHash)
		if err != nil {
			continue
		}
		fullHash := hashPrefix(fullHashBytes)
		if !fullHash.IsFull() {
			continue
		}
		if c.pttls[fullHash] == nil {
			c.pttls[fullHash] = make(map[ThreatType]time.Time)
		}
		for _, detail := range match.FullHashDetails {
			if validThreatType(detail.ThreatType) {
				c.pttls[fullHash][detail.ThreatType] = expiration
			}
		}
	}
}

func (c *cache) Lookup(hash hashPrefix) (map[ThreatType]bool, cacheResult) {
	if !hash.IsFull() {
		panic("hash is not full")
	}

	c.Lock()
	defer c.Unlock()
	now := c.now()

	threats := make(map[ThreatType]bool)
	for threatType, pttl := range c.pttls[hash] {
		if pttl.After(now) {
			threats[threatType] = true
		} else {
			return nil, cacheMiss
		}
	}
	if len(threats) > 0 {
		return threats, positiveCacheHit
	}

	prefix := hash[:minHashPrefixLength]
	if nttl, ok := c.nttls[prefix]; ok && nttl.After(now) {
		return nil, negativeCacheHit
	}
	return nil, cacheMiss
}

func (c *cache) Purge() {
	c.Lock()
	defer c.Unlock()
	now := c.now()

	for fullHash, threatTTLs := range c.pttls {
		for threatType, pttl := range threatTTLs {
			if now.After(pttl) {
				delete(threatTTLs, threatType)
			}
		}
		if len(threatTTLs) == 0 {
			delete(c.pttls, fullHash)
		}
	}
	for partialHash, nttl := range c.nttls {
		if now.After(nttl) {
			delete(c.nttls, partialHash)
		}
	}
}
