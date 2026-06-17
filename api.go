// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

package safebrowsing

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
)

const (
	batchGetPath              = "/v5/hashLists:batchGet"
	hashSearchPath            = "/v5/hashes:search"
	maxHashPrefixesPerRequest = 1000
)

// The api interface specifies wrappers around the Safe Browsing API v5.
type api interface {
	ListUpdate(ctx context.Context, names []string, versions map[string][]byte) (*hashListsResponse, error)
	HashLookup(ctx context.Context, prefixes []hashPrefix) (*hashSearchResponse, error)
}

type netAPI struct {
	client *http.Client
	url    *url.URL
	key    string
	ua     string
}

type hashListsResponse struct {
	HashLists []hashList `json:"hashLists"`
}

type hashList struct {
	Name                string       `json:"name"`
	Version             string       `json:"version"`
	PartialUpdate       bool         `json:"partialUpdate"`
	CompressedRemovals  *rice32      `json:"compressedRemovals"`
	MinimumWaitDuration string       `json:"minimumWaitDuration"`
	SHA256Checksum      string       `json:"sha256Checksum"`
	AdditionsFourBytes  *rice32      `json:"additionsFourBytes"`
	Metadata            hashMetadata `json:"metadata"`
}

type hashMetadata struct {
	ThreatTypes []ThreatType `json:"threatTypes"`
	HashLength  string       `json:"hashLength"`
}

type rice32 struct {
	FirstValue    uint32 `json:"firstValue"`
	RiceParameter int32  `json:"riceParameter"`
	EntriesCount  int32  `json:"entriesCount"`
	EncodedData   string `json:"encodedData"`
}

type hashSearchResponse struct {
	FullHashes    []fullHash `json:"fullHashes"`
	CacheDuration string     `json:"cacheDuration"`
}

type fullHash struct {
	FullHash        string           `json:"fullHash"`
	FullHashDetails []fullHashDetail `json:"fullHashDetails"`
}

type fullHashDetail struct {
	ThreatType ThreatType `json:"threatType"`
	Attributes []string   `json:"attributes"`
}

func newNetAPI(root string, key string, proxy string, userAgent string) (*netAPI, error) {
	if !strings.Contains(root, "://") {
		root = "https://" + root
	}
	u, err := url.Parse(root)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{}
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	}

	return &netAPI{url: u, client: httpClient, key: key, ua: userAgent}, nil
}

func (a *netAPI) getProto(ctx context.Context, requestPath string, query url.Values, out proto.Message) error {
	u := *a.url
	u.Path = requestPath
	q := u.Query()
	for k, vals := range query {
		for _, v := range vals {
			q.Add(k, v)
		}
	}
	q.Set("key", a.key)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if a.ua != "" {
		req.Header.Set("User-Agent", a.ua)
	}
	req.Header.Set("Accept", "application/x-protobuf")

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("safebrowsing: unexpected server response code: %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := proto.Unmarshal(body, out); err != nil {
		return fmt.Errorf("safebrowsing: decode %s response (%s): %w", requestPath, resp.Header.Get("Content-Type"), err)
	}
	return nil
}

func (a *netAPI) ListUpdate(ctx context.Context, names []string, versions map[string][]byte) (*hashListsResponse, error) {
	q := url.Values{}
	for _, name := range names {
		q.Add("names", name)
		if version := versions[name]; len(version) > 0 {
			q.Add("version", base64.StdEncoding.EncodeToString(version))
		}
	}

	var wireResp batchGetHashListsResponse
	if err := a.getProto(ctx, batchGetPath, q, &wireResp); err != nil {
		return nil, err
	}
	resp := &hashListsResponse{HashLists: make([]hashList, 0, len(wireResp.HashLists))}
	for _, wireList := range wireResp.HashLists {
		list := hashList{
			Name:           wireList.Name,
			Version:        base64.StdEncoding.EncodeToString(wireList.Version),
			PartialUpdate:  wireList.PartialUpdate,
			SHA256Checksum: base64.StdEncoding.EncodeToString(wireList.SHA256Checksum),
		}
		if wait := wireList.MinimumWaitDuration; wait != nil {
			list.MinimumWaitDuration = wait.Duration().String()
		}
		if removals := wireList.CompressedRemovals; removals != nil {
			list.CompressedRemovals = rice32FromProto(removals)
		}
		if additions := wireList.AdditionsFourBytes; additions != nil {
			list.AdditionsFourBytes = rice32FromProto(additions)
		}
		resp.HashLists = append(resp.HashLists, list)
	}
	return resp, nil
}

func (a *netAPI) HashLookup(ctx context.Context, prefixes []hashPrefix) (*hashSearchResponse, error) {
	if len(prefixes) > maxHashPrefixesPerRequest {
		return nil, fmt.Errorf("safebrowsing: too many hash prefixes: %d", len(prefixes))
	}
	q := url.Values{}
	for _, prefix := range prefixes {
		if len(prefix) != minHashPrefixLength {
			return nil, fmt.Errorf("safebrowsing: hash prefix must be exactly %d bytes", minHashPrefixLength)
		}
		q.Add("hashPrefixes", base64.StdEncoding.EncodeToString([]byte(prefix)))
	}

	var wireResp searchHashesResponse
	if err := a.getProto(ctx, hashSearchPath, q, &wireResp); err != nil {
		return nil, err
	}
	resp := &hashSearchResponse{FullHashes: make([]fullHash, 0, len(wireResp.FullHashes))}
	if duration := wireResp.CacheDuration; duration != nil {
		resp.CacheDuration = duration.Duration().String()
	}
	for _, wireHash := range wireResp.FullHashes {
		match := fullHash{
			FullHash:        base64.StdEncoding.EncodeToString(wireHash.FullHash),
			FullHashDetails: make([]fullHashDetail, 0, len(wireHash.FullHashDetails)),
		}
		for _, wireDetail := range wireHash.FullHashDetails {
			attributes := make([]string, 0, len(wireDetail.Attributes))
			for _, attribute := range wireDetail.Attributes {
				attributes = append(attributes, threatAttributeName(attribute))
			}
			match.FullHashDetails = append(match.FullHashDetails, fullHashDetail{
				ThreatType: ThreatType(threatTypeName(wireDetail.ThreatType)),
				Attributes: attributes,
			})
		}
		resp.FullHashes = append(resp.FullHashes, match)
	}
	return resp, nil
}

func rice32FromProto(value *riceDeltaEncoded32Bit) *rice32 {
	return &rice32{
		FirstValue:    value.FirstValue,
		RiceParameter: value.RiceParameter,
		EntriesCount:  value.EntriesCount,
		EncodedData:   base64.StdEncoding.EncodeToString(value.EncodedData),
	}
}

func parseDuration(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
