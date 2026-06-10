// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/safebrowsing"
	_ "github.com/google/safebrowsing/cmd/sbserver/statik"
	"github.com/rakyll/statik/fs"
)

const (
	healthPath       = "/health"
	statusPath       = "/status"
	searchURLsPath   = "/v5/urls:search"
	getHashListsPath = "/v5/hashLists"
	redirectPath     = "/r"
	mimeJSON         = "application/json"
)

var (
	apiKeyFlag   = flag.String("apikey", "", "specify your Safe Browsing API key")
	srvAddrFlag  = flag.String("srvaddr", "localhost:8080", "TCP network address the HTTP server should use")
	proxyFlag    = flag.String("proxy", "", "proxy to use to connect to the HTTP server")
	databaseFlag = flag.String("db", "/var/lib/safebrowsing/safebrowsing.gob", "path to the Safe Browsing database")
)

var threatTemplate = map[safebrowsing.ThreatType]string{
	safebrowsing.ThreatTypeMalware:                       "/malware.tmpl",
	safebrowsing.ThreatTypePotentiallyHarmfulApplication: "/malware.tmpl",
	safebrowsing.ThreatTypeUnwantedSoftware:              "/unwanted.tmpl",
	safebrowsing.ThreatTypeSocialEngineering:             "/social_engineering.tmpl",
}

type urlSearchRequest struct {
	URL  string   `json:"url"`
	URLs []string `json:"urls"`
}

type urlSearchResponse struct {
	Matches []urlMatch `json:"matches,omitempty"`
}

type urlMatch struct {
	URL        string `json:"url"`
	ThreatType string `json:"threatType"`
	HashList   string `json:"hashList"`
	Pattern    string `json:"pattern,omitempty"`
}

type healthResponse struct {
	Healthy         bool   `json:"healthy"`
	LastUpdate      string `json:"lastUpdate,omitempty"`
	DatabaseAge     string `json:"databaseAge,omitempty"`
	NextUpdate      string `json:"nextUpdate,omitempty"`
	FreshUntil      string `json:"freshUntil,omitempty"`
	LastAttempt     string `json:"lastAttempt,omitempty"`
	UpdatePeriod    string `json:"updatePeriod"`
	LastUpdateError string `json:"lastUpdateError,omitempty"`
	Error           string `json:"error,omitempty"`
}

const usage = `sbserver: starts a Safe Browsing API v5 local-list server.

Usage: %s -apikey=$APIKEY -srvaddr=0.0.0.0:80

`

func writeJSON(resp http.ResponseWriter, status int, value interface{}) {
	resp.Header().Set("Content-Type", mimeJSON)
	resp.WriteHeader(status)
	if err := json.NewEncoder(resp).Encode(value); err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
	}
}

func serveStatus(resp http.ResponseWriter, req *http.Request, sb *safebrowsing.SafeBrowser) {
	stats, sbErr := sb.Status()
	errStr := ""
	if sbErr != nil {
		errStr = sbErr.Error()
	}
	writeJSON(resp, http.StatusOK, struct {
		Stats safebrowsing.Stats `json:"stats"`
		Error string             `json:"error"`
	}{stats, errStr})
}

func serveHealth(resp http.ResponseWriter, req *http.Request, sb *safebrowsing.SafeBrowser) {
	if req.Method != http.MethodGet {
		http.Error(resp, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	health := sb.DatabaseHealth()
	body := healthResponse{
		Healthy:         health.Healthy,
		UpdatePeriod:    health.UpdatePeriod.String(),
		LastUpdateError: health.LastUpdateError,
		Error:           health.Error,
	}
	if !health.LastUpdate.IsZero() {
		body.LastUpdate = health.LastUpdate.UTC().Format(time.RFC3339)
		body.DatabaseAge = health.Age.Round(time.Second).String()
	}
	if !health.NextUpdate.IsZero() {
		body.NextUpdate = health.NextUpdate.UTC().Format(time.RFC3339)
	}
	if !health.FreshUntil.IsZero() {
		body.FreshUntil = health.FreshUntil.UTC().Format(time.RFC3339)
	}
	if !health.LastAttempt.IsZero() {
		body.LastAttempt = health.LastAttempt.UTC().Format(time.RFC3339)
	}

	status := http.StatusOK
	if !health.Healthy {
		status = http.StatusServiceUnavailable
	}
	resp.Header().Set("Cache-Control", "no-store")
	writeJSON(resp, status, body)
}

func serveLookups(resp http.ResponseWriter, req *http.Request, sb *safebrowsing.SafeBrowser) {
	if req.Method != http.MethodPost {
		http.Error(resp, "invalid method", http.StatusBadRequest)
		return
	}

	var searchReq urlSearchRequest
	if err := json.NewDecoder(req.Body).Decode(&searchReq); err != nil {
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	urls := append([]string(nil), searchReq.URLs...)
	if searchReq.URL != "" {
		urls = append(urls, searchReq.URL)
	}
	if len(urls) == 0 {
		http.Error(resp, "missing url or urls", http.StatusBadRequest)
		return
	}

	threats, err := sb.LookupURLsContext(req.Context(), urls)
	if err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}

	var searchResp urlSearchResponse
	for i, urlThreats := range threats {
		seen := make(map[string]bool)
		for _, threat := range urlThreats {
			key := urls[i] + "\x00" + threat.ThreatType.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			searchResp.Matches = append(searchResp.Matches, urlMatch{
				URL:        urls[i],
				ThreatType: threat.ThreatType.String(),
				HashList:   threat.Name,
				Pattern:    threat.Pattern,
			})
		}
	}
	writeJSON(resp, http.StatusOK, searchResp)
}

func serveLists(resp http.ResponseWriter, req *http.Request, conf *safebrowsing.Config) {
	if req.Method != http.MethodGet {
		http.Error(resp, "invalid method", http.StatusBadRequest)
		return
	}
	lists := safebrowsing.DefaultHashLists
	if len(conf.HashLists) != 0 {
		lists = conf.HashLists
	}
	writeJSON(resp, http.StatusOK, struct {
		HashLists []safebrowsing.HashList `json:"hashLists"`
	}{lists})
}

func parseTemplates(fs http.FileSystem, t *template.Template, paths ...string) (*template.Template, error) {
	for _, path := range paths {
		file, err := fs.Open(path)
		if err != nil {
			return nil, err
		}
		tmpl, err := ioutil.ReadAll(file)
		if err != nil {
			return nil, err
		}
		t, err = t.Parse(string(tmpl))
		if err != nil {
			return nil, err
		}
	}
	return t, nil
}

func serveRedirector(resp http.ResponseWriter, req *http.Request, sb *safebrowsing.SafeBrowser, fs http.FileSystem) {
	rawURL := req.URL.Query().Get("url")
	if rawURL == "" || req.URL.Path != redirectPath {
		http.NotFound(resp, req)
		return
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}
	threats, err := sb.LookupURLsContext(req.Context(), []string{rawURL})
	if err != nil {
		http.Error(resp, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(threats[0]) == 0 {
		http.Redirect(resp, req, rawURL, http.StatusFound)
		return
	}

	t := template.New("Safe Browsing Interstitial")
	for _, threat := range threats[0] {
		if tmpl, ok := threatTemplate[threat.ThreatType]; ok {
			t, err = parseTemplates(fs, t, tmpl, "/interstitial.html")
			if err != nil {
				http.Error(resp, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := t.Execute(resp, map[string]interface{}{"Threat": threat, "Url": parsedURL}); err != nil {
				http.Error(resp, err.Error(), http.StatusInternalServerError)
			}
			return
		}
	}
	http.Error(resp, "no template for threat", http.StatusInternalServerError)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *apiKeyFlag == "" {
		fmt.Fprintln(os.Stderr, "No -apikey specified")
		os.Exit(1)
	}

	conf := safebrowsing.Config{
		APIKey:   *apiKeyFlag,
		ProxyURL: *proxyFlag,
		DBPath:   *databaseFlag,
		Logger:   os.Stderr,
	}
	sb, err := safebrowsing.NewSafeBrowser(conf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to initialize Safe Browsing client:", err)
		os.Exit(1)
	}
	statikFS, err := fs.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to initialize static files:", err)
		os.Exit(1)
	}

	http.HandleFunc(statusPath, func(w http.ResponseWriter, r *http.Request) {
		serveStatus(w, r, sb)
	})
	http.HandleFunc(healthPath, func(w http.ResponseWriter, r *http.Request) {
		serveHealth(w, r, sb)
	})
	http.HandleFunc(searchURLsPath, func(w http.ResponseWriter, r *http.Request) {
		serveLookups(w, r, sb)
	})
	http.HandleFunc(getHashListsPath, func(w http.ResponseWriter, r *http.Request) {
		serveLists(w, r, &conf)
	})
	http.HandleFunc(redirectPath, func(w http.ResponseWriter, r *http.Request) {
		serveRedirector(w, r, sb, statikFS)
	})
	http.Handle("/public/", http.StripPrefix("/public/", http.FileServer(statikFS)))

	fmt.Fprintln(os.Stdout, "Starting server at", *srvAddrFlag)
	if err := http.ListenAndServe(*srvAddrFlag, nil); err != nil {
		fmt.Fprintln(os.Stderr, "Server error:", err)
	}
}
