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

// Command sbserver is an application for serving URL lookups via a simple API.
//
// In order to abstract away the complexities of the Safe Browsing API v4, the
// sbserver application can be used to serve a subset of API v4 over HTTP.
// This subset is intentionally small so that it would be easy to implement by
// a client. It is intended for sbserver to either be running locally on a
// client's machine or within the same local network. That way it can handle
// most local API calls before resorting to making an API call to the actual
// Safe Browsing API over the internet.
//
// Usage of sbserver looks something like this:
//	             _________________
//	            |                 |
//	            |  Safe Browsing  |
//	            |  API v4 servers |
//	            |_________________|
//	                     |
//	            ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
//	               The Internet
//	            ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
//	                     |
//	              _______V_______
//	             |               |
//	             |   SBServer    |
//	      +------|  Application  |------+
//	      |      |_______________|      |
//	      |              |              |
//	 _____V_____    _____V_____    _____V_____
//	|           |  |           |  |           |
//	|  Client1  |  |  Client2  |  |  Client3  |
//	|___________|  |___________|  |___________|
//
// In theory, each client could directly use the Go SafeBrowser implementation,
// but there are situations where that is not desirable. For example, the client
// may not be using the language Go, or there may be multiple clients in the
// same machine or local network that would like to share a local database
// and cache. The sbserver was designed to address these issues.
//
// The sbserver application is technically a proxy since it is itself actually
// an API v4 client. It connects the Safe Browsing API servers using an API key
// and maintains a local database and cache. However, it is also a server since
// it re-serves a subset of the API v4 endpoints. These endpoints are minimal
// in that they do not require each client to maintain state between calls.
//
// The assumption is that communication between SBServer and Client1, Client2,
// and Client3 is inexpensive, since they are within the same machine or same
// local network. Thus, the sbserver can efficiently satisfy some requests
// without talking to the global Safe Browsing servers since it has a
// potentially larger cache. Furthermore, it can multiplex multiple requests to
// the Safe Browsing servers on fewer TCP connections, reducing the cost for
// comparatively more expensive internet transfers.
//
// By default, the sbserver listens on localhost:8080 and serves the following
// API endpoints:
//	/v4/threatMatches:find
//	/v4/threatLists
//	/status
//
//
// Endpoint: /v4/threatMatches:find
//
// This is a lightweight implementation of the API v4 threatMatches endpoint.
// Essentially, it takes in a list of URLs, and returns a list of threat matches
// for those URLs. Unlike the Safe Browsing API, it does not require an API key.
//
// Example usage:
//	# Send request to server:
//	$ curl \
//	  -H "Content-Type: application/json" \
//	  -X POST -d '{
//	      "threatInfo": {
//	          "threatTypes":      ["UNWANTED_SOFTWARE", "MALWARE"],
//	          "platformTypes":    ["ANY_PLATFORM"],
//	          "threatEntryTypes": ["URL"],
//	          "threatEntries": [
//	              {"url": "google.com"},
//	              {"url": "bad1url.org"},
//	              {"url": "bad2url.org"}
//	          ]
//	      }
//	  }' \
//	  localhost:8080/v4/threatMatches:find
//
//	# Receive response from server:
//	{
//	    "matches": [{
//	        "threat":          {"url": "bad1url.org"},
//	        "platformType":    "ANY_PLATFORM",
//	        "threatType":      "UNWANTED_SOFTWARE",
//	        "threatEntryType": "URL"
//	    }, {
//	        "threat":          {"url": "bad2url.org"},
//	        "platformType":    "ANY_PLATFORM",
//	        "threatType":      "UNWANTED_SOFTWARE",
//	        "threatEntryType": "URL"
//	    }, {
//	        "threat":          {"url": "bad2url.org"},
//	        "platformType":    "ANY_PLATFORM",
//	        "threatType":      "MALWARE",
//	        "threatEntryType": "URL"
//	    }]
//	}
//
//
// Endpoint: /v4/threatLists
//
// The endpoint returns a list of the threat lists that the sbserver is
// currently subscribed to. The threats returned by the earlier threatMatches
// API call may only be one of these types.
//
// Example usage:
//	# Send request to server:
//	$ curl -X GET localhost:8080/v4/threatLists
//
//	# Receive response from server:
//	{
//	    "threatLists": [{
//	        "threatType":      "MALWARE"
//	        "platformType":    "ANY_PLATFORM",
//	        "threatEntryType": "URL",
//	    }, {
//	        "threatType":      "SOCIAL_ENGINEERING",
//	        "platformType":    "ANY_PLATFORM"
//	        "threatEntryType": "URL",
//	    }, {
//	        "threatType":      "UNWANTED_SOFTWARE"
//	        "platformType":    "ANY_PLATFORM",
//	        "threatEntryType": "URL",
//	    }]
//	}
//
//
// Endpoint: /status
//
// The status endpoint allows a client to obtain some statistical information
// regarding the health of sbserver. It can be used to determine how many
// requests were satisfied locally by sbserver alone and how many requests
// were forwarded to the Safe Browsing API servers.
//
// Example usage:
//	$ curl localhost:8080/status
//	{
//	    "Stats" : {
//	        "QueriesByDatabase" : 132,
//	        "QueriesByCache" : 31,
//	        "QueriesByAPI" : 6,
//	        "QueriesFail" : 0,
//	    },
//	    "Error" : ""
//	}
//
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/teamnsrg/safebrowsing"
	"time"
)

var (
	apiKeyFlag          = flag.String("apikey", "", "specify your Safe Browsing API key")
	srvAddrFlag         = flag.String("srvaddr", "localhost:8080", "TCP network address the HTTP server should use")
	proxyFlag           = flag.String("proxy", "", "proxy to use to connect to the HTTP server")
	databaseFlag        = flag.String("db", "safebrowsing.db", "path to the Safe Browsing database")
	databaseArchiveFlag = flag.String("dba", ".sb_archive", "path to the Safe Browsing database archive")
	clientFlag          = flag.String("client", "UniversityOfIllinoisSPRAIResearch", "client name")
	versionFlag         = flag.String("version", "1.0.0", "client version")
)

const usage = `sbserver: starts a Safe Browsing API proxy server.

In order to abstract away the complexities of the Safe Browsing API v4, the
sbserver application can be used to serve a subset of the v4 API.
This subset is intentionally small so that it would be easy to implement by
a client. It is intended for sbserver to either be running locally on a
client's machine or within the same local network so that it can handle most
local API calls before resorting to making an API call to the actual
Safe Browsing API over the internet.

Usage: %s -apikey=$APIKEY

`

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
		APIKey:             *apiKeyFlag,
		DBPath:             *databaseFlag,
		ProxyURL:           *proxyFlag,
		Logger:             os.Stderr,
		ID:                 *clientFlag,
		Version:            *versionFlag,
		DBArchive:          true,
		DBArchiveDirectory: *databaseArchiveFlag,
		UpdatePeriod:       5 * time.Minute,
	}
	sb, err := safebrowsing.NewSafeBrowser(conf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to initialize Safe Browsing client: ", err)
		os.Exit(1)
	}

	select {
	case <-sb.Done:
		fmt.Fprintln(os.Stdout, "Stopping downloader")
		return
	}

}
