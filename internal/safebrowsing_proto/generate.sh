#!/bin/bash
set -e

# This script builds the generated Go code for the protocol buffers.
# The protoc and protoc-gen-go tools must be installed. The recommended versions are:
#
#	github.com/google/protobuf: v3.0.0-beta-3
#	github.com/golang/protobuf: 7cc19b78d562895b13596ddce7aafb59dd789318
for TOOL in protoc protoc-gen-go; do
	command -v $TOOL >/dev/null 2>&1 || { echo "Could not locate $TOOL. Aborting." >&2; exit 1; }
done

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

protoc --go_out=. *.proto
