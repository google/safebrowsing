#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

$DIR/cmd/sbserver/generate.sh
$DIR/internal/safebrowsing_proto/generate.sh
