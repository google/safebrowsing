#!/bin/bash
set -e

# This script builds the generated Go code for the static web files.
# The statik tool must be installed. The recommended version is:
#
#	github.com/rakyll/statik: 2940084503a48359b41de178874e862c5bc3efe8
for TOOL in statik; do
	command -v $TOOL >/dev/null 2>&1 || { echo "Could not locate $TOOL. Aborting." >&2; exit 1; }
done

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

statik -src public -dest .
