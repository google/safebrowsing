#!/bin/bash -v
set -e

export GOPATH="/home/zzma/src/golang"

DATE=`date +%Y-%m-%d`
EXEC_PATH="$GOPATH/src/github.com/teamnsrg/safebrowsing/cmd/sbdownload"
API_KEY_FILE="$GOPATH/src/github.com/teamnsrg/safebrowsing/.api/sb-api.key"
ARCHIVE_DIR_PATH="/data1/nsrg/safebrowsing/archive/"
LOG_PATH="/data1/nsrg/safebrowsing/logs/"

cd $EXEC_PATH
go build 
$EXEC_PATH/sbdownload -apikey $(cat $API_KEY_FILE) -dba $ARCHIVE_DIR_PATH >> $LOG_PATH/$DATE.log 2>> $LOG_PATH/$DATE.err

if [ "$1" != 0 ]; then
    cat $LOG_PATH/$DATE.err | mail -s "Safebrowsing Script Failed" zanema2@illinois.edu
fi