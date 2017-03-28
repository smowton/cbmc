#!/bin/bash

MYDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOTDIR=$MYDIR/..

INCLUDES_LIST=$ROOTDIR/.boost_includes.h
NEW_LIST=$INCLUDES_LIST.new

$MYDIR/find_boost_includes.sh $NEW_LIST

if [ ! -f $INCLUDES_LIST ] || ! diff -q $INCLUDES_LIST $NEW_LIST; then
  echo "Boost includes have changed"
  cp $NEW_LIST $INCLUDES_LIST
  exit 1
else
  exit 0
fi
