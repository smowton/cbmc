#!/bin/bash

MYDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SRCDIR=$MYDIR/../src

if [ $# -ne 1 ]; then
  echo "Usage: gather_boost_deps.sh boost_includes.h"
  exit 1
fi

find $SRCDIR -print0 | xargs -0 grep -I -d skip -h "#include" | grep boost | sort | uniq > $1
