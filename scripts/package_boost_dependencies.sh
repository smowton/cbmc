#!/bin/bash

MYDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PACKAGED_BOOST_DIR=$MYDIR/../boost
INCLUDES_LIST=$MYDIR/../.boost_includes.h
DEPS_LIST=$MYDIR/../.boost_deps.list

g++ -E $INCLUDES_LIST -o $INCLUDES_LIST.full
# Assumption:
grep "^#" $INCLUDES_LIST.full | grep boost | awk ' { gsub(/"/, "", $3); print $3 } ' | sort | uniq | grep -v 'cpp$' > $DEPS_LIST
