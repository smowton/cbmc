#############################################################################
#
# Module: functions_summaries
# Author: Marek Trtik
#
# @ Copyright Diffblue, Ltd.
#
#############################################################################

SRC = function_summary.cpp

INCLUDES= -I ..

include ../config.inc
include ../common

CLEANFILES = function_summaries$(LIBEXT)

all: function_summaries$(LIBEXT)

###############################################################################

function_summaries$(LIBEXT): $(OBJ) 
	$(LINKLIB)

