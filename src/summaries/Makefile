#############################################################################
#
# Module: functions_summaries
# Author: Marek Trtik
#
# @ Copyright Diffblue, Ltd.
#
#############################################################################

SRC = summary.cpp

INCLUDES= -I ..

include ../config.inc
include ../common

CLEANFILES = summary$(LIBEXT)

all: summary$(LIBEXT)

###############################################################################

summary$(LIBEXT): $(OBJ) 
	$(LINKLIB)

