SRC = goto_analyzer_main.cpp goto_analyzer_parse_options.cpp \
      taint_parser.cpp taint_analysis.cpp static_analyzer.cpp \
      unreachable_instructions.cpp \
      taint_summary.cpp \
      taint_summary_dump.cpp taint_summary_json.cpp \
      pointsto_temp_analyser.cpp \
      pointsto_temp_summary_dump.cpp \
      taint_trace_recogniser.cpp \
      taint_trace_dump_html.cpp \
      taint_trace_dump_json.cpp \
      taint_statistics.cpp \
      taint_statistics_dump_html.cpp \
      taint_statistics_dump_json.cpp \
      taint_summary_libmodels.cpp \
      class_info.cpp

OBJ += ../ansi-c/ansi-c$(LIBEXT) \
      ../cpp/cpp$(LIBEXT) \
      ../linking/linking$(LIBEXT) \
      ../big-int/big-int$(LIBEXT) \
      ../goto-programs/goto-programs$(LIBEXT) \
      ../analyses/analyses$(LIBEXT) \
      ../pointer-analysis/pointer-analysis$(LIBEXT) \
      ../langapi/langapi$(LIBEXT) \
      ../json/json$(LIBEXT) \
      ../assembler/assembler$(LIBEXT) \
      ../util/util$(LIBEXT) \
      ../summaries/summary$(LIBEXT)

INCLUDES= -I ..

LIBS =

include ../config.inc
include ../common

CLEANFILES = goto-analyzer$(EXEEXT)

all: goto-analyzer$(EXEEXT)

ifneq ($(wildcard ../java_bytecode/Makefile),)
  OBJ += ../java_bytecode/java_bytecode$(LIBEXT)
  CP_CXXFLAGS += -DHAVE_JAVA_BYTECODE
  ifneq ($(wildcard $(LIBZIPINC)),)
    LIBS += $(LIBZIPLIB)
  endif
endif

ifneq ($(wildcard ../jsil/Makefile),)
  OBJ += ../jsil/jsil$(LIBEXT)
  CP_CXXFLAGS += -DHAVE_JSIL
endif

ifneq ($(wildcard ../specc/Makefile),)
  OBJ += ../specc/specc$(LIBEXT)
  CP_CXXFLAGS += -DHAVE_SPECC
endif

ifneq ($(wildcard ../php/Makefile),)
  OBJ += ../php/php$(LIBEXT)
  CP_CXXFLAGS += -DHAVE_PHP
endif

###############################################################################

goto-analyzer$(EXEEXT): $(OBJ)
	$(LINKBIN)

.PHONY: goto-analyzer-mac-signed

goto-analyzer-mac-signed: goto-analyzer$(EXEEXT)
	strip goto-analyzer$(EXEEXT) ; codesign -v -s $(OSX_IDENTITY) goto-analyzer$(EXEEXT)

