/*******************************************************************\

Module: taint_trace_recogniser

Author: Marek Trtik

Date: Octomber 2016



@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_TRACE_RECOGNISER_DUMP_H
#define CPROVER_TAINT_TRACE_RECOGNISER_DUMP_H

#include <goto-programs/goto_program.h>
#include <util/irep.h>
#include <unordered_map>
#include <vector>
#include <string>

typedef std::unordered_map<
          std::string,  // Name of the taint: 'taint_parse_treet::rulet::taint'
          std::unordered_map<
            std::string,  // Name of a function in a goto-program
            std::vector<goto_programt::targett>,
                          // A vector of istructions of taint sources
            dstring_hash
            > >
        taint_sources_mapt;

typedef taint_sources_mapt
        taint_sinks_mapt;




#endif
