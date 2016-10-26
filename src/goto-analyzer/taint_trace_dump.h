/*******************************************************************\

Module: taint_trace_dump

Author: Marek Trtik

Date: Octomber 2016



@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_TRACE_DUMP_H
#define CPROVER_TAINT_TRACE_DUMP_H

#include <goto-analyzer/taint_trace_recogniser.h>
#include <goto-programs/goto_model.h>
#include <vector>
#include <string>


void taint_dump_traces_in_html(
    std::vector<taint_tracet> const&  traces,
    goto_modelt const&  goto_model,
    std::string const&  dump_root_directory
    );

void taint_trace_dump_in_html(
    taint_tracet const&  trace,
    goto_modelt const&  goto_model,
    std::string const&  dump_root_directory
    );


#endif
