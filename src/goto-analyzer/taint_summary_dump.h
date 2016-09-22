/////////////////////////////////////////////////////////////////////////////
//
// Module: taint_summary_dump
// Author: Marek Trtik
//
// It provides a dump of computed taint summary in HTML format.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef CPROVER_TAINT_SUMMARY_DUMP_H
#define CPROVER_TAINT_SUMMARY_DUMP_H

#include <goto-analyzer/taint_summary.h>
#include <summaries/summary_dump.h>

namespace sumfn { namespace taint {


/**
 *
 *
 *
 *
 */
std::string  dump_in_html(
    object_summary_t const  obj_summary,
    goto_modelt const&  program,
    std::ostream&  ostr
    );


}}

#endif
