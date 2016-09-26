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
#include <iosfwd>

namespace sumfn { namespace taint {


/**
 *
 *
 *
 *
 */
void  dump_value_in_html(
    value_of_variable_t const&  value,
    std::ostream&  ostr
    );


/**
 *
 *
 *
 *
 */
void  dump_vars_to_values_in_html(
    map_from_vars_to_values_t const&  vars_to_values,
    std::ostream&  ostr
    );


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
