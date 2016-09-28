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
#include <goto-programs/goto_model.h>
#include <util/namespace.h>
#include <iosfwd>

namespace sumfn { namespace taint {


/**
 *
 *
 *
 *
 */
void  dump_lvalue_in_html(
    lvaluet const&  lvalue,
    namespacet const&  ns,
    std::ostream&  ostr
    );



/**
 *
 *
 *
 *
 */
void  dump_svalue_in_html(
    svaluet const&  value,
    std::ostream&  ostr
    );


/**
 *
 *
 *
 *
 */
void  dump_lvalues_to_svalues_in_html(
    map_from_lvalues_to_svaluest const&  vars_to_values,
    namespacet const&  ns,
    std::ostream&  ostr
    );


/**
 *
 *
 *
 *
 */
std::string  dump_in_html(
    object_summaryt const  obj_summary,
    goto_modelt const&  program,
    std::ostream&  ostr
    );


}}

#endif
