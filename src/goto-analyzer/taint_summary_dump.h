/*******************************************************************\

Module: taint_summary_dump

Author: Marek Trtik

Date: September 2016

It provides a dump of computed taint summary in HTML format.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_SUMMARY_DUMP_H
#define CPROVER_TAINT_SUMMARY_DUMP_H

#include <goto-analyzer/taint_summary.h>
#include <summaries/summary_dump.h>
#include <goto-programs/goto_model.h>
#include <util/namespace.h>
#include <iosfwd>


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  taint_dump_lvalue_in_html(
    taint_lvaluet const&  lvalue,
    namespacet const&  ns,
    std::ostream&  ostr
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  taint_dump_svalue_in_html(
    taint_svaluet const&  svalue,
    std::ostream&  ostr
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  taint_dump_lvalues_to_svalues_in_html(
    taint_map_from_lvalues_to_svaluest const&  lvalues_to_svalues,
    namespacet const&  ns,
    std::ostream&  ostr
    );

void taint_dump_numbered_lvalues_to_svalues_as_html(
    taint_numbered_lvalue_svalue_mapt const&  lvalues_to_svalues,
    namespacet const&  ns,
    const object_numberingt&,
    std::ostream&  ostr
    );

void taint_dump_numbered_lvalues_to_svalues_changes_as_html(
    taint_numbered_lvalue_svalue_mapt const&  lvalues_to_svalues,
    taint_numbered_lvalue_svalue_mapt const&  old_lvalues_to_svalues,    
    namespacet const&  ns,
    const object_numberingt&,
    std::ostream&  ostr
    );						    

/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
std::string  taint_dump_in_html(
    object_summaryt const  obj_summary,
    goto_modelt const&  program,
    std::ostream&  ostr
    );


#endif
