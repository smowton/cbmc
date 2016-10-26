/*******************************************************************\

Module: taint_planner_dump

Author: Marek Trtik

Date: Octomber 2016

Functionality for dumping content of taint planner and also other analyses
of the whole taint analysis.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_PLANNER_DUMP_H
#define CPROVER_TAINT_PLANNER_DUMP_H

#include <goto-analyzer/taint_planner.h>
#include <goto-programs/goto_model.h>
#include <string>
#include <iosfwd>


/*******************************************************************\

Function: taint_dump_taint_planner_in_html

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  taint_dump_taint_planner_in_html(
    const taint_plannert&  planner,
    goto_modelt const&  program,
    namespacet const&  ns,
    std::string const&  dump_root_directory
    );



#endif
