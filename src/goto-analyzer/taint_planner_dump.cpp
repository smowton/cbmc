/*******************************************************************\

Module: taint_plannert

Author: Marek Trtik

Date: Octomber 2016

This module defines an analysis which is responsible to plan work of
analyses taint_analysis and taint_summary. Namely, it specifies what
functions will be processed by what analysis, what functions have
a-priori know summaries (like sources of tainted data), and what variables
are important for analyses (i.e. defining a precision level for
the underlying analyses).

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_planner_dump.h>
#include <cassert>
#include <iostream>


void  taint_dump_taint_planner_in_html(
    const taint_plannert&  planner,
    goto_modelt const&  program,
    namespacet const&  ns,
    std::string const&  dump_root_directory
    )
{
}
