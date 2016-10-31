/*******************************************************************\

Module: taint_statistics_dump

Author: Marek Trtik

Date: November 2016

This module defines interfaces and functionality for dumping statistical
information stored in the 'taint_statistics' instance. There is currently
provided a dump in HTML and JSON formats.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_STATISTICS_DUMP_H
#define CPROVER_TAINT_STATISTICS_DUMP_H

#include <string>
#include <iosfwd>


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  taint_dump_statistics_in_HTML(std::string const&  dump_root_directory);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  taint_dump_statistics_in_JSON(std::ostream const&  ostr);


#endif
