/*******************************************************************\

Module: summary_dump

Author: Marek Trtik

Date: September 2016

It provides dump of computed summaries in human readable form.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_SUMMARIES_SUMMARY_DUMP_H
#define CPROVER_SUMMARIES_SUMMARY_DUMP_H

#include <summaries/summary.h>
#include <summaries/utility.h>
#include <goto-programs/goto_model.h>
#include <analyses/call_graph.h>
#include <util/json.h>
#include <functional>
#include <string>
#include <iosfwd>

/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  dump_irept(
    irept const&  irep,
    std::ostream&  ostr,
    std::string const&  shift = ""
    );


/*******************************************************************\
\*******************************************************************/
typedef std::function<std::string(object_summaryt,
                                  goto_modelt const&,
                                  std::ostream&)>
        callback_dump_derived_summary_in_htmlt;


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
std::string  dump_in_html(
    database_of_summariest const&  computed_summaries,
    callback_dump_derived_summary_in_htmlt const&  summary_dump_callback,
    goto_modelt const&  program,
    call_grapht const&  call_graph,
    std::string const&  dump_root_directory,
    std::ostream* const  log = nullptr
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
std::string  dump_in_html(
    object_summaryt const  summary,
    callback_dump_derived_summary_in_htmlt const&  summary_dump_callback,
    goto_modelt const&  program,
    std::string const&  dump_root_directory
    );


typedef std::function<json_objectt(const object_summaryt&)>
        callback_summary_to_jsont;

/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
std::string  to_html_text(std::string  result);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  dump_access_path_in_html(
    access_path_to_memoryt const&  access_path,
    namespacet const&  ns,
    std::ostream&  ostr
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  dump_html_prefix(
    std::ostream&  ostr,
    std::string const&  page_name = ""
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  dump_html_suffix(std::ostream&  ostr);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  dump_instruction_code_in_html(
    goto_programt::instructiont const&  I,
    goto_modelt const&  program,
    std::ostream&  ostr
    );


#endif
