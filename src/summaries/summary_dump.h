/////////////////////////////////////////////////////////////////////////////
//
// Module: summary_dump
// Author: Marek Trtik
//
// It provides dump of computed summaries in human readable form.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef CPROVER_SUMMARIES_SUMMARY_DUMP_H
#define CPROVER_SUMMARIES_SUMMARY_DUMP_H

#include <summaries/summary.h>
#include <goto-programs/goto_model.h>
#include <analyses/call_graph.h>
#include <util/json.h>
#include <functional>
#include <string>
#include <iosfwd>

namespace sumfn { namespace detail {


/**
 *
 *
 */
void  dump_irept(
    irept const&  irep,
    std::ostream&  ostr,
    std::string const&  shift = ""
    );


}}

namespace sumfn {


/**
 *
 *
 *
 */
typedef std::function<std::string(object_summaryt,
                                  goto_modelt const&,
                                  std::ostream&)>
        callback_dump_derived_summary_in_htmlt;


/**
 *
 *
 *
 */
std::string  dump_in_html(
    database_of_summariest const&  computed_summaries,
    callback_dump_derived_summary_in_htmlt const&  summary_dump_callback,
    goto_modelt const&  program,
    call_grapht const&  call_graph,
    std::string const&  dump_root_directory,
    std::ostream* const  log = nullptr
    );


/**
 *
 *
 *
 */
std::string  dump_in_html(
    object_summaryt const  summary,
    callback_dump_derived_summary_in_htmlt const&  summary_dump_callback,
    goto_modelt const&  program,
    std::string const&  dump_root_directory
    );

typedef std::function<json_objectt(const object_summaryt&)> callback_summary_to_jsont;

void write_database_as_json(
  database_of_summariest const&,
  callback_summary_to_jsont,
  std::string const& outdir);
  
 
/**
 *
 *
 */
std::string  to_file_name(std::string  result);


/**
 *
 *
 */
std::string  to_html_text(std::string  result);


/**
 *
 *
 */
void  dump_html_prefix(
    std::ostream&  ostr,
    std::string const&  page_name = ""
    );


/**
 *
 *
 */
void  dump_html_suffix(std::ostream&  ostr);


/**
 *
 *
 */
void  dump_instruction_code_in_html(
    goto_programt::instructiont const&  I,
    goto_modelt const&  program,
    std::ostream&  ostr
    );


}

#endif
