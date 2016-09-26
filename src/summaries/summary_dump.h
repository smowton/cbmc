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

#ifndef CPROVER_SUMMARY_DUMP_H
#define CPROVER_SUMMARY_DUMP_H

#include <summaries/summary.h>
#include <goto-programs/goto_model.h>
#include <functional>
#include <string>
#include <iosfwd>

namespace sumfn {


/**
 *
 *
 *
 */
using  callback_dump_derived_summary_in_html =
    std::function<std::string(object_summary_t,
                              goto_modelt const&,
                              std::ostream&)>;



/**
 *
 *
 *
 */
std::string  dump_in_html(
    database_of_summaries_t const&  computed_summaries,
    callback_dump_derived_summary_in_html const&  summary_dump_callback,
    goto_modelt const&  program,
    std::string const&  dump_root_directory,
    std::ostream* const  log = nullptr
    );


/**
 *
 *
 *
 */
std::string  dump_in_html(
    object_summary_t const  summary,
    callback_dump_derived_summary_in_html const&  summary_dump_callback,
    goto_modelt const&  program,
    std::string const&  dump_root_directory
    );


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
void  dump_html_prefix(std::ostream&  ostr);


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
