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
    std::function<std::string(object_summary_t,std::ostream&)>;



/**
 *
 *
 *
 */
std::string  dump_in_html(
    database_of_summaries_t const&  summaries_to_compute,
    callback_dump_derived_summary_in_html const&  summary_dump_callback,
    std::string const&  dump_root_directory
    );


/**
 *
 *
 *
 */
std::string  dump_in_html(
    object_summary_t const  summary,
    callback_dump_derived_summary_in_html const&  summary_dump_callback,
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


}

#endif
