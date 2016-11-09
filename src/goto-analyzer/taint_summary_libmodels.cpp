/*******************************************************************\

Module: taint_summary_libmodels

Author: Marek Trtik

Date: November 2016

This module provides loading and applying models of library functions
of analysed program to the process of taint analysis.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_summary_libmodels.h>
#include <util/file_util.h>
#include <util/msgstream.h>
#include <util/json.h>
#include <fstream>
#include <cassert>


taint_summary_libmodelst&  taint_summary_libmodelst::instance()
{
  static taint_summary_libmodelst tslm;
  return tslm;
}


void  taint_summary_libmodelst::clear()
{
}


std::string  taint_summary_libmodelst::load(
    std::string const&  libmodels_json_file_pathname
    )
{
  if (!fileutl_file_exists(libmodels_json_file_pathname))
    return msgstream() << "File '" << libmodels_json_file_pathname
                       << "' does not exist.";
  if (fileutl_is_directory(libmodels_json_file_pathname))
    return msgstream() << "File '" << libmodels_json_file_pathname
                       << "' is actually a directory.";



  return ""; // No error.
}


bool  taint_summary_libmodelst::has_model_of_function(
    irep_idt const  fn_name
    ) const
{
  // TODO!
  return false;
}


taint_summary_ptrt  taint_summary_libmodelst::get_model_of_function(
    irep_idt const  fn_name
    ) const
{
  // TODO!
  assert(false);
}
/*
std::string const  fname = as_string(fn_name);
if (fname.find("java::sun.") == 0UL
|| fname.find("java::jdk.") == 0UL
|| fname.find("java::sun.") == 0UL
|| fname.find("java::java.") == 0UL
|| fname.find("java::javax.") == 0UL
)
{
msgout.progress()
  << "["
  << std::fixed << std::setprecision(1) << std::setw(5)
  << (inverted_topological_order.size() == 0UL ? 100.0 :
        100.0 * (double)(processed + skipped) /
                (double)inverted_topological_order.size())
  << "%] Skipping: "
  << fn_name
  << messaget::eom; std::cout.flush();
++skipped;
continue;
}
*/
