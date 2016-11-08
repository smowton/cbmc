/*******************************************************************\

Module: Taint Analysis

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef CPROVER_TAINT_ANALYSIS_H
#define CPROVER_TAINT_ANALYSIS_H

#include <goto-analyzer/taint_trace_recogniser.h>
#include <util/message.h>
#include <util/namespace.h>
#include <goto-programs/goto_model.h>
#include <string>

bool taint_analysis(
  goto_modelt &,
  const std::string &taint_file_name,
  message_handlert &,
  bool show_full,
  const std::string &json_file_name,
  const std::string &summary_directory);

bool taint_analysis(
  goto_modelt &goto_model,
  message_handlert &message_handler,
  bool show_full,
  const std::string &json_file_name,
  const database_of_summaries_ptrt& summarydb);
  
std::string  taint_analysis_instrument_knowledge(
  goto_modelt&  model,
  std::string const&  taint_file_name,
  message_handlert&  logger,
  taint_sources_mapt&  taint_sources,
  taint_sinks_mapt&  taint_sinks,
  taint_specification_symbol_names_to_svalue_symbols_mapt&  taint_spec_names
  );


#endif
