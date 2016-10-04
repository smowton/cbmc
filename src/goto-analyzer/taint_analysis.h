/*******************************************************************\

Module: Taint Analysis

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef CPROVER_TAINT_ANALYSIS_H
#define CPROVER_TAINT_ANALYSIS_H

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


std::string  taint_analysis_instrument_knowledge(
  goto_modelt&  model,
  std::string const&  taint_file_name,
  message_handlert&  logger
  );


#endif
