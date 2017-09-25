// Copyright 2016-2017 DiffBlue Limited. All Rights Reserved.

/// \file
/// Model for lazy loading of functions

#include "lazy_goto_model.h"
#include <util/recording_symbol_table.h>


lazy_goto_modelt::lazy_goto_modelt(
    const post_process_functiont &post_process_function,
    const post_process_functionst &post_process_functions,
    message_handlert &message_handler)
  : symbol_table(goto_model.symbol_table),
    function_map(
      goto_model.goto_functions.function_map,
      language_files,
      goto_model.symbol_table,
      [this, post_process_function] (
        const irep_idt &function_name,
        goto_functionst::goto_functiont &function)
      { return post_process_function(function_name, function, symbol_table); },
      message_handler),
    post_process_functions(std::move(post_process_functions))
{
  language_files.set_message_handler(message_handler);
}

bool lazy_goto_modelt::freeze()
{
  messaget msg(language_files.get_message_handler());
  recording_symbol_tablet symbol_table=
    recording_symbol_tablet::wrap(this->symbol_table);
  if(language_files.final(symbol_table))
  {
    msg.error() << "FINAL STAGE CONVERSION ERROR" << messaget::eom;
    return false;
  }
  for(const irep_idt &updated_symbol_id : symbol_table.get_updated())
  {
    if(is_function_symbol(*symbol_table.lookup(updated_symbol_id)))
    {
      // Re-convert any that already exist
      function_map.unload(updated_symbol_id);
      function_map.at(updated_symbol_id);
    }
  }

  post_process_functions(goto_model);

  return true;
}
