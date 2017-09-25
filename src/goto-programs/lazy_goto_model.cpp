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

void lazy_goto_modelt::load_all_functions()
{
  std::vector<irep_idt> fn_ids_to_convert;
  symbol_tablet::symbolst::size_type table_size;
  symbol_tablet::symbolst::size_type new_table_size=symbol_table.symbols.size();
  do
  {
    table_size=new_table_size;

    // Find symbols that correspond to functions
    fn_ids_to_convert.clear();
    for(const auto &named_symbol : symbol_table.symbols)
    {
      if(is_function_symbol(named_symbol.second))
        fn_ids_to_convert.push_back(named_symbol.first);
    }

    // Access all functions to convert them
    for(const irep_idt &symbol_name : fn_ids_to_convert)
      function_map.at(symbol_name);

    // Repeat while new symbols are being added in case any of those are
    // stubbed functions. Even stubs can create new stubs while being
    // converted if they are special stubs (e.g. string functions)
    new_table_size=symbol_table.symbols.size();
  } while(new_table_size!=table_size);

  goto_model.goto_functions.compute_location_numbers();
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
