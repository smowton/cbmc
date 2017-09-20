// Copyright 2016-2017 DiffBlue Limited. All Rights Reserved.

/// \file
/// Model for lazy loading of functions

#ifndef CPROVER_GOTO_PROGRAMS_LAZY_GOTO_MODEL_H
#define CPROVER_GOTO_PROGRAMS_LAZY_GOTO_MODEL_H

#include <util/language_file.h>

#include "goto_model.h"
#include "goto_convert_functions.h"


/// Model that holds partially loaded map of functions
class lazy_goto_modelt
{
private:
  goto_modelt goto_model;

public:
  language_filest language_files;
  concrete_symbol_tablet &symbol_table;
  goto_functionst &function_map;

public:
  explicit lazy_goto_modelt(message_handlert &message_handler)
    : symbol_table(goto_model.symbol_table),
      function_map(goto_model.goto_functions)
  {
    language_files.set_message_handler(message_handler);
  }

public:
  /// Eagerly loads all functions from the symbol table.
  void load_all_functions()
  {
    goto_convert(
      symbol_table, function_map, language_files.get_message_handler());
    // As lazy goto functions are not required, language files is done with
    language_files.clear();
  }

  goto_modelt &freeze()
  {
    // The object returned here has access to the functions we've already
    // loaded but is frozen in the sense that, with regard to the facility to
    // load new functions, it has let it go.
    return goto_model;
  }
};

#endif // CPROVER_GOTO_PROGRAMS_LAZY_GOTO_MODEL_H
