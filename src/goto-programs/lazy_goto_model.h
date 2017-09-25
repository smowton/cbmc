// Copyright 2016-2017 DiffBlue Limited. All Rights Reserved.

/// \file
/// Model for lazy loading of functions

#ifndef CPROVER_GOTO_PROGRAMS_LAZY_GOTO_MODEL_H
#define CPROVER_GOTO_PROGRAMS_LAZY_GOTO_MODEL_H

#include <util/language_file.h>

#include "goto_model.h"
#include "lazy_goto_functions_map.h"
#include "goto_convert_functions.h"
#include "read_goto_binary.h"


/// Model that holds partially loaded map of functions
class lazy_goto_modelt
{
public:
  typedef std::function<void(
    const irep_idt &function_name,
    goto_functionst::goto_functiont &function,
    symbol_tablet &symbol_table)> post_process_functiont;
  typedef std::function<void(goto_modelt &goto_model)> post_process_functionst;

private:
  goto_modelt goto_model;

public:
  language_filest language_files;
  concrete_symbol_tablet &symbol_table;
  const lazy_goto_functions_mapt<goto_programt> function_map;

private:
  post_process_functionst post_process_functions;

public:
  lazy_goto_modelt(
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

public:
  /// Add functions from binary file to the symbol table and function map
  bool read_binary_object_and_link(const std::string &file)
  {
    return read_object_and_link(
      file,
      goto_model.symbol_table,
      goto_model.goto_functions,
      language_files.get_message_handler());
  }

  /// Eagerly loads all functions from the symbol table.
  void load_all_functions()
  {
    goto_convert(
      symbol_table,
      goto_model.goto_functions,
      language_files.get_message_handler());
    // As lazy goto functions are not required, language files is done with
    language_files.clear();
  }

  goto_modelt &freeze()
  {
    // The object returned here has access to the functions we've already
    // loaded but is frozen in the sense that, with regard to the facility to
    // load new functions, it has let it go.
    post_process_functions(goto_model);
    return goto_model;
  }
};

class optionst;

template<typename THandler>
lazy_goto_modelt create_lazy_model_from_handler_object(
  THandler &handler,
  const optionst &options,
  message_handlert &message_handler)
{
  messaget msg(message_handler);
  return lazy_goto_modelt(
    [&handler, &msg] (
      const irep_idt &function_name,
      goto_functionst::goto_functiont &function,
      symbol_tablet &symbol_table)
    {
      try
      {
        handler.process_goto_function(function_name, function, symbol_table);
      }
      catch(const char *e)
      {
        msg.error() << "process_goto_function: " << e << messaget::eom;
        throw;
      }
      catch(const std::string &e)
      {
        msg.error() << "process_goto_function: " << e << messaget::eom;
        throw;
      }
      catch(const std::bad_alloc &)
      {
        msg.error() << "Out of memory" << messaget::eom;
        throw;
      }
    },
    [&handler, &options, &msg] (goto_modelt &goto_model)
    {
      try
      {
        return handler.process_goto_functions(goto_model, options);
      }
      catch(const char *e)
      {
        msg.error() << "process_goto_functions: " << e << messaget::eom;
      }
      catch(const std::string &e)
      {
        msg.error() << "process_goto_functions: " << e << messaget::eom;
      }
      catch(int)
      {
      }
      catch(const std::bad_alloc &)
      {
        msg.error() << "process_goto_functions: Out of memory" << messaget::eom;
      }
      return true;
    },
    message_handler);
}

#endif // CPROVER_GOTO_PROGRAMS_LAZY_GOTO_MODEL_H
