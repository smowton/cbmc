/*******************************************************************\

Module: Remove function exceptional returns

Author: Cristina David

Date:   December 2016

\*******************************************************************/

/// \file
/// Remove function exceptional returns

#ifndef CPROVER_GOTO_PROGRAMS_REMOVE_EXCEPTIONS_H
#define CPROVER_GOTO_PROGRAMS_REMOVE_EXCEPTIONS_H

#include <goto-programs/goto_model.h>

#define EXC_SUFFIX "#exception_value"

// Removes 'throw x' and CATCH-PUSH/CATCH-POP
// and adds the required instrumentation (GOTOs and assignments)

enum class remove_exceptions_typest
{
  dont_remove_instanceof,
  remove_added_instanceof,
  also_remove_instanceof,
};

void remove_exceptions(
  symbol_tablet &symbol_table,
  goto_functionst &goto_functions,
  bool do_remove_instanceof);
void remove_exceptions(goto_modelt &goto_model, remove_exceptions_typest type);

#endif
