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
  dont_remove_instanceof=0,
  remove_added_instanceof=1,
  also_remove_instanceof=3,
};
inline remove_exceptions_typest operator|(
  remove_exceptions_typest a, remove_exceptions_typest b)
{
  return static_cast<remove_exceptions_typest>(
    static_cast<int>(a) | static_cast<int>(b));
}
inline bool has_flag(
  remove_exceptions_typest value, remove_exceptions_typest flag)
{
  return (static_cast<int>(value) & static_cast<int>(flag)) != 0;
}

void remove_exceptions(
  symbol_tablet &symbol_table,
  goto_functionst &goto_functions,
  bool do_remove_instanceof);
void remove_exceptions(goto_modelt &goto_model, remove_exceptions_typest type);

#endif
