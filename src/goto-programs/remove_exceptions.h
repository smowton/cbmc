/*******************************************************************\

Module: Remove function exceptional returns

Author: Cristina David

Date:   December 2016

\*******************************************************************/

#ifndef CPROVER__TESTGEN_SRC_GOTO_PROGRAMS_REMOVE_EXCEPTIONS_H
#define CPROVER__TESTGEN_SRC_GOTO_PROGRAMS_REMOVE_EXCEPTIONS_H

#include <goto-programs/goto_model.h>

#define EXC_SUFFIX "#exception_value"

class exceptiont
{
public:
  typedef std::vector<std::pair<irep_idt,
    goto_programt::targett>> catch_handlerst;
  catch_handlerst catch_handlers;
};

typedef std::vector<exceptiont> stack_catcht;

// Removes 'throw x' and CATCH-PUSH/CATCH-POP
// and adds the required instrumentation (GOTOs and assignments)

void remove_exceptions(symbol_tablet &, goto_functionst &);


#endif
