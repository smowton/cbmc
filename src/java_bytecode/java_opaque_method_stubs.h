
/*******************************************************************\

Module: Java opaque stub generation

Author: Chris Smowton, chris@smowton.net

\*******************************************************************/

#ifndef CPROVER_JAVA_OPAQUE_STUBS_H
#define CPROVER_JAVA_OPAQUE_STUBS_H

#include <util/symbol_table.h>

void java_generate_opaque_method_stubs(
  symbol_tablet &symbol_table,
  bool assume_non_null,
  int max_nondet_array_length,
  const source_locationt &loc);

#endif
