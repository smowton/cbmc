/*******************************************************************\

Module: JAVA Bytecode Language Conversion

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef CPROVER_JAVA_BYTECODE_CONVERT_H
#define CPROVER_JAVA_BYTECODE_CONVERT_H

#include <util/symbol_table.h>
#include <util/message.h>

#include "java_bytecode_parse_tree.h"

typedef std::map<irep_idt, std::pair<const symbolt*, const java_bytecode_parse_treet::methodt*> >
  lazy_methodst;

bool java_bytecode_convert_class(
  const java_bytecode_parse_treet &parse_tree,
  const bool &disable_runtime_checks,
  symbol_tablet &symbol_table,
  message_handlert &message_handler,
  int max_array_length,
  lazy_methodst&);

#endif

