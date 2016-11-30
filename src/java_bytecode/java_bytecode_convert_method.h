/*******************************************************************\

Module: JAVA Bytecode Language Conversion

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef CPROVER_JAVA_BYTECODE_CONVERT_METHOD_H
#define CPROVER_JAVA_BYTECODE_CONVERT_METHOD_H

#include <util/symbol_table.h>
#include <util/message.h>

#include "java_bytecode_parse_tree.h"

class class_hierarchyt;

void java_bytecode_convert_method(
  const symbolt &class_symbol,
  const java_bytecode_parse_treet::methodt &,
  symbol_tablet &symbol_table,
  message_handlert &message_handler,
  const bool &enable_runtime_checks,
  int max_array_length,
  std::vector<irep_idt>& needed_methods,
  std::set<irep_idt>& needed_classes,  
  const class_hierarchyt&);

void java_bytecode_convert_method_lazy(
  const symbolt &class_symbol,
  const irep_idt method_identifier,
  const java_bytecode_parse_treet::methodt &,
  symbol_tablet &symbol_table);

symbol_exprt check_stub_function(
  symbol_tablet&,
  const irep_idt& symname,
  const irep_idt& basename,
  const irep_idt& prettyname,
  const typet& fntype);

#endif

