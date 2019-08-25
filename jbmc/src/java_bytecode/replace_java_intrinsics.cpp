/*******************************************************************\

Module: Replace Java intrinsics

Author: Diffblue Ltd.

\*******************************************************************/

/// \file
/// Replace Java intrinsics

#include "replace_java_intrinsics.h"

#include <goto-programs/class_identifier.h>
#include <goto-programs/goto_convert_functions.h>
#include <goto-programs/goto_model.h>
#include <java_bytecode/java_types.h>
#include <util/fresh_symbol.h>
#include <util/namespace.h>
#include <util/symbol_table_base.h>

/// Returns the symbol name for `org.cprover.CProver.createArrayWithType`
static irep_idt get_create_array_with_type_name()
{
  static irep_idt create_array_with_type_name =
    "java::org.cprover.CProver.createArrayWithType:"
    "(I[Ljava/lang/Object;)[Ljava/lang/Object;";
  return create_array_with_type_name;
}

/// Returns the internal implementation for
/// `org.cprover.CProver.createArrayWithType`. Our implementation copies the
/// internal type information maintained by jbmc that tracks the runtime type
/// of an array object rather than using reflection to achieve similar type
/// cloning.
/// \param symbol_table: global symbol table
/// \param message_handler: any GOTO program conversion errors are logged here
/// \return new GOTO program body for `org.cprover.CProver.createArrayWithType`.
static goto_programt create_array_with_type_program(
  symbol_table_baset &symbol_table,
  message_handlert &message_handler)
{
  // Replace CProver.createArrayWithType, which uses reflection to copy the
  // type but not the content of a given array, with a java_new_array statement
  // followed by overwriting its element type and dimension, similar to our
  // implementation (in java_bytecode_convert_class.cpp) of the
  // array[reference].clone() method.

  namespacet ns{symbol_table};

  symbolt &function_symbol =
    symbol_table.get_writeable_ref(get_create_array_with_type_name());
  const auto &function_type = to_code_type(function_symbol.type);
  const auto &length_argument = function_type.parameters().at(0);
  symbol_exprt length_argument_symbol_expr{length_argument.get_identifier(),
                                           length_argument.type()};
  const auto &existing_array_argument = function_type.parameters().at(1);
  symbol_exprt existing_array_argument_symbol_expr{
    existing_array_argument.get_identifier(), existing_array_argument.type()};

  symbolt &new_array_symbol = get_fresh_aux_symbol(
    function_type.parameters().at(1).type(),
    id2string(get_create_array_with_type_name()),
    "new_array",
    source_locationt(),
    ID_java,
    symbol_table);
  const auto new_array_symbol_expr = new_array_symbol.symbol_expr();

  code_blockt code_block;

  // Declare new_array temporary:
  code_block.add(code_declt(new_array_symbol_expr));

  // new_array = new Object[length];
  side_effect_exprt new_array_expr{
    ID_java_new_array, new_array_symbol.type, source_locationt{}};
  new_array_expr.copy_to_operands(length_argument_symbol_expr);
  code_block.add(code_assignt(new_array_symbol_expr, new_array_expr));

  dereference_exprt existing_array(existing_array_argument_symbol_expr);
  dereference_exprt new_array(new_array_symbol_expr);

  // new_array.@array_dimensions = existing_array.@array_dimensions
  // new_array.@element_class_identifier =
  //   existing_array.@element_class_identifier
  member_exprt old_array_dimension(
    existing_array, JAVA_ARRAY_DIMENSION_FIELD_NAME, java_int_type());
  member_exprt old_array_element_classid(
    existing_array, JAVA_ARRAY_ELEMENT_CLASSID_FIELD_NAME, string_typet());

  member_exprt new_array_dimension(
    new_array, JAVA_ARRAY_DIMENSION_FIELD_NAME, java_int_type());
  member_exprt new_array_element_classid(
    new_array, JAVA_ARRAY_ELEMENT_CLASSID_FIELD_NAME, string_typet());

  code_block.add(code_assignt(new_array_dimension, old_array_dimension));
  code_block.add(
    code_assignt(new_array_element_classid, old_array_element_classid));

  // return new_array
  code_block.add(code_returnt(new_array_symbol_expr));

  goto_functiont result;
  goto_convert_functionst convert(symbol_table, message_handler);
  function_symbol.value = code_block;
  convert.convert_function(function_symbol.name, result);
  return std::move(result.body);
}

/// Replace function \p name's body with our internal implementation, if
/// we have one.
/// \param name: name of the function to consider replacing
/// \param symbol_table: global symbol table
/// \param goto_program: existing program body, to be replaced or altered
/// \param message_handler: errors producing the new GOTO program are logged
///   here
static void replace_java_intrinsics(
  const irep_idt &name,
  symbol_table_baset &symbol_table,
  goto_programt &goto_program,
  message_handlert &message_handler)
{
  if(name == get_create_array_with_type_name())
  {
    goto_program =
      create_array_with_type_program(symbol_table, message_handler);
  }
}

/// Replaces Java intrinsic functions in \p goto_model_function with their
/// custom internal implementations, logging any errors to \p message_handler.
void replace_java_intrinsics(
  goto_model_functiont &goto_model_function,
  message_handlert &message_handler)
{
  replace_java_intrinsics(
    goto_model_function.get_function_id(),
    goto_model_function.get_symbol_table(),
    goto_model_function.get_goto_function().body,
    message_handler);
}

/// Replaces Java intrinsic functions in \p goto_model with their custom
/// internal implementations, logging any errors to \p message_handler.
void replace_java_intrinsics(
  goto_modelt &goto_model,
  message_handlert &message_handler)
{
  for(auto &name_and_function : goto_model.goto_functions.function_map)
  {
    replace_java_intrinsics(
      name_and_function.first,
      goto_model.symbol_table,
      name_and_function.second.body,
      message_handler);
  }
}
