// Copyright 2017 DiffBlue Limited. All Rights Reserved.

/// \file
/// Function-level/module-level pass to remove java_new and replace with
/// malloc & zero-initialize

#include "remove_java_new.h"

#include <util/pointer_offset_size.h>
#include <linking/zero_initializer.h>

#include "class_identifier.h"

static bool remove_java_new(
  goto_programt &goto_program,
  const namespacet &ns,
  message_handlert &message_handler)
{
  messaget msg(message_handler);

  bool changed=false;
  for(goto_programt::targett target=goto_program.instructions.begin();
    target!=goto_program.instructions.end();
    ++target)
  {
    codet &code=target->code;
    const irep_idt &statement=code.get_statement();
    if(statement!=ID_assign)
      continue;
    code_assignt &assign=to_code_assign(code);
    if(assign.rhs().id()!=ID_side_effect)
      continue;
    side_effect_exprt &rhs=to_side_effect_expr(assign.rhs());
    if(rhs.get_statement()!=ID_java_new)
      continue;
    INVARIANT(rhs.operands().empty(), "java_new does not have operands");
    INVARIANT(rhs.type().id()==ID_pointer, "java_new returns pointer");

    const exprt &lhs=assign.lhs();
    INVARIANT(!lhs.is_nil(), "remove_java_new without lhs is yet to be implemented");

    typet object_type=rhs.type().subtype();

    // build size expression
    exprt object_size=size_of_expr(object_type, ns);
    INVARIANT(object_size.is_not_nil(), "remove_java_new got nil object_size");

    changed=true;

    // We produce a malloc side-effect
    side_effect_exprt malloc_expr(ID_malloc);
    malloc_expr.copy_to_operands(object_size);
    malloc_expr.type()=rhs.type();
    rhs=std::move(malloc_expr);

    // zero-initialize the object
    dereference_exprt deref(lhs, object_type);
    source_locationt location=rhs.source_location();
    exprt zero_object=
      zero_initializer(object_type, location, ns, message_handler);
    set_class_identifier(
      to_struct_expr(zero_object), ns, to_symbol_type(object_type));
    goto_programt::targett zi_assign=goto_program.insert_after(target);
    zi_assign->make_assignment();
    zi_assign->code=code_assignt(deref, zero_object);
    zi_assign->source_location=location;
  }
  if(!changed)
    return false;
  goto_program.update();
  return true;
}

bool remove_java_new(
  goto_functionst::goto_functiont &goto_function,
  const namespacet &ns,
  message_handlert &message_handler)
{
  return remove_java_new(goto_function.body, ns, message_handler);
}

void remove_java_new(
  goto_functionst &goto_functions,
  const namespacet &ns,
  message_handlert &message_handler)
{
  for(auto &named_fn : goto_functions.function_map)
    remove_java_new(named_fn.second, ns, message_handler);
}

void remove_java_new(
  goto_modelt &goto_model,
  message_handlert &message_handler)
{
  remove_java_new(
    goto_model.goto_functions,
    namespacet(goto_model.symbol_table),
    message_handler);
}
