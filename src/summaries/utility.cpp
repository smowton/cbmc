/*******************************************************************\

Module: utility

Author: Marek Trtik

Date: September 2016

This module defines utility functions which can be useful when implementing
summaries of any kinds.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <summaries/utility.h>
#include <util/std_expr.h>
#include <util/simplify_expr.h>
#include <util/symbol.h>
#include <util/msgstream.h>


#include <summaries/summary_dump.h>
#include <fstream>
#include <iostream>


static void  substitute_symbol(
    access_path_to_memoryt&  path,
    std::string const&  symbol_name,
    access_path_to_memoryt const&  replacement
    )
{
  if (is_identifier(path) && name_of_symbol_access_path(path) == symbol_name)
    path = replacement;
  else
    for (auto&  element : path.operands())
      substitute_symbol(element,symbol_name,replacement);
}


static access_path_to_memoryt  remove_cast_to_void_ptr_if_present(
        access_path_to_memoryt const&  access_path
        )
{
  if (access_path.id() == ID_typecast)
    return remove_cast_to_void_ptr_if_present(access_path.op0());
  return access_path;
}


access_path_to_memoryt const&  empty_access_path()
{
  static access_path_to_memoryt const  null_path(ID_nil);
  return null_path;
}


bool  is_empty(access_path_to_memoryt const&  path)
{
  return path.is_nil();
}


bool  is_typecast(access_path_to_memoryt const&  lvalue)
{
  return lvalue.id() == ID_typecast;
}

const access_path_to_memoryt&  get_typecast_target(
    access_path_to_memoryt const&  lvalue,
    namespacet const&  ns
    )
{
  assert(is_typecast(lvalue));
  return static_cast<const exprt&>(lvalue.get_sub().front());
}


bool  is_identifier(access_path_to_memoryt const&  lvalue)
{
  return lvalue.id() == ID_symbol;
}


bool  is_dereference(access_path_to_memoryt const&  lvalue)
{
  return lvalue.id() == ID_dereference;
}

const access_path_to_memoryt&  get_dereferenced_operand(
    access_path_to_memoryt const&  lvalue
    )
{
  assert(is_dereference(lvalue));
  return static_cast<const exprt&>(lvalue.get_sub().front());
}


bool  is_member(access_path_to_memoryt const&  lvalue)
{
  return lvalue.id() == ID_member;
}

const exprt& get_underlying_object(const exprt& in)
{
  if(in.id()==ID_member)
    return get_underlying_object(in.op0());
  else
    return in;
}

const access_path_to_memoryt&  get_member_accessor(
    access_path_to_memoryt const&  lvalue
    )
{
  assert(is_member(lvalue));
  return static_cast<const exprt&>(lvalue.get_sub().front());
}

const irep_idt&  get_member_name(access_path_to_memoryt const&  lvalue)
{
  assert(is_member(lvalue));
  return lvalue.get_named_sub().at(ID_component_name).id();
}


bool  is_side_effect_malloc(access_path_to_memoryt const&  lvalue)
{
  if (lvalue.id() != ID_side_effect)
    return false;
  auto const  it = lvalue.get_named_sub().find(ID_statement);
  if (it == lvalue.get_named_sub().cend() || it->second.id() != "malloc")
    return false;
  return true;
}

const access_path_to_memoryt& get_malloc_of_side_effect(
    access_path_to_memoryt const&  lvalue
    )
{
  assert(is_side_effect_malloc(lvalue));
  return static_cast<const exprt&>(lvalue.get_named_sub().at(ID_statement));
}


std::string  name_of_symbol_access_path(access_path_to_memoryt const&  lvalue)
{
  return is_identifier(lvalue) ?
              as_string(to_symbol_expr(lvalue).get_identifier()) :
              "";
}


bool  is_parameter(access_path_to_memoryt const&  lvalue, namespacet const&  ns)
{
  if (is_identifier(lvalue))
  {
    symbolt const*  symbol = nullptr;
    ns.lookup(name_of_symbol_access_path(lvalue),symbol);
    return symbol != nullptr && symbol->is_parameter;
  }
  return false;
}

bool  is_static(access_path_to_memoryt const&  lvalue, namespacet const&  ns)
{
  if (is_identifier(lvalue))
  {
    symbolt const*  symbol = nullptr;
    ns.lookup(name_of_symbol_access_path(lvalue),symbol);
    return symbol != nullptr && symbol->is_static_lifetime;
  }
  else if (lvalue.id() == ID_member)
  {
  }
  return false;
}

bool  is_return_value_auxiliary(access_path_to_memoryt const&  lvalue,
                                namespacet const&  ns)
{
  if (is_identifier(lvalue))
  {
    irep_idt const&  name = name_of_symbol_access_path(lvalue);
    symbolt const*  symbol = nullptr;
    ns.lookup(name,symbol);
    return symbol != nullptr &&
           symbol->is_static_lifetime &&
           symbol->is_auxiliary &&
           symbol->is_file_local &&
           symbol->is_thread_local &&
           as_string(name).find("#return_value") != std::string::npos
           ;
  }
  return false;
}

bool  is_pure_local(access_path_to_memoryt const&  lvalue,
                    namespacet const&  ns)
{
  return lvalue.id() != ID_member &&
         lvalue.id() != "external-value-set" &&
         lvalue.id() != ID_dynamic_object &&
         !is_parameter(lvalue,ns) &&
         !is_static(lvalue,ns)
         ;
}

bool  is_pointer(access_path_to_memoryt const&  lvalue,
                 namespacet const&  ns)
{
  return lvalue.type().id() == ID_pointer;
}

bool  is_this(access_path_to_memoryt const&  lvalue, namespacet const&  ns)
{
  if (!is_identifier(lvalue))
    return false;
  std::string const  name = name_of_symbol_access_path(lvalue);
  std::string const  keyword = "::this";
  if (name.size() <= keyword.size())
    return false;
  std::size_t const  index = name.rfind(keyword);
  std::size_t const  matching_index = name.size() - keyword.size();
  return index == matching_index;
}


void  collect_access_paths(
    exprt const&  expr,
    namespacet const&  ns,
    set_of_access_pathst&  result,
    bool const  perform_normalisation
    )
{
  if (expr.id() == ID_symbol || expr.id() == ID_member)
    result.insert(
          perform_normalisation ? normalise(expr,ns) : expr
          );
  else
    for (exprt const&  op : expr.operands())
      collect_access_paths(op,ns,result);
}


access_path_to_memoryt  normalise(
    access_path_to_memoryt const&  access_path,
    namespacet const&  ns
    )
{
  return simplify_expr(access_path,ns);
}


access_path_to_memoryt  scope_translation(
    access_path_to_memoryt const&  source_path,
    irep_idt const&  source_scope_id,
    irep_idt const&  target_scope_id,
    code_function_callt const&  source_scope_call_expr,
    code_typet const&  source_scope_type,
    namespacet const&  ns
    )
{
  (void)target_scope_id;

  std::string const  source_this =
      msgstream() << as_string(source_scope_id) << "::this";

  if (!source_scope_type.parameters().empty() &&
          as_string(source_scope_type.parameters().at(0UL).get_identifier())
          == source_this)
  {
    access_path_to_memoryt const&  target_this =
        remove_cast_to_void_ptr_if_present(
            source_scope_call_expr.arguments().at(0UL)
            );

    access_path_to_memoryt  target_path = source_path;
    substitute_symbol(target_path,source_this,target_this);
    target_path = normalise(target_path,ns);

//std::cout << "**********************************************************\n";
//std::cout << "source_path pretty: " << from_expr(ns, "", source_path) << "\n";
//std::cout << "target_path pretty: " << from_expr(ns, "", target_path) << "\n";
//std::cout << "target_this pretty: " << from_expr(ns, "", target_this) << "\n";
//std::cout << "source_path:\n";
//detail::dump_irept(source_path,std::cout);
//std::cout << "target_this:\n";
//detail::dump_irept(target_this,std::cout);
//std::cout << "target_path:\n";
//detail::dump_irept(target_path,std::cout);

    return target_path;
  }

  return source_path;
}

// Returns true if an expression refers to a unique dynamic lvalue,
// as opposed to e.g. a dynamic object expression, which refers to the general
// case of objects allocated [at a particular program point]
bool is_singular_object(const exprt& e)
{
  const auto& obj=get_underlying_object(e);
  if(obj.id()==ID_symbol)
    return true;
  else
    return false;
}
