/*******************************************************************\

Module: Symbolic Execution

Author: Romain Brenguier, romain.brenguier@diffblue.com

\*******************************************************************/

/// \file
/// Renaming levels

#include "renaming_level.h"

#include <util/namespace.h>
#include <util/ssa_expr.h>
#include <util/symbol.h>

#include "goto_symex_state.h"

void symex_level0t::
operator()(ssa_exprt &ssa_expr, const namespacet &ns, unsigned thread_nr) const
{
  // already renamed?
  if(!ssa_expr.get_level_0().empty())
    return;

  const irep_idt &obj_identifier = ssa_expr.get_object_name();

  // guards are not L0-renamed
  if(obj_identifier == goto_symex_statet::guard_identifier())
    return;

  const symbolt *s;
  const bool found_l0 = !ns.lookup(obj_identifier, s);
  INVARIANT(found_l0, "level0: failed to find " + id2string(obj_identifier));

  // don't rename shared variables or functions
  if(s->type.id() == ID_code || s->is_shared())
    return;

  // rename!
  ssa_expr.set_level_0(thread_nr);
}

void symex_level1t::operator()(ssa_exprt &ssa_expr) const
{
  // already renamed?
  if(!ssa_expr.get_level_1().empty())
    return;

  const irep_idt l0_name = ssa_expr.get_l1_object_identifier();

  const auto it = current_names.find(l0_name);
  if(it == current_names.end())
    return;

  // rename!
  ssa_expr.set_level_1(it->second.second);
}

void symex_level1t::restore_from(
  const symex_renaming_levelt::current_namest &other)
{
  auto it = current_names.begin();
  for(const auto &pair : other)
  {
    while(it != current_names.end() && it->first < pair.first)
      ++it;
    if(it == current_names.end() || pair.first < it->first)
      current_names.insert(it, pair);
    else if(it != current_names.end())
    {
      PRECONDITION(it->first == pair.first);
      it->second = pair.second;
      ++it;
    }
  }
}

/// Allocates a fresh L2 name for the given L1 identifier, and makes it the
/// latest generation on this path.
void symex_level2t::increase_generation(
  const irep_idt l1_identifier,
  const ssa_exprt &lhs)
{
  INVARIANT(
    global_names != nullptr, "Global level 2 naming map can't be null.");

  current_names.emplace(l1_identifier, std::make_pair(lhs, 0));
  global_names->emplace(l1_identifier, std::make_pair(lhs, 0));

  increase_generation_if_exists(l1_identifier);
}

/// Allocates a fresh L2 name for the given L1 identifier, and makes it the
/// latest generation on this path. Does nothing if there isn't an expression
/// keyed by the l1 identifier.
void symex_level2t::increase_generation_if_exists(const irep_idt identifier)
{
  // If we can't find the name in the local scope, don't increase the global
  // even if it exists there.
  auto current_names_iter = current_names.find(identifier);
  if(current_names_iter == current_names.end())
    return;

  INVARIANT(
    global_names != nullptr, "Global level 2 naming map can't be null.");

  // If we have a global store, increment its generation count, then assign
  // that new value to our local scope.
  auto global_names_iter = global_names->find(identifier);
  if(global_names_iter != global_names->end())
  {
    global_names_iter->second.second++;
    current_names_iter->second.second = global_names_iter->second.second;
  }
}

void get_original_name(exprt &expr)
{
  get_original_name(expr.type());

  if(expr.id() == ID_symbol && expr.get_bool(ID_C_SSA_symbol))
    expr = to_ssa_expr(expr).get_original_expr();
  else
    Forall_operands(it, expr)
      get_original_name(*it);
}

void get_original_name(typet &type)
{
  // rename all the symbols with their last known value

  if(type.id() == ID_array)
  {
    auto &array_type = to_array_type(type);
    get_original_name(array_type.subtype());
    get_original_name(array_type.size());
  }
  else if(type.id() == ID_struct || type.id() == ID_union)
  {
    struct_union_typet &s_u_type = to_struct_union_type(type);
    struct_union_typet::componentst &components = s_u_type.components();

    for(auto &component : components)
      get_original_name(component.type());
  }
  else if(type.id() == ID_pointer)
  {
    get_original_name(to_pointer_type(type).subtype());
  }
}
