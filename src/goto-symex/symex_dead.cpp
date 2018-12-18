/*******************************************************************\

Module: Symbolic Execution

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

/// \file
/// Symbolic Execution

#include "goto_symex.h"

#include <util/find_symbols.h>
#include <util/std_expr.h>

#include <pointer-analysis/add_failed_symbols.h>

#include "field_sensitivity.h"

void goto_symext::symex_dead(statet &state)
{
  const goto_programt::instructiont &instruction=*state.source.pc;

  const code_deadt &code = to_code_dead(instruction.code);

  // We increase the L2 renaming to make these non-deterministic.
  // We also prevent propagation of old values.

  ssa_exprt ssa(code.symbol());
  state.rename(ssa, ns, goto_symex_statet::L1);

  // in case of pointers, put something into the value set
  if(ns.follow(code.symbol().type()).id() == ID_pointer)
  {
    exprt failed = get_failed_symbol(to_symbol_expr(code.symbol()), ns);

    exprt rhs;

    if(failed.is_not_nil())
      rhs = address_of_exprt(failed, to_pointer_type(code.symbol().type()));
    else
      rhs=exprt(ID_invalid);

    state.rename(rhs, ns, goto_symex_statet::L1);
    state.value_set.assign(ssa, rhs, ns, true, false);
  }

  const exprt l2_fields = field_sensitivityt::get_fields(ns, ssa, state);
  std::set<exprt> l2_fields_set;
  find_symbols(l2_fields, l2_fields_set);

  for(const exprt &l2_field_set : l2_fields_set)
  {
    ssa_exprt ssa_lhs = to_ssa_expr(l2_field_set);
    const irep_idt &l1_identifier = ssa_lhs.get_identifier();

    // prevent propagation
    state.propagation.erase(l1_identifier);

    // TODO: not sure why the rest below is necessary
    // L2 renaming
    auto level2_it = state.level2.current_names.find(l1_identifier);
    if(level2_it != state.level2.current_names.end())
      symex_renaming_levelt::increase_counter(level2_it);

    const bool record_events = state.record_events;
    state.record_events = false;
    state.rename(ssa_lhs, ns);
    state.record_events = record_events;

    if(
      state.dirty(ssa_lhs.get_object_name()) && state.atomic_section_id == 0)
    {
      target.shared_write(
        state.guard.as_expr(), ssa_lhs, state.atomic_section_id, state.source);
    }
  }
}
