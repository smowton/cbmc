/*******************************************************************\

Module: Symbolic Execution of ANSI-C

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

/// \file
/// Symbolic Execution of ANSI-C

#include "goto_symex.h"

#include <util/arith_tools.h>
#include <util/base_type.h>
#include <util/byte_operators.h>
#include <util/c_types.h>
#include <util/pointer_offset_size.h>

/// Given an expression, find the root object and the offset into it.
/// The expression refers to a cell of the array, so for example if the
/// underlying array is an int32_t[10] then `expr` will have type `int32_t`.
///
/// Input `expr` should already have been `clean_expr`'d, and so should be
/// dereference-free.
///
/// The extra complication to be considered here is that the expression may
/// have any number of ternary expressions mixed with type casts.
void goto_symext::array_cell_to_underlying_array(exprt &expr)
{
  // This may change the type of the expression!

  if(expr.id()==ID_if)
  {
    if_exprt &if_expr=to_if_expr(expr);
    array_cell_to_underlying_array(if_expr.true_case());
    array_cell_to_underlying_array(if_expr.false_case());

    if(!base_type_eq(if_expr.true_case(), if_expr.false_case(), ns))
    {
      byte_extract_exprt be(
        byte_extract_id(),
        if_expr.false_case(),
        from_integer(0, index_type()),
        if_expr.true_case().type());

      if_expr.false_case().swap(be);
    }

    if_expr.type()=if_expr.true_case().type();
  }
  else if(expr.id()==ID_address_of)
  {
    // strip
    exprt tmp = to_address_of_expr(expr).object();
    expr.swap(tmp);
    array_cell_to_underlying_array(expr);
  }
  else if(expr.id()==ID_symbol &&
          expr.get_bool(ID_C_SSA_symbol) &&
          to_ssa_expr(expr).get_original_expr().id()==ID_index)
  {
    const ssa_exprt &ssa=to_ssa_expr(expr);
    const index_exprt &index_expr=to_index_expr(ssa.get_original_expr());
    exprt tmp=index_expr.array();
    expr.swap(tmp);

    array_cell_to_underlying_array(expr);
  }
  else if(expr.id() != ID_symbol)
  {
    object_descriptor_exprt ode;
    ode.build(expr, ns);
    do_simplify(ode.offset());

    expr = ode.root_object();

    if(!ode.offset().is_zero())
    {
      if(expr.type().id() != ID_array)
      {
        exprt array_size = size_of_expr(expr.type(), ns);
        do_simplify(array_size);
        expr =
          byte_extract_exprt(
            byte_extract_id(),
            expr,
            from_integer(0, index_type()),
            array_typet(char_type(), array_size));
      }

      // given an array type T[N], i.e., an array of N elements of type T, and a
      // byte offset B, compute the array offset B/sizeof(T) and build a new
      // type T[N-(B/sizeof(T))]
      const array_typet &prev_array_type = to_array_type(expr.type());
      const typet &array_size_type = prev_array_type.size().type();
      const typet &subtype = prev_array_type.subtype();

      exprt new_offset(ode.offset());
      if(new_offset.type() != array_size_type)
        new_offset.make_typecast(array_size_type);
      exprt subtype_size = size_of_expr(subtype, ns);
      if(subtype_size.type() != array_size_type)
        subtype_size.make_typecast(array_size_type);
      new_offset = div_exprt(new_offset, subtype_size);
      minus_exprt new_size(prev_array_type.size(), new_offset);
      do_simplify(new_size);

      array_typet new_array_type(subtype, new_size);

      expr =
        byte_extract_exprt(
          byte_extract_id(),
          expr,
          ode.offset(),
          new_array_type);
    }
  }
}

/// Given a pointer-typed expression, find the root object and the offset into
/// it. The expression is a pointer to the array, so for example if the
/// underlying array is an int32_t[10] then `expr` will have type `int32_t *`.
///
/// `expr` will be cleaned in the process, so it may contain pointers on calling
/// this function, and on exit it will be dereference-free.
void goto_symext::array_pointer_to_underlying_array(
  exprt &expr, goto_symex_statet &state, bool write)
{
  // Strip any pointer-type casts first, to save
  // `array_cell_to_underlying_array` or the `object_descriptor_exprt` that does
  // much of its work from having to deal with that case.
  while(expr.id() == ID_typecast)
    expr = expr.op0();

  dereference_exprt array_cell(expr);
  clean_expr(array_cell, state, write);

  array_cell_to_underlying_array(array_cell);

  expr = array_cell;
}

/// Rewrite index/member expressions in byte_extract to offset
static void adjust_byte_extract_rec(exprt &expr, const namespacet &ns)
{
  Forall_operands(it, expr)
    adjust_byte_extract_rec(*it, ns);

  if(expr.id()==ID_byte_extract_big_endian ||
     expr.id()==ID_byte_extract_little_endian)
  {
    byte_extract_exprt &be=to_byte_extract_expr(expr);
    if(be.op().id()==ID_symbol &&
       to_ssa_expr(be.op()).get_original_expr().get_bool(ID_C_invalid_object))
      return;

    object_descriptor_exprt ode;
    ode.build(expr, ns);

    be.op()=ode.root_object();
    be.offset()=ode.offset();
  }
}

static void
replace_nondet(exprt &expr, symex_nondet_generatort &build_symex_nondet)
{
  if(expr.id() == ID_side_effect && expr.get(ID_statement) == ID_nondet)
  {
    nondet_symbol_exprt new_expr = build_symex_nondet(expr.type());
    new_expr.add_source_location() = expr.source_location();
    expr.swap(new_expr);
  }
  else
  {
    Forall_operands(it, expr)
      replace_nondet(*it, build_symex_nondet);
  }
}

void goto_symext::clean_expr(
  exprt &expr,
  statet &state,
  const bool write)
{
  replace_nondet(expr, build_symex_nondet);
  dereference(expr, state, write);

  // make sure all remaining byte extract operations use the root
  // object to avoid nesting of with/update and byte_update when on
  // lhs
  if(write)
    adjust_byte_extract_rec(expr, ns);
}
