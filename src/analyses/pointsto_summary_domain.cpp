/*******************************************************************\

Module: pointsto_summary_domain

Author: Marek Trtik

Date: Octomber 2016


@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <analyses/pointsto_summary_domain.h>
#include <summaries/summary_dump.h>
#include <algorithm>
#include <iterator>
#include <iostream>


static bool  irep_id_less(const irept&  a, const irept&  b)
{
  return a.id() < b.id();
}


pointsto_expressiont::pointsto_expressiont(const dstring&  keyword)
  : irept(keyword)
{}

dstring pointsto_expressiont::keyword()
{
  return "";
}


dstring pointsto_set_of_offsetst::keyword()
{
  return ID_pointsto_access_paths_definition_offsets;
}

pointsto_set_of_offsetst::pointsto_set_of_offsetst(
    const offset_namest&  offset_names,
    bool const is_exact
    )
  : irept(keyword())
{
  for (auto const&  offset : offset_names)
    get_sub().push_back(irept(offset));
  get_sub().push_back(irept(is_exact ? "yes" : "no"));
}

std::size_t  pointsto_set_of_offsetst::get_num_offsets() const
{
  return get_sub().size() - 1UL;
}

const irep_idt&  pointsto_set_of_offsetst::get_offset_name(
    const std::size_t offset_index
    ) const
{
  assert(offset_index < get_num_offsets());
  return get_sub().at(offset_index).id();
}

bool  pointsto_set_of_offsetst::is_exact() const
{
  return get_sub().back().id() == "yes";
}

bool  pointsto_set_of_offsetst::contains(
    const irep_idt&  offset_name
    ) const
{
  return std::binary_search(
            get_sub().cbegin(),
            std::prev(get_sub().cend()),
            irept(offset_name),
            irep_id_less
            );
}



dstring pointsto_address_shiftt::keyword()
{
  return ID_pointsto_access_paths_shift;
}

pointsto_address_shiftt::pointsto_address_shiftt(
    const pointsto_expressiont&  targets,
    const pointsto_set_of_offsetst&  offsets
    )
  : irept(keyword())
{
  get_sub().push_back(targets);
  get_sub().push_back(offsets);
}

const pointsto_expressiont& pointsto_address_shiftt::get_targets() const
{
  return pointsto_as<pointsto_expressiont>(get_sub().front());
}

const pointsto_set_of_offsetst& pointsto_address_shiftt::get_offsets() const
{
  return pointsto_as<pointsto_set_of_offsetst>(get_sub().back());
}


dstring pointsto_null_targett::keyword()
{
  return ID_NULL;
}

pointsto_null_targett::pointsto_null_targett()
  : pointsto_expressiont(keyword())
{}


dstring pointsto_symbolic_set_of_targetst::keyword()
{
  return ID_pointsto_access_paths_definition_symbolic;
}

pointsto_symbolic_set_of_targetst::pointsto_symbolic_set_of_targetst()
  : pointsto_expressiont(keyword())
{
  get_sub().push_back(irept(make_fresh_symbol_name()));
}

const irep_idt& pointsto_symbolic_set_of_targetst::get_symbolic_set_name() const
{
  return get_sub().back().id();
}

irep_idt  pointsto_symbolic_set_of_targetst::make_fresh_symbol_name()
{
  static uint64_t  counter = 0UL;
  std::string const  symbol_name =
      msgstream() << "A" << ++counter;
  return symbol_name;
}


dstring  pointsto_set_of_concrete_targetst::keyword()
{
  return ID_pointsto_access_paths_definition_concrete;
}

pointsto_set_of_concrete_targetst::pointsto_set_of_concrete_targetst(
    const irep_idt&  target_name
    )
  : pointsto_set_of_concrete_targetst(
      std::set<irep_idt>{target_name}
      )
{}

pointsto_set_of_concrete_targetst::pointsto_set_of_concrete_targetst(
    const target_namest&  targets
    )
  : pointsto_expressiont(keyword())
{
  for (const auto&  target : targets)
    get_sub().push_back(irept(target));
}

std::size_t  pointsto_set_of_concrete_targetst::get_num_targets() const
{
  return get_sub().size();
}

const irep_idt&  pointsto_set_of_concrete_targetst::get_target_name(
    const std::size_t target_index
    ) const
{
  assert(target_index < get_num_targets());
  return get_sub().at(target_index).id();
}

bool  pointsto_set_of_concrete_targetst::contains(
    const irep_idt&  target_name
    ) const
{
  return std::binary_search(
            get_sub().cbegin(),
            get_sub().cend(),
            irept(target_name),
            irep_id_less
            );
}


dstring  pointsto_set_of_address_shifted_targetst::keyword()
{
  return ID_pointsto_access_paths_definition_shifted;
}

pointsto_set_of_address_shifted_targetst::
pointsto_set_of_address_shifted_targetst(
      const pointsto_address_shiftt& shift
      )
  : pointsto_expressiont(keyword())
{
  get_sub().push_back(shift);
}

const pointsto_address_shiftt&
pointsto_set_of_address_shifted_targetst::get_address_shift() const
{
  return pointsto_as<pointsto_address_shiftt>(get_sub().front());
}


dstring pointsto_address_dereferencet::keyword()
{
  return ID_pointsto_access_paths_dereference;
}

pointsto_address_dereferencet::pointsto_address_dereferencet(
    const pointsto_address_shiftt&  address_shift
    )
  : pointsto_expressiont(keyword())
{
  get_sub().push_back(address_shift);
}

const pointsto_address_shiftt&
pointsto_address_dereferencet::get_address_shift() const
{
  return pointsto_as<pointsto_address_shiftt>(get_sub().front());
}


dstring pointsto_subtract_sets_of_targetst::keyword()
{
  return ID_pointsto_access_paths_subtract;
}

pointsto_subtract_sets_of_targetst::pointsto_subtract_sets_of_targetst(
    const pointsto_expressiont&  left,
    const pointsto_expressiont&  right
    )
  : pointsto_expressiont(keyword())
{
  get_sub().push_back(left);
  get_sub().push_back(right);
}

const pointsto_expressiont& pointsto_subtract_sets_of_targetst::get_left() const
{
  return pointsto_as<pointsto_expressiont>(get_sub().front());
}

const pointsto_expressiont& pointsto_subtract_sets_of_targetst::get_right()const
{
  return pointsto_as<pointsto_expressiont>(get_sub().back());
}


dstring pointsto_union_sets_of_targetst::keyword()
{
  return ID_pointsto_access_paths_union;
}

pointsto_union_sets_of_targetst::pointsto_union_sets_of_targetst(
    const pointsto_expressiont&  left,
    const pointsto_expressiont&  right
    )
  : pointsto_expressiont(keyword())
{
  get_sub().push_back(left);
  get_sub().push_back(right);
}

const pointsto_expressiont& pointsto_union_sets_of_targetst::get_left() const
{
  return pointsto_as<pointsto_expressiont>(get_sub().front());
}

const pointsto_expressiont& pointsto_union_sets_of_targetst::get_right()const
{
  return pointsto_as<pointsto_expressiont>(get_sub().back());
}


dstring  pointsto_if_empty_then_elset::keyword()
{
  return ID_pointsto_access_paths_conditional;
}

pointsto_if_empty_then_elset::pointsto_if_empty_then_elset(
      const pointsto_expressiont&  conditional_targets,
      const pointsto_expressiont&  true_branch_targets,
      const pointsto_expressiont&  false_branch_targets
      )
  : pointsto_expressiont(keyword())
{
  get_sub().push_back(conditional_targets);
  get_sub().push_back(true_branch_targets);
  get_sub().push_back(false_branch_targets);
}

const pointsto_expressiont&
pointsto_if_empty_then_elset::get_conditional_targets() const
{
  return pointsto_as<pointsto_expressiont>(get_sub().front());
}

const pointsto_expressiont&
pointsto_if_empty_then_elset::get_true_branch_targets() const
{
  return pointsto_as<pointsto_expressiont>(get_sub().at(1));
}

const pointsto_expressiont&
pointsto_if_empty_then_elset::get_false_branch_targets() const
{
  return pointsto_as<pointsto_expressiont>(get_sub().back());
}


pointsto_expressiont  pointsto_expression_empty_set_of_targets()
{
  return pointsto_set_of_concrete_targetst(
            pointsto_set_of_concrete_targetst::target_namest{}
            );
}

bool  pointsto_is_empty_set_of_targets(const pointsto_expressiont& a)
{
  if (const pointsto_set_of_concrete_targetst* const targets =
        pointsto_as<pointsto_set_of_concrete_targetst>(&a))
    if (targets->empty())
      return true;
  return false;
}


pointsto_expressiont  pointsto_expression_normalise(
    const pointsto_expressiont&  a
    )
{
  if (const pointsto_subtract_sets_of_targetst* const subtract =
        pointsto_as<pointsto_subtract_sets_of_targetst>(&a))
  {
    if (const pointsto_set_of_concrete_targetst* const left =
          pointsto_as<pointsto_set_of_concrete_targetst>(&subtract->get_left()))
    {
      if (const pointsto_set_of_concrete_targetst* const right =
         pointsto_as<pointsto_set_of_concrete_targetst>(&subtract->get_right()))
      {
        pointsto_set_of_concrete_targetst::target_namest  names;
        for (std::size_t  i = 0UL; i < left->get_num_targets(); ++i)
          if (!right->contains(left->get_target_name(i)))
            names.insert(left->get_target_name(i));
        return pointsto_set_of_concrete_targetst{names};
      }
    }
  }
  if (const pointsto_union_sets_of_targetst* const punion =
        pointsto_as<pointsto_union_sets_of_targetst>(&a))
  {
    if (punion->get_left() == punion->get_right())
      return punion->get_left();
    if (pointsto_is_empty_set_of_targets(punion->get_left()))
      return punion->get_right();
    if (pointsto_is_empty_set_of_targets(punion->get_right()))
      return punion->get_left();

    if (const pointsto_union_sets_of_targetst* const right =
          pointsto_as<pointsto_union_sets_of_targetst>(&punion->get_right()))
    {
      if (punion->get_left() == right->get_left())
        return pointsto_union_sets_of_targetst(
                  punion->get_left(),
                  right->get_right()
                  );

    }
    return a;
  }
  if (const pointsto_address_dereferencet* const deref =
        pointsto_as<pointsto_address_dereferencet>(&a))
  {
    const pointsto_address_shiftt&  shift = deref->get_address_shift();
    if (const pointsto_union_sets_of_targetst* const punion =
          pointsto_as<pointsto_union_sets_of_targetst>(&shift.get_targets()))
      return pointsto_union_sets_of_targetst(
                pointsto_expression_normalise(
                    pointsto_address_dereferencet(
                        pointsto_address_shiftt(
                            punion->get_left(),
                            shift.get_offsets()
                            )
                        )
                    ),
                pointsto_expression_normalise(
                    pointsto_address_dereferencet(
                        pointsto_address_shiftt(
                            punion->get_right(),
                            shift.get_offsets()
                            )
                        )
                    )
                );
    if (const pointsto_address_dereferencet* const inner =
          pointsto_as<pointsto_address_dereferencet>(&shift.get_targets()))
    {
      const pointsto_address_shiftt&  inner_shift = inner->get_address_shift();
      pointsto_set_of_offsetst::offset_namest names;
      {
        const pointsto_set_of_offsetst& inner_offsets =
            inner_shift.get_offsets();
        for (std::size_t  i = 0UL; i < inner_offsets.get_num_offsets(); ++i)
          names.insert(inner_offsets.get_offset_name(i));
        const pointsto_set_of_offsetst& outer_offsets =
            shift.get_offsets();
        for (std::size_t  i = 0UL; i < outer_offsets.get_num_offsets(); ++i)
          names.insert(outer_offsets.get_offset_name(i));
      }
      return pointsto_address_dereferencet(
                  pointsto_address_shiftt(
                      inner_shift.get_targets(),
                      pointsto_set_of_offsetst(
                          names,
                          false
                          )
                      )
                  );
    }
    return a;
  }
  if (const pointsto_if_empty_then_elset* const ite =
        pointsto_as<pointsto_if_empty_then_elset>(&a))
  {
    if (const pointsto_set_of_concrete_targetst* const cond =
          pointsto_as<pointsto_set_of_concrete_targetst>(
              &ite->get_conditional_targets()) )
      return cond->empty() ? ite->get_true_branch_targets()  :
                             ite->get_false_branch_targets() ;
    return a;
  }
  return a;
}


pointsto_expressiont  pointsto_evaluate_expression(
    const pointsto_rulest&  domain_value,
    const pointsto_expressiont&  expression
    )
{
  pointsto_expressiont  result = pointsto_expression_empty_set_of_targets();
  for (const auto&  rule : domain_value)
    result =
        pointsto_expression_normalise(
            pointsto_union_sets_of_targetst(
                result,
                pointsto_expression_normalise(
                    pointsto_if_empty_then_elset(
                        pointsto_expression_normalise(
                            pointsto_subtract_sets_of_targetst(
                                expression,
                                rule.first
                                )
                            ),
                        rule.second,
                        pointsto_expression_empty_set_of_targets()
                        )
                    )
                )
          );
  return result;
}

pointsto_expressiont  pointsto_evaluate_access_path(
    const pointsto_rulest&  domain_value,
    const access_path_to_memoryt&  access_path,
    const bool  as_lvalue,
    const namespacet&  ns
    )
{
  if (is_typecast(access_path))
    return pointsto_evaluate_access_path(
              domain_value,
              get_typecast_target(access_path,ns),
              as_lvalue,
              ns
              );

  if (is_identifier(access_path))
  {
    const pointsto_set_of_concrete_targetst  expression(
                      name_of_symbol_access_path(access_path)
                      );
    if (as_lvalue)
      return expression;
    return pointsto_evaluate_expression(domain_value,expression);
  }
  if (is_dereference(access_path))
    return pointsto_evaluate_access_path(
              domain_value,
              get_dereferenced_operand(access_path),
              false,
              ns
              );
  if (is_side_effect_malloc(access_path))
  {
    return pointsto_set_of_concrete_targetst(
              get_malloc_of_side_effect(access_path).id()
              );
  }
  if (is_member(access_path))
  {
    const irep_idt&  member_name = get_member_name(access_path);
    const pointsto_expressiont  accessor =
        pointsto_evaluate_access_path(
            domain_value,
            get_member_accessor(access_path),
            false,
            ns
            );
    if (pointsto_is_empty_set_of_targets(accessor))
      return accessor;
    const pointsto_address_shiftt  shift(
        accessor,
        pointsto_set_of_offsetst({member_name},true)
        );
    if (as_lvalue)
      return pointsto_expression_normalise(
                pointsto_set_of_address_shifted_targetst(shift)
                );
    else
      return pointsto_expression_normalise(
                pointsto_address_dereferencet(shift)
                );
  }

  std::cout << "\n\n**** UNSUPPORTED YET ***********************************\n";
  dump_access_path_in_html(access_path,ns,std::cout);
  std::cout << "\n";
  dump_irept(access_path,std::cout);
  std::cout.flush();

  return pointsto_expression_empty_set_of_targets();
}
