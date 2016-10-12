/*******************************************************************\

Module: pointsto_summary_domain

Author: Marek Trtik

Date: Octomber 2016


@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <analyses/pointsto_summary_domain.h>


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
  get_sub().push_back(irept(is_exact ? "yes" : "no"));
  for (auto const&  offset : offset_names)
    get_sub().push_back(irept(offset));
}

void  pointsto_set_of_offsetst::get_offset_names(
    offset_namest&  output_names
    ) const
{
  for (std::size_t  i = 1UL; i < get_sub().size(); ++i)
    output_names.insert(get_sub().at(i).id());
}

bool  pointsto_set_of_offsetst::is_exact() const
{
  return get_sub().front().id() == "yes";
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
      std::unordered_set<irep_idt,dstring_hash>{target_name}
      )
{}

pointsto_set_of_concrete_targetst::pointsto_set_of_concrete_targetst(
    const std::unordered_set<irep_idt,dstring_hash>&  targets
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
  return get_sub().at(target_index).id();
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
            std::unordered_set<irep_idt,dstring_hash>{}
            );
}


pointsto_expressiont  pointsto_expression_normalise(
    const pointsto_expressiont&  a
    )
{
  // TODO!
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
    const access_path_to_memoryt&  access_path
    )
{
  if (is_identifier(access_path))
    return pointsto_set_of_concrete_targetst(
                name_of_symbol_access_path(access_path)
                );

  // TODO!

  if (is_member(access_path))
  {
  }

  return pointsto_expression_empty_set_of_targets();
}
