#include <analyses/pointsto_summary_domain_dump.h>
#include <summaries/utility.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cassert>


static bool enclose_in_brackets(const pointsto_expressiont&  expression)
{
  return !(
        pointsto_is_of<pointsto_symbolic_set_of_targetst>(expression)
        || pointsto_is_of<pointsto_set_of_concrete_targetst>(expression)
        || pointsto_is_of<pointsto_address_dereferencet>(expression)
        );
}


std::string  pointsto_dump_expression_in_html(
    const pointsto_expressiont&  expression,
    std::ostream&  ostr
    )
{
  if (const pointsto_null_targett* ptr =
        pointsto_as<pointsto_null_targett>(&expression))
    return pointsto_dump_null_target_in_html(*ptr,ostr);
  if (const pointsto_symbolic_set_of_targetst* ptr =
        pointsto_as<pointsto_symbolic_set_of_targetst>(&expression))
    return pointsto_dump_symbolic_set_of_targets_in_html(*ptr,ostr);
  if (const pointsto_set_of_concrete_targetst* ptr =
        pointsto_as<pointsto_set_of_concrete_targetst>(&expression))
    return pointsto_dump_set_of_concrete_targets_in_html(*ptr,ostr);
  if (const pointsto_set_of_address_shifted_targetst* ptr =
        pointsto_as<pointsto_set_of_address_shifted_targetst>(&expression))
    return pointsto_dump_address_shifted_targets_in_html(*ptr,ostr);
  if (const pointsto_address_dereferencet* ptr =
        pointsto_as<pointsto_address_dereferencet>(&expression))
    return pointsto_dump_address_dereference_in_html(*ptr,ostr);
  if (const pointsto_subtract_sets_of_targetst* ptr =
        pointsto_as<pointsto_subtract_sets_of_targetst>(&expression))
    return pointsto_dump_subtract_sets_of_targets_in_html(*ptr,ostr);
  if (const pointsto_union_sets_of_targetst* ptr =
        pointsto_as<pointsto_union_sets_of_targetst>(&expression))
    return pointsto_dump_union_sets_of_targets_in_html(*ptr,ostr);
  if (const pointsto_if_empty_then_elset* ptr =
        pointsto_as<pointsto_if_empty_then_elset>(&expression))
    return pointsto_dump_if_empty_then_else_in_html(*ptr,ostr);

  return "UNKNOWN";
}

std::string  pointsto_dump_null_target_in_html(
    const pointsto_null_targett&,
    std::ostream&  ostr
    )
{
  ostr << "NULL";
  return ""; // No error.
}

std::string  pointsto_dump_symbolic_set_of_targets_in_html(
    const pointsto_symbolic_set_of_targetst&  targets,
    std::ostream&  ostr
    )
{
  ostr << targets.get_symbolic_set_name();
  return ""; // No error.
}

std::string  pointsto_dump_set_of_concrete_targets_in_html(
    const pointsto_set_of_concrete_targetst&  targets,
    std::ostream&  ostr
    )
{
  ostr << '{';
  for (std::size_t  i = 0UL; i < targets.get_num_targets(); ++i)
  {
    ostr << targets.get_target_name(i);
    if (i+1UL < targets.get_num_targets())
      ostr << ',';
  }
  ostr << '}';
  return ""; // No error.
}

std::string  pointsto_dump_address_shifted_targets_in_html(
    const pointsto_set_of_address_shifted_targetst&  targets,
    std::ostream&  ostr
    )
{
  ostr << '{';
  std::string const  error_message =
      pointsto_dump_address_shift_in_html(
          targets.get_address_shift(),
          ostr
          );
  if (!error_message.empty())
    return error_message;
  ostr << '}';
  return ""; // No error.
}

std::string  pointsto_dump_address_dereference_in_html(
    const pointsto_address_dereferencet&  targets,
    std::ostream&  ostr
    )
{
  ostr << '[';
  std::string const  error_message =
      pointsto_dump_address_shift_in_html(
        targets.get_address_shift(),
        ostr
        );
  if (!error_message.empty())
    return error_message;
  ostr << ']';
  return ""; // No error.
}

std::string  pointsto_dump_address_shift_in_html(
    const pointsto_address_shiftt&  shift,
    std::ostream&  ostr
    )
{
  if (enclose_in_brackets(shift.get_targets()))
    ostr << '(';
  std::string  error_message =
      pointsto_dump_expression_in_html(
        shift.get_targets(),
        ostr
        );
  if (!error_message.empty())
    return error_message;
  if (enclose_in_brackets(shift.get_targets()))
    ostr << ')';
  ostr << '.';
  error_message =
       pointsto_dump_set_of_offsetst_in_html(
         shift.get_offsets(),
         ostr
         );
   return error_message;
}

std::string  pointsto_dump_set_of_offsetst_in_html(
    const pointsto_set_of_offsetst&  offsets,
    std::ostream&  ostr
    )
{
  ostr << '{';
  for (std::size_t  i = 0UL; i < offsets.get_num_offsets(); ++i)
  {
    ostr << offsets.get_offset_name(i);
    if (i+1UL<offsets.get_num_offsets())
      ostr << ',';
  }
  ostr << '}';
  if (!offsets.is_exact())
    ostr << "<b>!</b>";
  return ""; // No error.
}


std::string  pointsto_dump_subtract_sets_of_targets_in_html(
    const pointsto_subtract_sets_of_targetst&  expression,
    std::ostream&  ostr
    )
{
  if (enclose_in_brackets(expression.get_left()))
    ostr << '(';
  std::string  error_message =
      pointsto_dump_expression_in_html(
        expression.get_left(),
        ostr
        );
  if (!error_message.empty())
    return error_message;
  if (enclose_in_brackets(expression.get_left()))
    ostr << ')';
  ostr << " <b>\\</b> ";
  if (enclose_in_brackets(expression.get_right()))
    ostr << '(';
  error_message =
      pointsto_dump_expression_in_html(
        expression.get_right(),
        ostr
        );
  if (!error_message.empty())
    return error_message;
  if (enclose_in_brackets(expression.get_right()))
    ostr << ')';
  return ""; // No error.
}

std::string  pointsto_dump_union_sets_of_targets_in_html(
    const pointsto_union_sets_of_targetst&  expression,
    std::ostream&  ostr
    )
{
  for (std::size_t  i = 0UL; i < expression.get_num_operands(); ++i)
  {
    if (enclose_in_brackets(expression.get_operand(i)))
      ostr << '(';
    std::string  error_message =
        pointsto_dump_expression_in_html(
          expression.get_operand(i),
          ostr
          );
    if (!error_message.empty())
      return error_message;
    if (enclose_in_brackets(expression.get_operand(i)))
      ostr << ')';
    if (i+1UL < expression.get_num_operands())
      ostr << " <b>&#x2210;</b> ";
  }
  return ""; // No error.
}

std::string  pointsto_dump_if_empty_then_else_in_html(
    const pointsto_if_empty_then_elset&  expression,
    std::ostream&  ostr
    )
{
  std::string  error_message =
      pointsto_dump_expression_in_html(
        expression.get_conditional_targets(),
        ostr
        );
  if (!error_message.empty())
    return error_message;
  ostr << "=0 <b>?</b> ";
  error_message =
      pointsto_dump_expression_in_html(
        expression.get_true_branch_targets(),
        ostr
        );
  if (!error_message.empty())
    return error_message;
  ostr << " <b>:</b> ";
  error_message =
      pointsto_dump_expression_in_html(
        expression.get_false_branch_targets(),
        ostr
        );
  return error_message;
}


std::string  pointsto_dump_rules_in_html(
    pointsto_rulest const&  rules,
    std::ostream&  ostr,
    const std::string&  shift
    )
{
  if (rules.empty())
    ostr << shift << "BOTTOM";
  else
  {
    ostr << shift << "<table>\n";
    for (const auto&  pointers_targets : rules)
    {
      ostr << shift << "  <tr>\n";

      ostr << shift << "    <td>";
      std::string  error_message =
          pointsto_dump_expression_in_html(pointers_targets.first,ostr);
      ostr << shift << "</td>\n";
      if (!error_message.empty())
      {
        ostr << shift << "</table>\n";
        return error_message;
      }

      ostr << shift << "    <td>";
      error_message =
          pointsto_dump_expression_in_html(pointers_targets.second,ostr);
      ostr << shift << "</td>\n";
      if (!error_message.empty())
      {
        ostr << shift << "</table>\n";
        return error_message;
      }

      ostr << shift << "  </tr>\n";
    }
    ostr << shift << "</table>\n";
  }
  return ""; // No error.
}


