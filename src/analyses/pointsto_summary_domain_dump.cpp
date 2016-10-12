#include <analyses/pointsto_summary_domain_dump.h>
#include <summaries/utility.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cassert>


std::string  pointsto_dump_expression_in_html(
    const pointsto_expressiont&  expression,
    std::ostream&  ostr
    )
{
  if (const pointsto_symbolic_set_of_targetst* ptr =
        pointsto_as<pointsto_symbolic_set_of_targetst>(&expression))
    return pointsto_dump_symbolic_set_of_targets_in_html(*ptr,ostr);
  if (const pointsto_set_of_concrete_targetst* ptr =
        pointsto_as<pointsto_set_of_concrete_targetst>(&expression))
    return pointsto_dump_set_of_concrete_targets_in_html(*ptr,ostr);

  return "ERROR: expression of no concrete type.";
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
    ostr << targets.get_function_name(i)
         << '@'
         << targets.get_location_number(i)
         << "::"
         << targets.get_target_name(i)
         ;
    if (i+1UL < targets.get_num_targets())
      ostr << ',';
  }
  ostr << '}';
  return ""; // No error.
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
      if (!error_message.empty())
        return error_message;
      ostr << shift << "</td>\n";

      ostr << shift << "    <td>";
      error_message =
          pointsto_dump_expression_in_html(pointers_targets.second,ostr);
      if (!error_message.empty())
        return error_message;
      ostr << shift << "</td>\n";

      ostr << shift << "  </tr>\n";
    }
    ostr << shift << "</table>\n";
  }
  return ""; // No error.
}


