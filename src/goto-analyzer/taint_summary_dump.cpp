/////////////////////////////////////////////////////////////////////////////
//
// Module: taint_summary
// Author: Marek Trtik
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////


#include <goto-analyzer/taint_summary_dump.h>
#include <memory>
#include <set>
#include <iostream>
#include <iomanip>
#include <cassert>

namespace sumfn { namespace taint { namespace detail { namespace {


}}}}

namespace sumfn { namespace taint {


void  dump_value_in_html(
    value_of_variable_t const&  value,
    std::ostream&  ostr
    )
{
  if (value.is_top())
    ostr << "TOP";
  else if (value.is_bottom())
    ostr << "BOTTOM";
  else
  {
    bool first = true;
    for (auto const&  symbol : value.expression())
    {
       ostr << (first ? "" : " &#x2210 ") << symbol;
       first = false;
    }
  }
}

void  dump_vars_to_values_in_html(
    map_from_vars_to_values_t const&  vars_to_values,
    std::ostream&  ostr
    )
{
  std::set<variable_id_t>  vars;
  for (auto const&  elem : vars_to_values.data())
    vars.insert(elem.first);

  if (vars.empty())
    ostr << "BOTTOM";
  else
  {
    ostr << "    <table>\n";
    for (auto const&  var : vars)
    {
      ostr << "      <tr>\n";
      ostr << "        <td>" << to_html_text(var) << "</td>\n";
      ostr << "        <td>";
      dump_value_in_html(vars_to_values.data().at(var),ostr);
      ostr << "</td>\n";
      ostr << "      </tr>\n";
    }
    ostr << "    </table>\n";
  }
}


std::string  dump_in_html(
    object_summary_t const  obj_summary,
    goto_modelt const&  program,
    std::ostream&  ostr
    )
{
  summarised_object_id_t const&  function_id = obj_summary.first;
  summary_ptr_t const  summary =
      std::dynamic_pointer_cast<summary_t const>(obj_summary.second);
  if (!summary.operator bool())
    return "ERROR: cannot cast the passed summary to 'taint' summary.";

  ostr << "<h2>Taint summary</h2>\n"
       << "<p>TODO!</p>\n"
       ;

  if (summary->domain())
  {
    auto const  fn_it =
        program.goto_functions.function_map.find(irep_idt(function_id));
    if (fn_it != program.goto_functions.function_map.cend())
    {
      goto_programt const&  fn_body = fn_it->second.body;
      ostr << "<h3>Domain</h3>\n"
              "<table>\n"
              "  <tr>\n"
              "    <th>Loc</th>\n"
              "    <th>Targets</th>\n"
              "    <th>Instruction</th>\n"
              "    <th>Domain value</th>\n"
              "  </tr>\n"
           ;
      for (auto  instr_it = fn_body.instructions.cbegin();
          instr_it != fn_body.instructions.cend();
          ++instr_it)
      {
        ostr << "  <tr>\n";

        // Dumping program location
        ostr << "    <td>"
             << instr_it->location_number
             << "</td>\n"
             ;

        // Dumping targets
        if (instr_it->is_target())
          ostr << "    <td>" << instr_it->target_number << "</td>\n";
        else
          ostr << "    <td>    </td>\n";

        // Dumping instruction
        ostr << "    <td>\n";
        dump_instruction_code_in_html(*instr_it,program,ostr);
        ostr << "</td>\n";

        // Dumping taint domain
        auto const  vars_to_values_it = summary->domain()->find(instr_it);
        if (vars_to_values_it != summary->domain()->cend())
        {
          ostr << "  <td>\n";
          dump_vars_to_values_in_html(vars_to_values_it->second,ostr);
          ostr << "  </td>\n";
        }

        ostr << "  </tr>\n";
      }
      ostr << "</table>\n";
    }
  }

  return ""; // no error.
}
  
  
}}
