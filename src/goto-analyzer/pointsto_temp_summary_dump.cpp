#include <goto-analyzer/pointsto_temp_summary_dump.h>
#include <analyses/pointsto_summary_domain_dump.h>
#include <summaries/utility.h>
#include <map>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cassert>


std::string  pointsto_temp_summary_dump_in_html(
    object_summaryt const  obj_summary,
    goto_modelt const&  program,
    std::ostream&  ostr
    )
{
  namespacet const  ns(program.symbol_table);
  summarised_object_idt const&  function_id = obj_summary.first;
  pointsto_temp_summary_ptrt const  summary =
      std::dynamic_pointer_cast<pointsto_temp_summaryt const>(
          obj_summary.second
          );
  if (!summary.operator bool())
    return "ERROR: cannot cast the passed summary to 'pointsto_temp_summaryt'"
           " summary.";

  ostr << "<h2>Pointsto temp summary</h2>\n"
       << "<p>Mapping of input to symbolic sets of targets:</p>\n"
       ;
  pointsto_dump_rules_in_html(summary->get_input(),ostr);

  ostr << "<p>The summary (TODO: prune out local variables!!!):</p>\n";
  pointsto_dump_rules_in_html(summary->get_output(),ostr);

  if (summary->get_domain().operator bool())
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
      namespacet const  ns(program.symbol_table);
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
        auto const  value_it = summary->get_domain()->find(instr_it);
        if (value_it != summary->get_domain()->cend())
        {
          ostr << "  <td>\n";
          pointsto_dump_rules_in_html(value_it->second,ostr,"    ");
          ostr << "  </td>\n";
        }
        else
          ostr << "ERROR: the value is missing!";

        ostr << "  </tr>\n";
      }
      ostr << "</table>\n";
    }
  }

  return ""; // No error.
}
