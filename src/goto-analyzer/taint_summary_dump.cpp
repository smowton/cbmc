/*******************************************************************\

Module: taint_summary_dump

Author: Marek Trtik

Date: September 2016

It provides a dump of computed taint summary in HTML format.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_summary_dump.h>
#include <util/msgstream.h>
#include <memory>
#include <map>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cassert>

void  taint_dump_lvalue_in_html(
    taint_lvaluet const&  lvalue,
    namespacet const&  ns,
    std::ostream&  ostr
    )
{
  dump_access_path_in_html(lvalue,ns,ostr);
}

void  taint_dump_svalue_in_html(
    taint_svaluet const&  svalue,
    std::ostream&  ostr
    )
{
  if (svalue.is_top())
    ostr << "TOP";
  else if (svalue.is_bottom())
    ostr << "BOTTOM";
  else
  {
    bool first = true;
    for (auto const&  symbol : svalue.expression())
    {
       ostr << (first ? "" : " <b>&#x2210;</b> ") << symbol;
       first = false;
    }
    if (!svalue.suppression().empty())
      ostr << " <b>\\</b> ";
    first = true;
    for (auto const&  symbol : svalue.suppression())
    {
       ostr << (first ? "" : " <b>&#x2210;</b> ") << symbol;
       first = false;
    }
  }
}

void  taint_dump_lvalues_to_svalues_in_html(
    taint_map_from_lvalues_to_svaluest const&  lvalues_to_svalues,
    namespacet const&  ns,
    std::ostream&  ostr
    )
{
  if (lvalues_to_svalues.empty())
    ostr << "BOTTOM";
  else
  {
    std::map<std::string,taint_lvaluet> order;
    for (auto const&  elem : lvalues_to_svalues)
    {
      std::stringstream sstr;
      taint_dump_lvalue_in_html(elem.first,ns,sstr);
      order.insert({sstr.str(),elem.first});
    }
    ostr << "    <table>\n";
    for (auto const&  elem : order)
    {
      ostr << "      <tr>\n";
      ostr << "        <td>" << elem.first << "</td>\n";
      ostr << "        <td>";
      taint_dump_svalue_in_html(lvalues_to_svalues.at(elem.second),ostr);
      ostr << "</td>\n";
      ostr << "      </tr>\n";
    }
    ostr << "    </table>\n";
  }
}


std::string  taint_dump_in_html(
    object_summaryt const  obj_summary,
    goto_modelt const&  program,
    std::ostream&  ostr
    )
{
  namespacet const  ns(program.symbol_table);
  summarised_object_idt const&  function_id = obj_summary.first;
  taint_summary_ptrt const  summary =
      std::dynamic_pointer_cast<taint_summaryt const>(obj_summary.second);
  if (!summary.operator bool())
    return "ERROR: cannot cast the passed summary to 'taint' summary.";

  ostr << "<h2>Taint summary</h2>\n"
       << "<p>Mapping of input to symbols:</p>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>L-value</th>\n"
          "    <th>Symbol</th>\n"
          "  </tr>\n"
       ;
  {
    std::map<std::string,taint_lvaluet> order;
    for (auto const&  elem : summary->input())
    {
      std::stringstream sstr;
      taint_dump_lvalue_in_html(elem.first,ns,sstr);
      order.insert({sstr.str(),elem.first});
    }
    for (auto const&  elem : order)
    {
      ostr << "  <tr>\n";
      ostr << "        <td>" << elem.first << "</td>\n";
      ostr << "    <td>";
      taint_dump_svalue_in_html(summary->input().at(elem.second),ostr);
      ostr <<"</td>\n";
      ostr << "  </tr>\n";
    }
  }
  ostr << "</table>\n";
  ostr << "<p>The summary:</p>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>L-value</th>\n"
          "    <th>Expression</th>\n"
          "  </tr>\n"
       ;
  {
    std::map<std::string,taint_lvaluet> order;
    for (auto const&  elem : summary->output())
    {
      std::stringstream sstr;
      taint_dump_lvalue_in_html(elem.first,ns,sstr);
      order.insert({sstr.str(),elem.first});
    }
    for (auto const&  elem : order)
    {
      ostr << "  <tr>\n";
      ostr << "        <td>" << elem.first << "</td>\n";
      ostr << "    <td>";
      taint_dump_svalue_in_html(summary->output().at(elem.second),ostr);
      ostr <<"</td>\n";
      ostr << "  </tr>\n";
    }
  }
  ostr << "</table>\n";

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
        auto const  vars_to_values_it = summary->domain()->find(instr_it);
        if (vars_to_values_it != summary->domain()->cend())
        {
          ostr << "  <td>\n";
          taint_dump_lvalues_to_svalues_in_html(
                vars_to_values_it->second,
                ns,
                ostr
                );
          ostr << "  </td>\n";
        }

        ostr << "  </tr>\n";
      }
      ostr << "</table>\n";
    }
  }

  return ""; // no error.
}
