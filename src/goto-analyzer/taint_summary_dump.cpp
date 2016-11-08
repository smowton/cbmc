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
    taint_svalue_symbols_to_specification_symbols_mapt const&
        taint_spec_names,
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
       ostr << (first ? "" : " <b>&#x2210;</b> ");
       auto const  name_it = taint_spec_names.find(symbol);
       if (name_it != taint_spec_names.cend())
         ostr << name_it->second;
       else
        ostr << "T" << symbol;
       first = false;
    }
    if (!svalue.suppression().empty())
      ostr << " <b>\\</b> ";
    first = true;
    for (auto const&  symbol : svalue.suppression())
    {
       ostr << (first ? "" : " <b>&#x2210;</b> ");
       auto const  name_it = taint_spec_names.find(symbol);
       if (name_it != taint_spec_names.cend())
         ostr << name_it->second;
       else
         ostr << "T" << symbol;
       first = false;
    }
  }
}

void  taint_dump_lvalues_to_svalues_in_html(
    taint_map_from_lvalues_to_svaluest const&  lvalues_to_svalues,
    namespacet const&  ns,
    taint_svalue_symbols_to_specification_symbols_mapt const&
        taint_spec_names,
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
      taint_dump_svalue_in_html(lvalues_to_svalues.at(elem.second),
                                taint_spec_names,ostr);
      ostr << "</td>\n";
      ostr << "      </tr>\n";
    }
    ostr << "    </table>\n";
  }
}

void  taint_dump_numbered_lvalues_to_svalues_as_html(
    taint_numbered_lvalue_svalue_mapt const&  lvalues_to_svalues,
    namespacet const&  ns,
    const object_numberingt& numbering,
    taint_svalue_symbols_to_specification_symbols_mapt const&
        taint_spec_names,
    std::ostream&  ostr
    )
{
  if (lvalues_to_svalues.empty())
    ostr << "BOTTOM";
  else
  {
    std::map<std::string,unsigned> order;
    for (auto const&  elem : lvalues_to_svalues)
    {
      std::stringstream sstr;
      const auto& lvalue=numbering[elem.first];
      taint_dump_lvalue_in_html(lvalue,ns,sstr);
      order.insert({sstr.str(),elem.first});
    }
    ostr << "    <table>\n";
    for (auto const&  elem : order)
    {
      ostr << "      <tr>\n";
      ostr << "        <td>" << elem.first << "</td>\n";
      ostr << "        <td>";
      taint_dump_svalue_in_html(lvalues_to_svalues.at(elem.second),
                                taint_spec_names,ostr);
      ostr << "</td>\n";
      ostr << "      </tr>\n";
    }
    ostr << "    </table>\n";
  }
}

void  taint_dump_numbered_lvalues_to_svalues_changes_as_html(
    taint_numbered_lvalue_svalue_mapt const&  lvalues_to_svalues,
    taint_numbered_lvalue_svalue_mapt const&  old_lvalues_to_svalues,    
    namespacet const&  ns,
    const object_numberingt& numbering,
    taint_svalue_symbols_to_specification_symbols_mapt const&
        taint_spec_names,
    std::ostream&  ostr
    )
{
  auto newit=lvalues_to_svalues.begin(), newitend=lvalues_to_svalues.end();
  auto oldit=old_lvalues_to_svalues.begin(), olditend=old_lvalues_to_svalues.end();

  std::map<std::string,unsigned> order;
  while(newit!=newitend || oldit!=olditend)
  {
    unsigned num=(unsigned)-1;
    if(newit!=newitend && oldit!=olditend && newit->first==oldit->first)
    {
      if(newit->second!=oldit->second)
	num=newit->first;
      ++newit; ++oldit;
    }
    else if(oldit==olditend || (newit!=newitend && newit->first<oldit->first))
    {
      num=newit->first;
      ++newit;
    }
    else
    {
      num=oldit->first;
      ++oldit;
    }
    if(num!=((unsigned)-1))
    {
      std::stringstream sstr;
      const auto& lvalue=numbering[num];
      taint_dump_lvalue_in_html(lvalue,ns,sstr);
      order.insert({sstr.str(),num});
    }
  }

  ostr << "    <table>\n";
  for (auto const&  elem : order)
  {
    ostr << "      <tr>\n";
    ostr << "        <td>" << elem.first << "</td>\n";
    ostr << "        <td>";
    auto findit=lvalues_to_svalues.find(elem.second);
    if(findit!=lvalues_to_svalues.end())
      taint_dump_svalue_in_html(findit->second,taint_spec_names,ostr);
    ostr << "</td>\n";
    ostr << "      </tr>\n";
  }
  ostr << "    </table>\n";
}

std::string  taint_dump_in_html(
    object_summaryt const  obj_summary,
    goto_modelt const&  program,
    taint_svalue_symbols_to_specification_symbols_mapt const&
        taint_spec_names,
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
      taint_dump_svalue_in_html(summary->input().at(elem.second),
                                taint_spec_names,ostr);
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
      taint_dump_svalue_in_html(summary->output().at(elem.second),
                                taint_spec_names,ostr);
      ostr <<"</td>\n";
      ostr << "  </tr>\n";
    }
  }
  ostr << "</table>\n";

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
      auto const  vars_to_values_it = summary->domain().find(instr_it);
      if (vars_to_values_it != summary->domain().cend())
      {
	ostr << "  <td>\n";
        if (false) // use full states dump?
        {
          taint_dump_numbered_lvalues_to_svalues_as_html(
                        vars_to_values_it->second,
                        ns,
                        summary->domain_numbering(),
                        taint_spec_names,
                        ostr
                        );
        }
        else
        {
          // Don't print anything for the first instruction:
          if(instr_it==fn_body.instructions.cbegin())
            continue;
          // For other instructions, print changes since the last domain snapshot:
          auto previt=instr_it;
          do {
            --previt;
            auto const prevfindit=summary->domain().find(previt);
            if(prevfindit!=summary->domain().cend())
            {
              taint_dump_numbered_lvalues_to_svalues_changes_as_html(
                vars_to_values_it->second,
                prevfindit->second,
                ns,
                summary->domain_numbering(),
                taint_spec_names,
                ostr);
              break;
            }
          } while(previt!=fn_body.instructions.cbegin());
        }
	ostr << "  </td>\n";
      }

      ostr << "  </tr>\n";
    }
    ostr << "</table>\n";
  }

  return ""; // no error.
}
