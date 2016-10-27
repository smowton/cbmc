/*******************************************************************\

Module: taint_trace_dump

Author: Marek Trtik

Date: Octomber 2016



@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_trace_dump.h>
#include <goto-analyzer/taint_summary_dump.h>
#include <summaries/summary_dump.h>
#include <util/file_util.h>
#include <util/msgstream.h>
#include <fstream>


void taint_dump_traces_in_html(
    std::vector<taint_tracet> const&  traces,
    goto_modelt const&  goto_model,
    std::string const&  dump_root_directory
    )
{
  fileutl_create_directory(dump_root_directory);
  std::ofstream  ostr(msgstream() << dump_root_directory << "/index.html");
  dump_html_prefix(ostr,"Traces");
  ostr << "<h1>Error traces from the taint analysis</h1>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>Source function</th>\n"
          "    <th>Source location</th>\n"
          "    <th>Sink function</th>\n"
          "    <th>Sink location</th>\n"
          "    <th>Length</th>\n"
          "    <th>Trace</th>\n"
          "  </tr>\n"
          ;
  for (std::size_t  i = 0UL; i != traces.size(); ++i)
  {
    taint_trace_dump_in_html(
          traces.at(i),
          goto_model,
          msgstream() << dump_root_directory << "/trace_" << i
          );
    ostr << "  <tr>\n"
            "    <td>" << traces.at(i).front().get_name_of_function()
         << "</td>\n"
            "    <td>" << traces.at(i).front().get_instruction_iterator()
                                              ->location_number
         << "</td>\n"
            "    <td>" << traces.at(i).back().get_name_of_function()
         << "</td>\n"
            "    <td>" << traces.at(i).back().get_instruction_iterator()
                                             ->location_number
         << "</td>\n"
            "    <td>" << traces.at(i).size() << "</td>\n"
            "    <td><a href=\"./trace_" << i << "/index.html\">here</a></td>\n"
            "  </tr>\n"
            ;
  }
  ostr << "</table>\n";
  dump_html_suffix(ostr);
}

void taint_trace_dump_in_html(
    taint_tracet const&  trace,
    goto_modelt const&  goto_model,
    std::string const&  dump_root_directory
    )
{
  fileutl_create_directory(dump_root_directory);
  std::ofstream  ostr(msgstream() << dump_root_directory << "/index.html");
  dump_html_prefix(ostr,"Trace");
  ostr << "<h2>Error trace</h1>\n"
          "<table>"
          "  <tr>\n"
          "    <th>#</th>\n"
          "    <th>Function</th>\n"
          "    <th>Location</th>\n"
          "    <th>Variables</th>\n"
          "    <th>Symbols</th>\n"
          "    <th>Message</th>\n"
          "    <th>Line</th>\n"
          "    <th>File</th>\n"
          "    <th>Comment</th>\n"
          "  </tr>\n"
          ;
  std::size_t  elem_index = 0UL;
  namespacet const  ns(goto_model.symbol_table);
  for (taint_trace_elementt const&  element : trace)
  {
      ostr << "  <tr>\n"
              "    <td>" << ++elem_index << "</td>\n"
              "    <td>"
           << to_html_text(element.get_name_of_function()) << "</td>\n"
              "    <td>"
           << element.get_instruction_iterator()->location_number
           << "</td>\n"
              ;
      ostr << "    <td>\n";
      taint_dump_lvalues_to_svalues_in_html(
            element.get_map_from_lvalues_to_svalues(),
            ns,
            ostr
            );
      ostr << "    </td>\n"
              "    <td>\n";
      taint_dump_svalue_in_html(
          {element.get_symbols(),false,false},
          ostr
          );
      ostr << "    </td>\n"
              "    <td>" << to_html_text(element.get_message())
           << "</td>\n"
              "    <td>"
              ;
      if (element.get_line() != 0UL)
        ostr << element.get_line();
      else
        ostr << "N/A";
      ostr << "</td>\n"
              "    <td>";
      if (!element.get_file().empty())
        ostr << to_html_text(element.get_file());
      else
        ostr << "N/A";
      ostr << "</td>\n"
              "    <td>" << to_html_text(element.get_code_annotation())
           << "</td>\n"
              "  </tr>\n";
  }
  ostr << "</table>";
  dump_html_suffix(ostr);
}
