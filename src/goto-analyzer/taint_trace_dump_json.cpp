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
#include <util/json.h>
#include <fstream>


void taint_dump_traces_in_json(
    std::vector<taint_tracet> const&  traces,
    goto_modelt const&  goto_model,
    std::string const&  dump_root_directory
    )
{
  fileutl_create_directory(dump_root_directory);
  for (std::size_t  i = 0UL; i != traces.size(); ++i)
    taint_trace_dump_in_json(
          traces.at(i),
          goto_model,
          msgstream() << dump_root_directory << "/trace_" << i << ".json"
          );
}

void taint_trace_dump_in_json(
    taint_tracet const&  trace,
    goto_modelt const&  goto_model,
    std::string const&  dump_file_name
    )
{
  json_arrayt  records;
  {
    namespacet ns(goto_model.symbol_table);
    for (taint_trace_elementt const&  elem : trace)
      for (auto const lvalue_svalue : elem.get_map_from_lvalues_to_svalues())
      {
        json_objectt  record;
        {
          record["mode"] = json_stringt("java");
          record["thread"] = json_numbert(msgstream() << 0);
          record["hidden"] = json_falset();
          record["stepType"] = json_stringt("assignment");
          record["assignmentType"] = json_stringt("variable");
          record["location"] = json_numbert(
                msgstream() << elem.get_instruction_iterator()->location_number
                );
          record["lhs"] =
              json_stringt(from_expr(ns, "",lvalue_svalue.first));
          json_objectt  location;
          {
            location["dir"] = json_stringt("./");
            location["file"] = json_stringt(elem.get_file());
            location["line"] = json_stringt(msgstream() << elem.get_line());
            location["function"] = json_stringt(elem.get_name_of_function());
          }
          record["sourceLocation"] = location;
          json_objectt  value;
          {
            value["name"] = json_stringt("pointer");
            msgstream  data;
            {
              bool first = true;
              for (auto const&  symbol : lvalue_svalue.second.expression())
              {
                 data << (first ? "" : ", ") << symbol;
                 first = false;
              }
            }
            value["data"] = json_stringt(data);
          }
          record["value"] = value;
        }
        records.push_back(record);
      }
  }
  std::ofstream  ostr(dump_file_name);
  ostr << records;
}
