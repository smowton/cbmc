#include <goto-analyzer/pointsto_temp_summary_dump.h>
#include <goto-analyzer/pointsto_temp_analyser.h>
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

  return ""; // No error.
}
