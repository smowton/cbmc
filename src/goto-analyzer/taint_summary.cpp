/////////////////////////////////////////////////////////////////////////////
//
// Module: taint_summary
// Author: Marek Trtik
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////


#include <goto-analyzer/taint_summary.h>
#include <util/msgstream.h>

namespace sumfn { namespace taint {


std::string  summary_t::kind() const
{
  return "sumfn::taint::summarise_function";
}

std::string  summary_t::description() const noexcept
{
  return "Function summary of taint analysis of java web applications.";
}



void  summarise_all_functions(
    goto_modelt const&  instrumented_program,
    database_of_summaries_t&  summaries_to_compute
    )
{
//  symbol_tablet::symbolst const&  symbols =
//      goto_model.symbol_table.symbols;

  goto_functionst::function_mapt const&  functions =
      instrumented_program.goto_functions.function_map;
  for (auto const&  elem : functions)
    summaries_to_compute.insert({
        "aa",//elem.first,
        summarise_function(elem.first,functions)
        });
}

summary_ptr_t  summarise_function(
    irep_idt const&  function_id,
    goto_functionst::function_mapt const&  functions
    )
{
  return std::make_shared<summary_t>();
}


}}
