#include <goto-analyzer/pointsto_temp_analyser.h>
#include <goto-programs/goto_functions.h>

pointsto_temp_summaryt::pointsto_temp_summaryt(
    const pointsto_rulest&  input_,
    const pointsto_rulest&  output_,
    const pointsto_temp_domain_ptrt  domain_
    )
  : input(input_)
  , output(output_)
  , domain(domain_)
{}

std::string  pointsto_temp_summaryt::kind() const noexcept
{
  return "cbmc://src/analyses/pointsto_temp_analyser";
}

std::string  pointsto_temp_summaryt::description() const noexcept
{
  return "Temporary summary-based points-to analysis. Its goal is to provide\n"
         "an impression, how to use points-to summary domain specification\n"
         "provided in files src/analyses/pointsto_summary_domain.h(cpp)."
         ;
}


void  pointsto_temp_summarise_all_functions(
    goto_modelt const&  program,
    database_of_summariest&  summaries_to_compute,
    call_grapht const&  call_graph,
    std::ostream* const  log
    )
{
}


pointsto_temp_summary_ptrt  pointsto_temp_summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    database_of_summariest const&  database,
    std::ostream* const  log
    )
{
  // TODO!
  return pointsto_temp_summary_ptrt();
}
