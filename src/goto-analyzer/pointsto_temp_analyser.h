#ifndef CPROVER_POINTS_TO_TEMP_ANALYSER_H
#define CPROVER_POINTS_TO_TEMP_ANALYSER_H

#include <analyses/pointsto_summary_domain.h>
#include <summaries/summary.h>
#include <summaries/utility.h>
#include <goto-programs/goto_model.h>
#include <analyses/call_graph.h>
#include <memory>


typedef goto_programt::instructiont::const_targett
        instruction_iteratort;

typedef std::unordered_map<instruction_iteratort,
                           pointsto_rulest,
                           instruction_iterator_hashert>
        pointsto_temp_domaint;

typedef std::shared_ptr<pointsto_temp_domaint>
        pointsto_temp_domain_ptrt;


class pointsto_temp_summaryt : public summaryt
{
public:

  pointsto_temp_summaryt(
      const pointsto_rulest&  input_,
      const pointsto_rulest&  output_,
      const pointsto_temp_domain_ptrt  domain_
      );

  std::string  kind() const noexcept;
  std::string  description() const noexcept;

  const pointsto_rulest& get_input() const noexcept { return input; }
  const pointsto_rulest& get_output() const noexcept { return output; }
  pointsto_temp_domain_ptrt get_domain() const noexcept { return domain; }
  void  drop_domain() { domain.reset(); }

private:
  pointsto_rulest  input;
  pointsto_rulest  output;
  pointsto_temp_domain_ptrt  domain;
};


typedef std::shared_ptr<pointsto_temp_summaryt const>
        pointsto_temp_summary_ptrt;


void  pointsto_temp_summarise_all_functions(
    goto_modelt const&  program,
    database_of_summariest&  summaries_to_compute,
    call_grapht const&  call_graph,
    std::ostream* const  log = nullptr
    );


pointsto_temp_summary_ptrt  pointsto_temp_summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  program,
    database_of_summariest const&  database,
    std::ostream* const  log = nullptr
    );


#endif
