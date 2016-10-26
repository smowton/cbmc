/*******************************************************************\

Module: taint_plannert

Author: Marek Trtik

Date: Octomber 2016

This module defines an analysis which is responsible to plan work of
analyses taint_analysis and taint_summary. Namely, it specifies what
functions will be processed by what analysis, what functions have
a-priori know summaries (like sources of tainted data), and what variables
are important for analyses (i.e. defining a precision level for
the underlying analyses).

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_PLANNER_H
#define CPROVER_TAINT_PLANNER_H

#include <summaries/summary.h>
#include <goto-analyzer/taint_summary.h>
#include <goto-programs/goto_model.h>
#include <analyses/call_graph.h>
#include <util/json.h>
#include <util/irep.h>
#include <util/message.h>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <string>
#include <iosfwd>


/*******************************************************************\

   Class: taint_plan_for_analysist

 Purpose:

\*******************************************************************/
class  taint_plan_for_analysist
{
public:

  explicit taint_plan_for_analysist(
      const std::vector<irep_idt>& _functions_to_analyse
      );

  const std::vector<irep_idt>&  get_functions_to_analyse() const noexcept
  { return functions_to_analyse; }


private:
  std::vector<irep_idt> functions_to_analyse;
};

typedef std::shared_ptr<taint_plan_for_analysist> taint_plan_for_analysis_ptrt;


/*******************************************************************\

   Class: taint_plan_for_summariest

 Purpose:

\*******************************************************************/
class  taint_plan_for_summariest
{
public:

  typedef std::vector<dstring>  access_pathst;
  typedef std::vector<access_pathst>  access_paths_of_functionst;

  taint_plan_for_summariest(
      const std::vector<irep_idt>& _functions_to_analyse,
      const access_paths_of_functionst& _access_paths_of_functions
      );

  const std::vector<irep_idt>&  get_functions_to_analyse() const noexcept
  { return functions_to_analyse; }

  const access_paths_of_functionst&
  get_access_paths_of_functions() const noexcept
  { return access_paths_of_functions; }


private:
  std::vector<irep_idt> functions_to_analyse;
  access_paths_of_functionst access_paths_of_functions;
};

typedef std::shared_ptr<taint_plan_for_summariest>
        taint_plan_for_summaries_ptrt;


/*******************************************************************\

   Class: taint_precision_level_datat

 Purpose:

\*******************************************************************/
class  taint_precision_level_datat
{
public:

  taint_precision_level_datat(
      const taint_plan_for_analysis_ptrt _plan_for_analysis,
      const taint_plan_for_summaries_ptrt _plan_for_summaries,
      const database_of_summaries_ptrt _summary_database
      );

  taint_plan_for_analysis_ptrt get_plan_for_analysis() const noexcept
  { return plan_for_analysis; }

  taint_plan_for_summaries_ptrt get_plan_for_summaries() const noexcept
  { return plan_for_summaries; }

  database_of_summaries_ptrt get_summary_database() const noexcept
  { return summary_database; }

  bool get_is_computed() const noexcept { return is_computed; }
  void set_is_computed() { is_computed = true; }

private:
  taint_plan_for_analysis_ptrt plan_for_analysis;
  taint_plan_for_summaries_ptrt plan_for_summaries;
  database_of_summaries_ptrt summary_database;
  bool is_computed;
};

typedef std::shared_ptr<taint_precision_level_datat>
        taint_precision_level_data_ptrt;


/*******************************************************************\

   Class: taint_plannert

 Purpose:

\*******************************************************************/
class  taint_plannert : public messaget
{
public:
  typedef std::vector<taint_precision_level_data_ptrt>
          precision_levelst;

  typedef std::unordered_map<irep_idt,taint_summary_ptrt,dstring_hash>
          sources_mapt;
  typedef std::unordered_map<irep_idt,
                             taint_map_from_lvalues_to_svaluest,
                             dstring_hash>
          sinks_mapt;
  typedef std::vector<taint_svaluet::taint_symbolt>
          taint_symbolst;

  taint_plannert(goto_modelt const&  program,
                 jsont const&  plan,
                 message_handlert& mh);

  taint_precision_level_data_ptrt  get_top_precision_level() const
  { return computed_levels.back(); }

  const precision_levelst&  get_precision_levels() const noexcept
  { return computed_levels; }

  const taint_symbolst& get_taint_symbols() const noexcept
  { return taint_symbols; }

  const sources_mapt& get_sources() const noexcept { return sources; }
  const sinks_mapt& get_sinks() const noexcept { return sinks; }

  std::string  solve_top_precision_level(
      goto_modelt&  program,
      call_grapht const&  call_graph,
      std::ostream* const  log = nullptr
      );

  static std::string get_unique_entry_point(jsont const& plan);
  
private:

  std::string  compute_summaries(
      const taint_plan_for_summaries_ptrt plan_for_summaries,
      const database_of_summaries_ptrt summary_database,
      goto_modelt const&  program,
      call_grapht const&  call_graph,
      std::ostream* const  log
      );

  std::string  run_taint_analysis(
      const taint_plan_for_analysis_ptrt plan_for_analysis,
      const database_of_summaries_ptrt summary_database,
      goto_modelt&  program,
      std::ostream* const  log
      );

  std::string  build_next_precision_level(
      goto_modelt const&  program,
      call_grapht const&  call_graph,
      std::ostream* const  log
      );

  precision_levelst  computed_levels;
  taint_symbolst taint_symbols;
  sources_mapt sources;
  sinks_mapt sinks;
};


#endif
