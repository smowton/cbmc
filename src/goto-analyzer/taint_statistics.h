/*******************************************************************\

Module: taint_statistics

Author: Marek Trtik

Date: November 2016

This module defines interfaces and functionality for collection and
holding statistical information about all phases of taint analysis.
It captures informations from program parsing up to dumping of error
traces (if any).

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_STATISTICS_H
#define CPROVER_TAINT_STATISTICS_H

#include <goto-programs/goto_model.h>
#include <goto-analyzer/taint_trace_recogniser.h>
#include <map>
#include <set>
#include <unordered_map>
#include <tuple>
#include <string>
#include <chrono>


typedef  std::chrono::high_resolution_clock::time_point
         taint_statisitcs_time_pointt;

typedef  std::chrono::duration<double>::rep
         taint_statisitcs_durationt;


/*******************************************************************\

   Class: taint_function_statisticst

 Purpose:

\*******************************************************************/
class taint_function_statisticst
{
public:
  typedef  taint_statisitcs_time_pointt  time_pointt;
  typedef  taint_statisitcs_durationt  durationt;

  explicit taint_function_statisticst(std::size_t const  num_locations_);

  ///////////////////////////////////////////////////////////////////
  /// Notifications
  ///////////////////////////////////////////////////////////////////

  void  begin_lvsa_analysis();
  void  end_lvsa_analysis(
      std::size_t const  num_fixpoint_steps_,
      std::size_t const  num_uses_of_callee_summaries_,
      std::size_t const  num_of_processed_rules_callee_summaries_
      );

  void  begin_taint_summaries();
  void  end_taint_summaries(
      taint_map_from_lvalues_to_svaluest const&  input,
      taint_map_from_lvalues_to_svaluest const&  output,
      taint_summary_domain_ptrt const  domain
      );
  void  on_fixpoint_step_of_taint_summaries();
  void  on_taint_analysis_use_callee_summary(
      taint_summary_ptrt const  summary
      );
  void  on_taint_analysis_use_my_summary();

  void  on_set_may(unsigned int const  location);
  void  on_clear_may(unsigned int const  location);
  void  on_get_may(unsigned int const  location);

  ///////////////////////////////////////////////////////////////////
  /// Queries
  ///////////////////////////////////////////////////////////////////

  std::size_t  get_num_locations() const noexcept { return num_locations; }

  std::set<unsigned int> const&  get_locations_of_taint_sources() const noexcept
  { return sources; }

  std::set<unsigned int> const&  get_locations_of_taint_sinks() const noexcept
  { return sinks; }

  std::set<unsigned int> const&
      get_locations_of_taint_sanitisers() const noexcept { return sanitisers; }

  durationt  get_duration_of_lvsa_analysis() const;
  durationt  get_duration_of_taint_summaries() const;

  durationt  get_duration_of_both_analyses() const;

  std::size_t  get_num_fixpoint_steps_of_lvsa_analysis() const;
  std::size_t  get_num_fixpoint_steps_of_taint_summaries() const;

  std::size_t  get_num_fixpoint_steps_of_both_analyses() const;

  std::size_t  get_num_lvsa_uses_of_callee_summaries() const noexcept
  { return num_lvsa_uses_of_callee_summaries; }
  std::size_t  get_num_lvsa_of_processed_rules_callee_summaries() const noexcept
  { return num_lvsa_of_processed_rules_callee_summaries; }

  std::size_t  get_summary_input_size() const noexcept
  { return summary_input_size; }
  std::size_t  get_summary_output_size() const noexcept
  { return summary_output_size; }
  std::size_t  get_summary_domain_size() const noexcept
  { return summary_domain_size; }

  std::size_t  get_num_usages_of_my_summary() const noexcept
  { return num_usages_of_my_summary; }

  std::size_t  get_num_usages_of_callee_summaries() const noexcept
  { return num_usages_of_callee_summaries; }
  std::size_t  get_num_rules_in_used_callee_summaries() const noexcept
  { return num_rules_in_used_callee_summaries; }

private:
  std::size_t  num_locations;

  std::set<unsigned int>  sources;
  std::set<unsigned int>  sinks;
  std::set<unsigned int>  sanitisers;

  time_pointt  time_point_begin_lvsa_analysis;
  time_pointt  time_point_end_lvsa_analysis;
  std::size_t  num_fixpoint_steps_of_lvsa_analysis;

  std::size_t  num_lvsa_uses_of_callee_summaries;
  std::size_t  num_lvsa_of_processed_rules_callee_summaries;

  time_pointt  time_point_begin_taint_summaries;
  time_pointt  time_point_end_taint_summaries;
  std::size_t  num_fixpoint_steps_of_taint_summaries;

  std::size_t  summary_input_size;
  std::size_t  summary_output_size;
  std::size_t  summary_domain_size;

  std::size_t  num_usages_of_my_summary;

  std::size_t  num_usages_of_callee_summaries;
  std::size_t  num_rules_in_used_callee_summaries;
};


typedef  std::map<std::string,taint_function_statisticst>
         taint_statistics_of_functionst;


/*******************************************************************\

   Class: taint_statisticst

 Purpose:

\*******************************************************************/
class taint_statisticst
{
public:
  typedef  taint_statisitcs_time_pointt  time_pointt;
  typedef  taint_statisitcs_durationt  durationt;

  typedef  std::map<std::string,std::set<std::string> >
           from_files_to_functions_mapt;

  typedef  std::unordered_map<std::string,std::string>
           from_functions_to_files_mapt;

//  typedef  std::pair<std::string,   //!< Function name
//                     unsigned int   //!< Location number
//                     >
//           program_locationt;

  static taint_statisticst&  instance();

  ///////////////////////////////////////////////////////////////////
  /// Notifications
  ///////////////////////////////////////////////////////////////////

  void  begin_goto_program_building();
  void  end_goto_program_building();

  void  begin_taint_info_instrumentation();
  void  end_taint_info_instrumentation(
      goto_modelt const&  model,
      taint_sinks_mapt  taint_sinks
      );

  void  begin_loading_lvsa_database();
  void  end_loading_lvsa_database();

  void  begin_loading_taint_summaries_database();
  void  end_loading_taint_summaries_database();

  void  begin_callgraph_building();
  void  end_callgraph_building();

  void  begin_lvsa_analysis_of_function(std::string const&  fn_name);
  void  end_lvsa_analysis_of_function(
      std::size_t const  num_fixpoint_steps,
      std::size_t const  num_uses_of_callee_summaries,
      std::size_t const  num_of_processed_rules_callee_summaries
      );

  void  begin_taint_analysis_of_function(std::string const&  fn_name);
  void  end_taint_analysis_of_function(
      taint_map_from_lvalues_to_svaluest const&  input,
      taint_map_from_lvalues_to_svaluest const&  output,
      taint_summary_domain_ptrt const  domain
      );
  void  on_fixpoint_step_of_taint_analysis();
  void  on_taint_analysis_use_callee_summary(
      taint_summary_ptrt const  summary,
      std::string const  callee_name
      );

  void  begin_error_traces_recognition();
  void  end_error_traces_recognition();

  void  begin_dump_of_taint_html_summaries();
  void  end_dump_of_taint_html_summaries();

  void  begin_dump_of_taint_json_summaries();
  void  end_dump_of_taint_json_summaries();

  void  begin_dump_of_taint_html_traces();
  void  end_dump_of_taint_html_traces();

  void  begin_dump_of_taint_json_traces();
  void  end_dump_of_taint_json_traces();

  ///////////////////////////////////////////////////////////////////
  /// Queries
  ///////////////////////////////////////////////////////////////////

  durationt  get_duration_of_program_building() const;
  durationt  get_duration_of_program_instrumentation() const;
  durationt  get_duration_of_program_info_collecting() const;
  durationt  get_duration_of_loading_lvsa_database() const;
  durationt  get_duration_of_loading_taint_database() const;
  durationt  get_duration_of_callgraph_building() const;
  durationt  get_duration_of_error_traces_recognition() const;
  durationt  get_duration_of_dump_of_taint_html_summaries() const;
  durationt  get_duration_of_dump_of_taint_json_summaries() const;
  durationt  get_duration_of_dump_of_taint_html_traces() const;
  durationt  get_duration_of_dump_of_taint_json_traces() const;

  durationt  get_duration_of_all_phases_together() const;

  from_files_to_functions_mapt const&
      get_map_from_files_to_functions() const  noexcept
  { return from_files_to_functions; }

  from_functions_to_files_mapt const&
      get_map_from_functions_to_files() const  noexcept
  { return from_functions_to_files; }

  taint_statistics_of_functionst const&
      get_statistics_of_functions() const  noexcept
  { return statistics_of_functions; }

private:
  taint_statisticst() = default;

  taint_statisticst(taint_statisticst const&) = delete;
  taint_statisticst& operator=(taint_statisticst const&) = delete;
  taint_statisticst(taint_statisticst&&) = delete;
  taint_statisticst& operator=(taint_statisticst&&) = delete;

  time_pointt  time_point_begin_program_build;
  time_pointt  time_point_end_program_build;

  time_pointt  time_point_begin_program_instrumentation;
  time_pointt  time_point_end_program_instrumentation;

  time_pointt  time_point_begin_program_info_collecting;
  time_pointt  time_point_end_program_info_collecting;

  time_pointt  time_point_begin_load_lvsa_database;
  time_pointt  time_point_end_load_lvsa_database;

  time_pointt  time_point_begin_load_taint_database;
  time_pointt  time_point_end_load_taint_database;

  time_pointt  time_point_begin_callgraph_build;
  time_pointt  time_point_end_callgraph_build;

  time_pointt  time_point_begin_error_traces_recognition;
  time_pointt  time_point_end_error_traces_recognition;

  time_pointt  time_point_begin_dump_taint_html_summaries;
  time_pointt  time_point_end_dump_taint_html_summaries;

  time_pointt  time_point_begin_dump_taint_json_summaries;
  time_pointt  time_point_end_dump_taint_json_summaries;

  time_pointt  time_point_begin_dump_taint_html_traces;
  time_pointt  time_point_end_dump_taint_html_traces;

  time_pointt  time_point_begin_dump_taint_json_traces;
  time_pointt  time_point_end_dump_taint_json_traces;

  from_files_to_functions_mapt  from_files_to_functions;
  from_functions_to_files_mapt  from_functions_to_files;

  taint_statistics_of_functionst  statistics_of_functions;
  std::string  current_function_name;
};


#endif
