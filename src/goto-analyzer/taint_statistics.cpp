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

#include <goto-analyzer/taint_statistics.h>
#include <cassert>


static inline  taint_statisticst::time_pointt  get_current_time()
{
  return std::chrono::high_resolution_clock::now();
}

static inline  taint_statisticst::durationt  get_duration(
    taint_statisticst::time_pointt const  begin,
    taint_statisticst::time_pointt const  end
    )
{
  return std::chrono::duration<double>(end - begin).count();
}


///////////////////////////////////////////////////////////////////
///
/// IMPLEMENTATION OF taint_function_statisticst
///
///////////////////////////////////////////////////////////////////


taint_function_statisticst::taint_function_statisticst(
        std::size_t const  num_locations_
        )
    : num_locations(num_locations_)

    , sources()
    , sinks()
    , sanitisers()

    , time_point_begin_lvsa_analysis()
    , time_point_end_lvsa_analysis()
    , num_fixpoint_steps_of_lvsa_analysis(0UL)

    , num_lvsa_uses_of_callee_summaries(0UL)
    , num_lvsa_of_processed_rules_callee_summaries(0UL)

    , time_point_begin_taint_summaries()
    , time_point_end_taint_summaries()
    , num_fixpoint_steps_of_taint_summaries(0UL)

    , summary_input_size(0UL)
    , summary_output_size(0UL)
    , summary_domain_size(0UL)

    , num_usages_of_my_summary(0UL)

    , num_usages_of_callee_summaries(0UL)
    , num_rules_in_used_callee_summaries(0UL)
{}

///////////////////////////////////////////////////////////////////
/// Notifications
///////////////////////////////////////////////////////////////////

void  taint_function_statisticst::begin_lvsa_analysis()
{
  time_point_begin_lvsa_analysis = get_current_time();
}

void  taint_function_statisticst::end_lvsa_analysis(
    std::size_t const  num_fixpoint_steps_,
    std::size_t const  num_uses_of_callee_summaries_,
    std::size_t const  num_of_processed_rules_callee_summaries_
    )
{
  time_point_end_lvsa_analysis = get_current_time();

  num_fixpoint_steps_of_lvsa_analysis = num_fixpoint_steps_;
  num_lvsa_uses_of_callee_summaries = num_uses_of_callee_summaries_;
  num_lvsa_of_processed_rules_callee_summaries =
      num_of_processed_rules_callee_summaries_;

}

void  taint_function_statisticst::begin_taint_summaries()
{
  time_point_begin_taint_summaries = get_current_time();
}

void  taint_function_statisticst::end_taint_summaries(
    taint_map_from_lvalues_to_svaluest const&  input,
    taint_map_from_lvalues_to_svaluest const&  output,
    taint_summary_domain_ptrt const  domain
    )
{
  time_point_end_taint_summaries = get_current_time();

  summary_input_size = input.size();
  summary_output_size = output.size();
  for (auto const&  iit_value : *domain)
    summary_domain_size += iit_value.second.size();
}

void  taint_function_statisticst::on_fixpoint_step_of_taint_summaries()
{
  ++num_fixpoint_steps_of_taint_summaries;
}

void  taint_function_statisticst::on_taint_analysis_use_callee_summary(
    taint_summary_ptrt const  summary
    )
{
  ++num_usages_of_callee_summaries;
  num_rules_in_used_callee_summaries += summary->input().size()
                                            + summary->output().size();
}

void  taint_function_statisticst::on_taint_analysis_use_my_summary()
{
  ++num_usages_of_my_summary;
}

void  taint_function_statisticst::on_set_may(unsigned int const  location)
{
  sources.insert(location);
}

void  taint_function_statisticst::on_clear_may(unsigned int const  location)
{
  sanitisers.insert(location);
}

void  taint_function_statisticst::on_get_may(unsigned int const  location)
{
  sinks.insert(location);
}

///////////////////////////////////////////////////////////////////
/// Queries
///////////////////////////////////////////////////////////////////

taint_function_statisticst::durationt
taint_function_statisticst::get_duration_of_lvsa_analysis() const
{
  return get_duration(
            time_point_begin_lvsa_analysis,
            time_point_end_lvsa_analysis
            );
}

taint_function_statisticst::durationt
taint_function_statisticst::get_duration_of_taint_summaries() const
{
  return get_duration(
            time_point_begin_taint_summaries,
            time_point_end_taint_summaries
            );
}

taint_function_statisticst::durationt
taint_function_statisticst::get_duration_of_both_analyses() const
{
  durationt const sum =
        get_duration_of_lvsa_analysis()
      + get_duration_of_taint_summaries()
      ;
  return sum < 0.0001 ? 0.0001 : sum;
}

std::size_t
taint_function_statisticst::get_num_fixpoint_steps_of_lvsa_analysis() const
{
  return num_fixpoint_steps_of_lvsa_analysis;
}

std::size_t
taint_function_statisticst::get_num_fixpoint_steps_of_taint_summaries() const
{
  return num_fixpoint_steps_of_taint_summaries;
}

std::size_t
taint_function_statisticst::get_num_fixpoint_steps_of_both_analyses() const
{
  return
        get_num_fixpoint_steps_of_lvsa_analysis()
      + get_num_fixpoint_steps_of_taint_summaries()
      ;
}



///////////////////////////////////////////////////////////////////
///
/// IMPLEMENTATION OF taint_statisticst
///
///////////////////////////////////////////////////////////////////



taint_statisticst&  taint_statisticst::instance()
{
  static taint_statisticst  stats;
  return stats;
}


///////////////////////////////////////////////////////////////////
/// Notifications
///////////////////////////////////////////////////////////////////


void  taint_statisticst::begin_goto_program_building()
{
  time_point_begin_program_build = get_current_time();
}

void  taint_statisticst::end_goto_program_building()
{
  time_point_end_program_build = get_current_time();
}

void  taint_statisticst::begin_taint_info_instrumentation()
{
  time_point_begin_program_instrumentation = get_current_time();
}

void  taint_statisticst::end_taint_info_instrumentation(
    goto_modelt const&  model,
    taint_sinks_mapt  taint_sinks
    )
{
  time_point_end_program_instrumentation = get_current_time();

  time_point_begin_program_info_collecting = get_current_time();

  for (auto const&  name_fn : model.goto_functions.function_map)
    if (!name_fn.second.body.instructions.empty())
    {
      statistics_of_functions.insert({
            as_string(name_fn.first),
            taint_function_statisticst{name_fn.second.body.instructions.size()}
            });
      bool  has_file_name = false;
      for (goto_programt::instructiont const&  instr :
           name_fn.second.body.instructions)
        if (!instr.source_location.get_file().empty())
        {
          from_files_to_functions[as_string(instr.source_location.get_file())]
              .insert(as_string(name_fn.first));
          from_functions_to_files.insert({
                as_string(name_fn.first),
                as_string(instr.source_location.get_file())
                });
          has_file_name = true;
          break;
        }
      if (has_file_name == false)
      {
        from_files_to_functions[""].insert(as_string(name_fn.first));
        from_functions_to_files.insert({as_string(name_fn.first),""});
      }
    }
  for (auto const&  name_fn : model.goto_functions.function_map)
    if (!name_fn.second.body.instructions.empty())
    {
      taint_function_statisticst& fn_stats =
          statistics_of_functions.at(as_string(name_fn.first));
      for (goto_programt::instructiont const&  I :
           name_fn.second.body.instructions)
        if (I.type == OTHER && I.code.get_statement() == "set_may")
          fn_stats.on_set_may(I.location_number);
        else if (I.type == OTHER &&I.code.get_statement() == "clear_may")
          fn_stats.on_clear_may(I.location_number);
    }

  for (auto const&  taint_map : taint_sinks)
    for (auto const&  fname_sinks : taint_map.second)
    {
      taint_function_statisticst& fn_stats =
          statistics_of_functions.at(as_string(fname_sinks.first));
      for (auto const&  sink_it : fname_sinks.second)
        fn_stats.on_get_may(sink_it->location_number);
    }

  time_point_end_program_info_collecting = get_current_time();
}

void  taint_statisticst::begin_loading_lvsa_database()
{
  time_point_begin_load_lvsa_database = get_current_time();
}

void  taint_statisticst::end_loading_lvsa_database()
{
  time_point_end_load_lvsa_database = get_current_time();
}

void  taint_statisticst::begin_loading_taint_summaries_database()
{
  time_point_begin_load_taint_database = get_current_time();
}

void  taint_statisticst::end_loading_taint_summaries_database()
{
  time_point_end_load_taint_database = get_current_time();
}

void  taint_statisticst::begin_callgraph_building()
{
  time_point_begin_callgraph_build = get_current_time();
}

void  taint_statisticst::end_callgraph_building()
{
  time_point_end_callgraph_build = get_current_time();
}

void  taint_statisticst::begin_lvsa_analysis_of_function(
    std::string const&  fn_name
    )
{
  assert(current_function_name.empty());
  current_function_name = fn_name;
  assert(statistics_of_functions.find(current_function_name)
         != statistics_of_functions.cend());
  statistics_of_functions.at(current_function_name).begin_lvsa_analysis();
}

void  taint_statisticst::end_lvsa_analysis_of_function(
    std::size_t const  num_fixpoint_steps,
    std::size_t const  num_uses_of_callee_summaries,
    std::size_t const  num_of_processed_rules_callee_summaries
    )
{
  assert(!current_function_name.empty());
  assert(statistics_of_functions.find(current_function_name)
         != statistics_of_functions.cend());
  statistics_of_functions.at(current_function_name).end_lvsa_analysis(
        num_fixpoint_steps,
        num_uses_of_callee_summaries,
        num_of_processed_rules_callee_summaries
        );
  current_function_name.clear();
}

void  taint_statisticst::begin_taint_analysis_of_function(
    std::string const&  fn_name
    )
{
  assert(current_function_name.empty());
  current_function_name = fn_name;
  assert(statistics_of_functions.find(current_function_name)
         != statistics_of_functions.cend());
  statistics_of_functions.at(current_function_name).begin_taint_summaries();
}

void  taint_statisticst::end_taint_analysis_of_function(
    taint_map_from_lvalues_to_svaluest const&  input,
    taint_map_from_lvalues_to_svaluest const&  output,
    taint_summary_domain_ptrt const  domain
    )
{
  assert(!current_function_name.empty());
  assert(statistics_of_functions.find(current_function_name)
         != statistics_of_functions.cend());
  statistics_of_functions.at(current_function_name).end_taint_summaries(
        input,output,domain
        );
  current_function_name.clear();
}

void  taint_statisticst::on_fixpoint_step_of_taint_analysis()
{
  assert(!current_function_name.empty());
  assert(statistics_of_functions.find(current_function_name)
         != statistics_of_functions.cend());
  statistics_of_functions.at(current_function_name)
                         .on_fixpoint_step_of_taint_summaries();
}

void  taint_statisticst::on_taint_analysis_use_callee_summary(
    taint_summary_ptrt const  summary,
    std::string const  callee_name
    )
{
  assert(!current_function_name.empty());
  assert(statistics_of_functions.find(current_function_name)
         != statistics_of_functions.cend());
  statistics_of_functions.at(current_function_name)
                         .on_taint_analysis_use_callee_summary(summary);
  statistics_of_functions.at(callee_name).on_taint_analysis_use_my_summary();
}


void  taint_statisticst::begin_error_traces_recognition()
{
  time_point_begin_error_traces_recognition = get_current_time();
}

void  taint_statisticst::end_error_traces_recognition()
{
  time_point_end_error_traces_recognition = get_current_time();
}

void  taint_statisticst::begin_dump_of_taint_html_summaries()
{
  time_point_begin_dump_taint_html_summaries = get_current_time();
}

void  taint_statisticst::end_dump_of_taint_html_summaries()
{
  time_point_end_dump_taint_html_summaries = get_current_time();
}

void  taint_statisticst::begin_dump_of_taint_json_summaries()
{
  time_point_begin_dump_taint_json_summaries = get_current_time();
}

void  taint_statisticst::end_dump_of_taint_json_summaries()
{
  time_point_end_dump_taint_json_summaries = get_current_time();
}

void  taint_statisticst::begin_dump_of_taint_html_traces()
{
  time_point_begin_dump_taint_html_traces = get_current_time();
}

void  taint_statisticst::end_dump_of_taint_html_traces()
{
  time_point_end_dump_taint_html_traces = get_current_time();
}

void  taint_statisticst::begin_dump_of_taint_json_traces()
{
  time_point_begin_dump_taint_json_traces = get_current_time();
}

void  taint_statisticst::end_dump_of_taint_json_traces()
{
  time_point_end_dump_taint_json_traces = get_current_time();
}


///////////////////////////////////////////////////////////////////
/// Queries
///////////////////////////////////////////////////////////////////


taint_statisticst::durationt
taint_statisticst::get_duration_of_program_building() const
{
  return get_duration(time_point_begin_program_build,
                      time_point_end_program_build);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_program_instrumentation() const
{
  return get_duration(time_point_begin_program_instrumentation,
                      time_point_end_program_instrumentation);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_program_info_collecting() const
{
  return get_duration(time_point_begin_program_info_collecting,
                      time_point_end_program_info_collecting);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_loading_lvsa_database() const
{
  return get_duration(time_point_begin_load_lvsa_database,
                      time_point_end_load_lvsa_database);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_loading_taint_database() const
{
  return get_duration(time_point_begin_load_taint_database,
                      time_point_end_load_taint_database);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_callgraph_building() const
{
  return get_duration(time_point_begin_callgraph_build,
                      time_point_end_callgraph_build);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_error_traces_recognition() const
{
  return get_duration(time_point_begin_error_traces_recognition,
                      time_point_end_error_traces_recognition);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_dump_of_taint_html_summaries() const
{
  return get_duration(time_point_begin_dump_taint_html_summaries,
                      time_point_end_dump_taint_html_summaries);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_dump_of_taint_json_summaries() const
{
  return get_duration(time_point_begin_dump_taint_json_summaries,
                      time_point_end_dump_taint_json_summaries);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_dump_of_taint_html_traces() const
{
  return get_duration(time_point_begin_dump_taint_html_traces,
                      time_point_end_dump_taint_html_traces);
}

taint_statisticst::durationt
taint_statisticst::get_duration_of_dump_of_taint_json_traces() const
{
  return get_duration(time_point_begin_dump_taint_json_traces,
                      time_point_end_dump_taint_json_traces);
}


taint_statisticst::durationt
taint_statisticst::get_duration_of_all_phases_together() const
{
  durationt const  sum =
        get_duration_of_program_building()
      + get_duration_of_program_instrumentation()
      + get_duration_of_program_info_collecting()
      + get_duration_of_loading_lvsa_database()
      + get_duration_of_loading_taint_database()
      + get_duration_of_callgraph_building()
      + get_duration_of_error_traces_recognition()
      + get_duration_of_dump_of_taint_html_summaries()
      + get_duration_of_dump_of_taint_json_summaries()
      + get_duration_of_dump_of_taint_html_traces()
      + get_duration_of_dump_of_taint_json_traces()
      ;
  return sum < 0.0001 ? 0.0001 : sum;
}


