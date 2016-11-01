/*******************************************************************\

Module: taint_statistics_dump_json

Author: Marek Trtik

Date: November 2016

This module defines interfaces and functionality for dumping statistical
information stored in a 'taint_statistics' instance in JSON format.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_statistics_dump.h>
#include <goto-analyzer/taint_statistics.h>
#include <summaries/summary_dump.h>
#include <util/file_util.h>
#include <util/msgstream.h>
#include <util/json.h>
#include <iostream>
#include <iomanip>


static void  taint_dump_phases_table(json_objectt&  root)
{
  taint_statisticst const& S = taint_statisticst::instance();

  json_objectt  table;
  table["goto-program-building"] =
      json_numbert(msgstream() << S.get_duration_of_program_building());
  table["goto-program-instrumentation"] =
      json_numbert(msgstream() << S.get_duration_of_program_instrumentation());
  table["goto-program-info-search"] =
      json_numbert(msgstream() << S.get_duration_of_program_info_collecting());
  table["LVSA-load-database"] =
      json_numbert(msgstream() << S.get_duration_of_loading_lvsa_database());
  table["TA-load-database"] =
      json_numbert(msgstream() << S.get_duration_of_loading_taint_database());
  table["call-graph-build"] =
      json_numbert(msgstream() << S.get_duration_of_callgraph_building());

  taint_statisitcs_durationt  total_lvsa_duration = 0.0;
  taint_statisitcs_durationt  total_taint_duration = 0.0;
  for (auto const&  file_fns : S.get_map_from_files_to_functions())
    for (auto const&  fn_name : file_fns.second)
    {
      taint_function_statisticst const fS =
          S.get_statistics_of_functions().at(fn_name);
      total_lvsa_duration += fS.get_duration_of_lvsa_analysis();
      total_taint_duration += fS.get_duration_of_taint_summaries();
    }

  table["LVSA-run-time"] =
      json_numbert(msgstream() << total_lvsa_duration);
  table["TA-run-time"] =
      json_numbert(msgstream() << total_taint_duration);
  table["error-traces-recognition"] =
      json_numbert(msgstream() << S.get_duration_of_error_traces_recognition());
  table["TA-summary-save-in-HTML"] =
      json_numbert(msgstream() <<
                   S.get_duration_of_dump_of_taint_html_summaries());
  table["TA-summary-save-in-JSON"] =
      json_numbert(msgstream() <<
                   S.get_duration_of_dump_of_taint_json_summaries());
  table["error-traces-save-in-HTML"] =
      json_numbert(msgstream() <<
                   S.get_duration_of_dump_of_taint_html_traces());
  table["error-traces-save-in-JSON"] =
      json_numbert(msgstream() <<
                   S.get_duration_of_dump_of_taint_html_traces());

  root["table-phases"] = table;
}


static void  taint_dump_files_table(json_objectt&  root)
{
  taint_statisticst const& S = taint_statisticst::instance();

  json_arrayt  table;
  for (auto const&  file_fns : S.get_map_from_files_to_functions())
  {
    json_objectt  file_record;
    file_record["file-name"] = json_stringt(file_fns.first);
    json_arrayt  functions;
    {
      for (auto const&  fn_name : file_fns.second)
      {
        taint_function_statisticst const fS =
            S.get_statistics_of_functions().at(fn_name);

        json_objectt  fn_table;
        fn_table["function-name"] =
            json_stringt(fn_name);
        fn_table["num-locations"] =
            json_numbert(msgstream() << fS.get_num_locations());
        fn_table["num-taint-sources"] =
            json_numbert(msgstream()
                      << fS.get_locations_of_taint_sources().size());
        fn_table["num-taint-sinks"] =
            json_numbert(msgstream()
                      << fS.get_locations_of_taint_sinks().size());
        fn_table["num-taint-sanitisers"] =
            json_numbert(msgstream()
                      << fS.get_locations_of_taint_sanitisers().size());

        fn_table["LVSA-num-uses-of-callee-summaries"] =
            json_numbert(msgstream()
                      << fS.get_num_lvsa_uses_of_callee_summaries());
        fn_table["LVSA-num-processed-rules-of-used-callee-summaries"] =
            json_numbert(msgstream()
                      << fS.get_num_lvsa_of_processed_rules_callee_summaries());
        fn_table["LVSA-num-fixpoint-steps"] =
            json_numbert(msgstream()
                      << fS.get_num_fixpoint_steps_of_lvsa_analysis());
        fn_table["LVSA-duration"] =
            json_numbert(msgstream()
                      << fS.get_duration_of_lvsa_analysis());

        fn_table["TA-num-rules-in-input"] =
            json_numbert(msgstream()
                      << fS.get_summary_input_size());
        fn_table["TA-num-rules-in-output"] =
            json_numbert(msgstream()
                      << fS.get_summary_output_size());
        fn_table["TA-num-rules-in-domain"] =
            json_numbert(msgstream()
                      << fS.get_summary_domain_size());
        fn_table["TA-num-uses-of-own-summary"] =
            json_numbert(msgstream()
                      << fS.get_num_usages_of_my_summary());
        fn_table["TA-num-uses-of-callee-summaries"] =
            json_numbert(msgstream()
                      << fS.get_num_usages_of_callee_summaries());
        fn_table["TA-num-processed-rules-of-used-callee-summaries"] =
            json_numbert(msgstream()
                      << fS.get_num_rules_in_used_callee_summaries());
        fn_table["TA-num-fixpoint-steps"] =
            json_numbert(msgstream()
                      << fS.get_num_fixpoint_steps_of_taint_summaries());
        fn_table["TA-duration"] =
            json_numbert(msgstream()
                      << fS.get_duration_of_taint_summaries());

        functions.push_back(fn_table);
      }
    }
    file_record["functions"] = functions;
    table.push_back(file_record);
  }

  root["table-files"] = table;
}


void  taint_dump_statistics_in_JSON(
    std::ostream&  ostr
    )
{
  json_objectt  root;

  taint_dump_phases_table(root);
  taint_dump_files_table(root);

  ostr << root;
}
