/*******************************************************************\

Module: taint_statistics_dump_html

Author: Marek Trtik

Date: November 2016

This module defines interfaces and functionality for dumping statistical
information stored in a 'taint_statistics' instance in HTML format.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_statistics_dump.h>
#include <goto-analyzer/taint_statistics.h>
#include <summaries/summary_dump.h>
#include <util/msgstream.h>
#include <fstream>
#include <iomanip>


static void  taint_build_global_stats_table(std::ofstream&  ostr)
{
  taint_statisticst const& S = taint_statisticst::instance();
  ostr << "<table>\n"
          "  <caption>Total times of individual phases of the analysis."
          "</caption>\n"
          "  <tr>\n"
          "    <th>Phase of the analysis</th>\n"
          "    <th>Time [s]</th>\n"
          "    <th>Time [%]</th>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Building of GOTO program</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_program_building()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_program_building()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Instrumentation of sinks, sources, and sanitisers</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_program_instrumentation()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_program_instrumentation()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Loading of LVSA database of summaries</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_loading_lvsa_database()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_loading_lvsa_database()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Loading of database of taint summaries</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_loading_taint_database()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_loading_taint_database()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Building call-graph</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_callgraph_building()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_callgraph_building()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Recognition of error traces</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_error_traces_recognition()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_error_traces_recognition()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Save of function taint summaries in HTML format</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_dump_of_taint_html_summaries()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_dump_of_taint_html_summaries()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Save of function taint summaries in JSON format</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_dump_of_taint_json_summaries()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_dump_of_taint_json_summaries()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Save of error traces in HTML format</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_dump_of_taint_html_traces()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_dump_of_taint_html_traces()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "  <tr>\n"
          "    <td>Save of error traces in JSON format</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_dump_of_taint_json_traces()
       << "</td>\n"
          "    <td align=\"right\">"
       << std::fixed << std::setprecision(1)
       << (S.get_duration_of_dump_of_taint_json_traces()
              * 100.0) / S.get_duration_of_all_phases_together()
       << "</td>\n"
          "  </tr>\n"

          "    <td><b>TOTAL</b></td>\n"
          "    <td align=\"right\"><b>"
       << std::fixed << std::setprecision(3)
       << S.get_duration_of_all_phases_together()
       << "</b></td>\n"
          "    <td align=\"right\"><b>100.0</b></td>\n"
          "  </tr>\n"

          "</table>\n"
          ;
}


static void  taint_per_function_stats_table(
    std::ofstream&  ostr,
    std::string const&  file_name
    )
{
  ostr << "<table>\n"
          "  <caption>Performance of taint analysis on individual functions."
          "</caption>\n"
          "  <tr>\n"
          "    <th>#</th>\n"
          "    <th>Function</th>\n"
          "  </tr>\n"
          ;
  taint_statisticst const& S = taint_statisticst::instance();
  std::size_t  file_id = 0UL;
  for (auto const&  fn_name : S.get_map_from_files_to_functions().at(file_name))
  {
    ostr << "  <tr>\n"
            "    <td align=\"right\">" << ++file_id << "</td>\n"
            "    <td>"
         << to_html_text(fn_name)
         << "</td>\n"
            ;
    ostr << "  </tr>\n";
  }
  ostr << "</table>\n"
          ;
}


static void  taint_per_file_stats_table(
    std::ofstream&  ostr,
    std::string const&  dump_root_directory
    )
{
  taint_statisticst const& S = taint_statisticst::instance();
  ostr << "<table>\n"
          "  <caption>Statistical data per individual analysed source files."
          "</caption>\n"
          "  <tr>\n"
          "    <th rowspan=\"2\">#</th>\n"
          "    <th rowspan=\"2\">Souce file</th>\n"
          "    <th colspan=\"2\">Functions</th>\n"
          "    <th colspan=\"2\">Locations</th>\n"
          "    <th colspan=\"4\">LVSA analysis</th>\n"
          "    <th colspan=\"4\">Taint summaries</th>\n"
          "    <th rowspan=\"2\">Details</th>\n"
          "  </tr>\n"
          "  <tr>\n"
          "    <th>#</th>\n"
          "    <th>%</th>\n"
          "    <th>#</th>\n"
          "    <th>%</th>\n"
          "    <th>Time [s]</th>\n"
          "    <th>%</th>\n"
          "    <th>Steps</th>\n"
          "    <th>%</th>\n"
          "    <th>Time [s]</th>\n"
          "    <th>%</th>\n"
          "    <th>Steps</th>\n"
          "    <th>%</th>\n"
          "  </tr>\n"
          ;
  std::size_t  total_num_locations = 0UL;
  taint_statisitcs_durationt  total_lvsa_duration = 0.0;
  taint_statisitcs_durationt  total_taint_duration = 0.0;
  std::size_t  total_lvsa_steps = 0UL;
  std::size_t  total_taint_steps = 0UL;
  for (auto const&  file_fns : S.get_map_from_files_to_functions())
  {
    for (auto const&  fn_name : file_fns.second)
    {
      taint_function_statisticst const fS =
          S.get_statistics_of_functions().at(fn_name);
      total_num_locations += fS.get_num_locations();
      total_lvsa_duration += fS.get_duration_of_lvsa_analysis();
      total_taint_duration += fS.get_duration_of_taint_summaries();
      total_lvsa_steps += fS.get_num_fixpoint_steps_of_lvsa_analysis();
      total_taint_steps += fS.get_num_fixpoint_steps_of_taint_summaries();
    }
  }
  std::size_t  file_id = 0UL;
  for (auto const&  file_fns : S.get_map_from_files_to_functions())
  {
    ostr << "  <tr>\n"
            "    <td align=\"right\">" << ++file_id << "</td>\n"
            "    <td>" << to_html_text(file_fns.first) << "</td>\n"
            "    <td align=\"right\">" << file_fns.second.size() << "</td>\n"
            ;
    ostr << "    <td align=\"right\">"
         << std::fixed << std::setprecision(1)
         << (S.get_map_from_functions_to_files().size() == 0UL ? 0.0 :
                (double)file_fns.second.size()
                / (double)S.get_map_from_functions_to_files().size())
         << "</td>\n"
            ;
    std::size_t  num_locations = 0UL;
    taint_statisitcs_durationt  lvsa_duration = 0.0;
    taint_statisitcs_durationt  taint_duration = 0.0;
    std::size_t  lvsa_steps = 0UL;
    std::size_t  taint_steps = 0UL;
    for (auto const&  fn_name : file_fns.second)
    {
      taint_function_statisticst const fS =
          S.get_statistics_of_functions().at(fn_name);
      num_locations += fS.get_num_locations();
      lvsa_duration += fS.get_duration_of_lvsa_analysis();
      taint_duration += fS.get_duration_of_taint_summaries();
      lvsa_steps += fS.get_num_fixpoint_steps_of_lvsa_analysis();
      taint_steps += fS.get_num_fixpoint_steps_of_taint_summaries();
    }
    ostr << "    <td align=\"right\">" << num_locations << "</td>\n";
    ostr << "    <td align=\"right\">"
         << std::fixed << std::setprecision(1)
         << 100.0 * (total_num_locations == 0UL ? 0.0 :
                (double)num_locations / (double)total_num_locations)
         << "</td>\n"
            ;
    ostr << "    <td align=\"right\">"
         << std::fixed << std::setprecision(3)
         << lvsa_duration
         << "</td>\n";
    ostr << "    <td align=\"right\">"
         << std::fixed << std::setprecision(1)
         << 100.0 * (total_lvsa_duration < 1e-4f ? 0.0 :
                lvsa_duration / total_lvsa_duration)
         << "</td>\n"
            ;
    ostr << "    <td align=\"right\">" << lvsa_steps << "</td>\n";
    ostr << "    <td align=\"right\">"
         << std::fixed << std::setprecision(1)
         << 100.0 * (total_lvsa_steps == 0UL ? 0.0 :
                (double)lvsa_steps / (double)total_lvsa_steps)
         << "</td>\n"
            ;

    ostr << "    <td align=\"right\">"
         << std::fixed << std::setprecision(3)
         << taint_duration
         << "</td>\n";
    ostr << "    <td align=\"right\">"
         << std::fixed << std::setprecision(1)
         << 100.0 * (total_taint_duration < 1e-4f ? 0.0 :
                taint_duration / total_taint_duration)
         << "</td>\n"
            ;
    ostr << "    <td align=\"right\">" << taint_steps << "</td>\n";
    ostr << "    <td align=\"right\">"
         << std::fixed << std::setprecision(1)
         << 100.0 * (total_taint_steps == 0UL ? 0.0 :
                (double)taint_steps / (double)total_taint_steps)
         << "</td>\n"
            ;

    {
      ostr << "    <td align=\"center\"><a href=\"./file_" << file_id
          << ".html\">here</a></td>\n"
              ;
      std::ofstream  file_ostr(msgstream() << dump_root_directory << "/file_"
                                           << file_id << ".html");
      dump_html_prefix(file_ostr,"File statistics");
      file_ostr << "<h1>Statistical data from a run of taint analysis on file "
                   "'" << to_html_text(file_fns.first) << "'</h1>\n";
      taint_per_function_stats_table(file_ostr,file_fns.first);
      dump_html_suffix(file_ostr);
    }

    ostr << "  </tr>\n";

  }

  ostr << "  <tr>\n"
          "    <td></td>\n"
          "    <td><b>TOTAL</b></td>\n"
          "    <td align=\"right\"><b>"
       << S.get_map_from_functions_to_files().size()
       << "</b></td>\n"
          "    <td align=\"right\"><b>100.0</b></td>\n"
          "    <td align=\"right\"><b>"
       << total_num_locations
       << "</b></td>\n"
          "    <td align=\"right\"><b>100.0</b></td>\n"
          "    <td align=\"right\"><b>"
       << total_lvsa_duration
       << "</b></td>\n"
          "    <td align=\"right\"><b>100.0</b></td>\n"
          "    <td align=\"right\"><b>"
       << total_lvsa_steps
       << "</b></td>\n"
          "    <td align=\"right\"><b>100.0</b></td>\n"
          "    <td align=\"right\"><b>"
       << total_taint_duration
       << "</b></td>\n"
          "    <td align=\"right\"><b>100.0</b></td>\n"
          "    <td align=\"right\"><b>"
       << total_taint_steps
       << "</b></td>\n"
          "    <td align=\"right\"><b>100.0</b></td>\n"
          "    <td></td>\n"
          "  </tr>\n"
          "</table>\n"
          ;
}


void  taint_dump_statistics_in_HTML(std::string const&  dump_root_directory)
{
  fileutl_create_directory(dump_root_directory);
  std::ofstream  ostr(msgstream() << dump_root_directory << "/index.html");
  dump_html_prefix(ostr,"Statistics");

  ostr << "<h1>Statistics data from a run of taint analysis</h1>\n";
  taint_build_global_stats_table(ostr);
  ostr << "<p></p>\n";
  taint_per_file_stats_table(ostr,dump_root_directory);

  dump_html_suffix(ostr);
}
