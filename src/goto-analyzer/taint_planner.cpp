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

#include <goto-analyzer/taint_planner.h>
#include <goto-analyzer/taint_summary.h>
#include <goto-analyzer/taint_analysis.h>
#include <util/msgstream.h>
#include <util/file_util.h>
#include <json/json_parser.h>
#include <cassert>
#include <stdexcept>


static access_path_to_memoryt string_to_access_path(
    const std::string& access_path,
    goto_modelt const&  program,
    const std::string& functionname)
{
  // TODO: implement this function!
  throw std::runtime_error("NOT IMPLEMENTED YET");
}


taint_plan_for_analysist::taint_plan_for_analysist(
    const std::vector<irep_idt>&  _functions_to_analyse
    )
  : functions_to_analyse(_functions_to_analyse)
{
//  assert(!functions_to_analyse.empty());
}


taint_plan_for_summariest::taint_plan_for_summariest(
    const std::vector<irep_idt>&  _functions_to_analyse,
    const access_paths_of_functionst& _access_paths_of_functions
    )
  : functions_to_analyse(_functions_to_analyse)
  , access_paths_of_functions(_access_paths_of_functions)
{
  assert(functions_to_analyse.size() == access_paths_of_functions.size());
}


taint_precision_level_datat::taint_precision_level_datat(
    const taint_plan_for_analysis_ptrt _plan_for_analysis,
    const taint_plan_for_summaries_ptrt _plan_for_summaries,
    const database_of_summaries_ptrt _summary_database
    )
  : plan_for_analysis(_plan_for_analysis)
  , plan_for_summaries(_plan_for_summaries)
  , summary_database(_summary_database)
  , is_computed(false)
{
  assert(plan_for_analysis.operator bool());
  assert(plan_for_summaries.operator bool());
  assert(summary_database.operator bool());
}

std::string  taint_plannert::solve_top_precision_level(
    goto_modelt&  program,
    call_grapht const&  call_graph,
    std::ostream* const  log
    )
{
  const taint_precision_level_data_ptrt  data = get_top_precision_level();
  if (data->get_is_computed())
    return "";  // No error. There is nothing to do (all was computed).

  std::string  error_message = compute_summaries(
        data->get_plan_for_summaries(),
        data->get_summary_database(),
        program,
        call_graph,
        log
        );
  if (!error_message.empty())
    return error_message;

  error_message = run_taint_analysis(
        data->get_plan_for_analysis(),
        data->get_summary_database(),
        program,
        log);
  if (!error_message.empty())
    return error_message;

  error_message = build_next_precision_level(
        program,
        call_graph,
        log
        );
  if (!error_message.empty())
    return error_message;

  data->set_is_computed();
  return ""; // No error.
}


std::string  taint_plannert::compute_summaries(
    const taint_plan_for_summaries_ptrt plan_for_summaries,
    const database_of_summaries_ptrt summary_database,
    goto_modelt const&  program,
    call_grapht const&  call_graph,
    std::ostream* const  log
    )
{
  std::vector<irep_idt>  inverted_topological_order;
  {
    std::unordered_set<irep_idt,dstring_hash>  processed;
    for (const auto&  elem : plan_for_summaries->get_functions_to_analyse())
      inverted_partial_topological_order(
            call_graph,
            elem,
            processed,
            inverted_topological_order
            );
  }
  for (const auto&  fn_name : inverted_topological_order)
  {
    goto_functionst::function_mapt  const  functions_map =
        program.goto_functions.function_map;
    auto const  fn_it = functions_map.find(fn_name);
    if (fn_it != functions_map.cend() && fn_it->second.body_available())
      summary_database->insert({
          as_string(fn_name),
          taint_summarise_function(
              // TODO: pass to this function a set of access paths
              //       representing potential sources of tainted data.
              //       The function should then consider all other objects
              //       In the scope as non-tainted.
              fn_name,
              program,
              *summary_database,
              log
              ),
          });
  }
  return ""; // No error.
}


std::string  taint_plannert::run_taint_analysis(
    const taint_plan_for_analysis_ptrt plan_for_analysis,
    const database_of_summaries_ptrt summary_database,
    goto_modelt&  program,
    std::ostream* const  log
    )
{
  // Plan ignored here, as it is currently used to set the entry point
  // in goto_analyzer_parse_options.cpp.
  taint_analysis(program, get_message_handler(), true, "", summary_database);
  return ""; // No error.
}


std::string  taint_plannert::build_next_precision_level(
    goto_modelt const&  program,
    call_grapht const&  call_graph,
    std::ostream* const  log
    )
{
  // TODO: here goes a code preparing new plans for both analyses
  //       (taint summary and taint analysis).
  return ""; // No error.
}

void taint_plannert::read_plan_from_file(const std::string& plan_file)
{
  if (!fileutl_file_exists(plan_file) || fileutl_is_directory(plan_file))
  {
    error() << "Cannot find the plan JSON file: " << plan_file;
    throw;
  }

  jsont  plan;
  if (parse_json(plan_file, get_message_handler(), plan))
  {
    error() << "Parsing of the JSON file '" << plan_file << "' has failed.";
    throw;
  }

  taint_plan_for_analysis_ptrt  plan_for_analysis;
  {
    const jsont& analysis_plan = plan["analysis_plan"];
    if (!analysis_plan.is_array())
      throw std::runtime_error(
          msgstream() << "In taint_plannert::taint_plannert() : "
                         "Cannot find array element 'analysis_plan'."
          );

    std::vector<irep_idt>  fn_names;
    for (const jsont&  plan_elem : analysis_plan.array)
    {
      const jsont& function = plan_elem["function"];
      if (!function.is_string())
        throw std::runtime_error(
            msgstream() << "In taint_plannert::taint_plannert() : "
                           "Cannot find string element 'function' in "
                           "array element 'analysis_plan'."
            );
      fn_names.push_back(function.value);
    }

    plan_for_analysis = std::make_shared<taint_plan_for_analysist>(fn_names);
  }

  taint_plan_for_summaries_ptrt plan_for_summaries;
  {
    const jsont& summary_plan = plan["summary_plan"];
    if (!summary_plan.is_array())
      throw std::runtime_error(
          msgstream() << "In taint_plannert::taint_plannert() : "
                         "Cannot find array element 'summary_plan'."
          );

    std::vector<irep_idt>  fn_names;
    taint_plan_for_summariest::access_paths_of_functionst
        access_paths_of_functions;
    for (const jsont&  plan_elem : summary_plan.array)
    {
      const jsont& function = plan_elem["function"];
      if (!function.is_string())
        throw std::runtime_error(
            msgstream() << "In taint_plannert::taint_plannert() : "
                           "Cannot find string element 'function' in "
                           "array element 'summary_plan'."
            );
      fn_names.push_back(function.value);

      const jsont& access_paths = plan_elem["access_paths"];
      if (!access_paths.is_array())
        throw std::runtime_error(
            msgstream() << "In taint_plannert::taint_plannert() : "
                           "Cannot find array element 'access_paths' in "
                           "array element of array 'summary_plan'."
            );
      access_paths_of_functions.push_back({});
      for (const auto&  path : access_paths.array)
      {
        if (!path.is_string())
          throw std::runtime_error(
              msgstream() << "In taint_plannert::taint_plannert() : "
                             "Cannot find string in array 'access_paths' "
                             "of array 'summary_plan'."
              );
        access_paths_of_functions.back().push_back(path.value);
      }
    }

    plan_for_summaries = std::make_shared<taint_plan_for_summariest>(
          fn_names,
          access_paths_of_functions
          );
  }

  const database_of_summaries_ptrt summary_database =
      std::make_shared<database_of_summariest>();
  {
    const jsont& summaries_of_sources = plan["summaries_of_sources"];
    if (!summaries_of_sources.is_array())
      throw std::runtime_error(
          msgstream() << "In taint_plannert::taint_plannert() : "
                         "Cannot find array element 'summaries_of_sources'."
          );
    for (const jsont&  fn_summary : summaries_of_sources.array)
    {
      const jsont& function = fn_summary["function"];
      if (!function.is_string())
        throw std::runtime_error(
            msgstream() << "In taint_plannert::taint_plannert() : "
                           "Cannot find string element 'function' in "
                           "array element 'summaries_of_sources'."
            );

      const jsont& input = fn_summary["input"];
      if (!input.is_array())
        throw std::runtime_error(
            msgstream() << "In taint_plannert::taint_plannert() : "
                           "Cannot find array element 'input' in "
                           "array of array 'summaries_of_sources'."
            );
      taint_map_from_lvalues_to_svaluest  input_map;
      for (const auto&  access_path : input.array)
      {
        if (!access_path.is_string())
          throw std::runtime_error(
              msgstream() << "In taint_plannert::taint_plannert() : "
                             "Cannot find string value in array 'input'"
                             "of arrays 'summaries_of_sources'."
              );

// TODO: uncomment the code bellow once 'string_to_access_path' is implemented.
//        input_map.insert({
//              string_to_access_path(access_path.value,program,function.value),
//              taint_make_symbol()
//              });
      }

      const jsont& summary = fn_summary["summary"];
      if (!summary.is_array())
        throw std::runtime_error(
            msgstream() << "In taint_plannert::taint_plannert() : "
                           "Cannot find array element 'summary' in "
                           "array of array 'summaries_of_sources'."
            );
      taint_map_from_lvalues_to_svaluest  output_map;
      for (const auto&  path_symbols : summary.array)
      {
        const jsont& access_path = path_symbols["access_path"];
        if (!access_path.is_string())
          throw std::runtime_error(
              msgstream() << "In taint_plannert::taint_plannert() : "
                             "Cannot find 'access_path' in array 'summary'"
                             "of arrays 'summaries_of_sources'."
              );

        const jsont& symbols = path_symbols["symbols"];
        if (!symbols.is_array())
          throw std::runtime_error(
              msgstream() << "In taint_plannert::taint_plannert() : "
                             "Cannot find array 'symbols' in array 'summary'"
                             "of arrays 'summaries_of_sources'."
              );

        taint_svaluet::expressiont  expression;
        for (const auto&  symbol : symbols.array)
        {
          if (!symbol.is_string())
            throw std::runtime_error(
                msgstream() << "In taint_plannert::taint_plannert() : "
                               "Cannot find string value in array 'symbols' "
                               "of array 'summary' of arrays "
                               "'summaries_of_sources'."
                );
          expression.insert(symbol.value);
        }

// TODO: uncomment the code bellow once 'string_to_access_path' is implemented.
//        output_map.insert({
//              string_to_access_path(access_path.value,program,function.value),
//              taint_svaluet(expression,false,false)
//              });
      }

      summary_database->insert({
            function.value,
            std::make_shared<taint_summaryt>(
                  input_map,
                  output_map,
                  taint_summary_domain_ptrt()
                  )
            });
    }

    // TODO! read sinks!
  }

  computed_levels.push_back(
        std::make_shared<taint_precision_level_datat>(
            plan_for_analysis,
            plan_for_summaries,
            summary_database
            )
        );
  
}
