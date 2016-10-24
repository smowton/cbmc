/*******************************************************************\

Module: taint_trace_recogniser

Author: Marek Trtik

Date: Octomber 2016



@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_trace_recogniser.h>


taint_trace_elementt::taint_trace_elementt(
    std::string const&  name_of_function_,
    goto_programt::targett  instruction_iterator_,
    std::string const&  message_
    )
  : name_of_function(name_of_function_)
  , instruction_iterator(instruction_iterator_)
  , message(message_)
{}


void taint_recognise_error_traces(
    std::vector<taint_tracet>&  output_traces,
    goto_modelt const&  goto_model,
    call_grapht const&  call_graph,
    database_of_summariest const&  summaries,
    taint_sources_mapt const&  taint_sources,
    taint_sinks_mapt const&  taint_sinks,
    std::stringstream* const  log
    )
{
  if (log != nullptr)
    *log << "<h2>Building taint error traces</h2>\n";
  for (auto const  tid_locs : taint_sinks)
    for (auto const  fn_locs : tid_locs.second)
      for (auto const  loc : fn_locs.second)
      {
        auto const  src_it = taint_sources.find(tid_locs.first);
        if (src_it != taint_sources.cend())
          for (auto const  src_fn_locs : src_it->second)
            for (auto const  src_loc : src_fn_locs.second)
              taint_recognise_error_traces(
                    output_traces,
                    goto_model,
                    call_graph,
                    summaries,
                    tid_locs.first,
                    src_fn_locs.first,
                    src_loc,
                    fn_locs.first,
                    loc,
                    log
                    );
      }
}


void taint_recognise_error_traces(
    std::vector<taint_tracet>&  output_traces,
    goto_modelt const&  goto_model,
    call_grapht const&  call_graph,
    database_of_summariest const&  summaries,
    std::string const&  taint_name,
    std::string const&  source_function_name,
    goto_programt::targett const source_instruction,
    std::string const&  sink_function_name,
    goto_programt::targett const sink_instruction,
    std::stringstream* const  log
    )
{
  if (log != nullptr)
    *log << "<h3>Building an error trace from source to sink</h3>\n"
            "<p>We will recognise all tained paths from this pair of source "
            "and sink:</p>\n"
            "<table>\n"
            "  <tr>\n"
            "    <th>Source function</th>\n"
            "    <th>Source location</th>\n"
            "    <th>Taint symbol</th>\n"
            "    <th>Sink function</th>\n"
            "    <th>Sink location</th>\n"
            "  </tr>\n"
            "  <tr>\n"
            "    <td>" << source_function_name << "</td>\n"
            "    <td>" << source_instruction->location_number << "</td>\n"
            "    <td>" << taint_name << "</td>\n"
            "    <td>" << sink_function_name<< "</td>\n"
            "    <td>" << sink_instruction->location_number << "</td>\n"
            "  </tr>\n"
            "</table>\n"
            ;

  if (source_function_name != sink_function_name &&
      !exists_direct_or_indirect_call(
        call_graph,
        source_function_name,
        sink_function_name
        ))
    {
    if (log != nullptr)
      *log << "<p>The sink function is call-graph unreachable from the source "
              "function. So, terminating immediatelly.</p>\n"
              ;
      return;
    }
}
