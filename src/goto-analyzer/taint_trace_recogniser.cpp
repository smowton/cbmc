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
}
