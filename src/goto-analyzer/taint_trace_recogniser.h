/*******************************************************************\

Module: taint_trace_recogniser

Author: Marek Trtik

Date: Octomber 2016



@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_TRACE_RECOGNISER_H
#define CPROVER_TAINT_TRACE_RECOGNISER_H

#include <goto-analyzer/taint_summary.h>
#include <goto-programs/goto_model.h>
#include <goto-programs/goto_program.h>
#include <analyses/call_graph.h>
#include <util/irep.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <sstream>


typedef std::unordered_map<
          std::string,  // Name of the taint: 'taint_parse_treet::rulet::taint'
          std::unordered_map<
            std::string,  // Name of a function in a goto-program
            std::vector<goto_programt::targett>,
                          // A vector of istructions of taint sources
            dstring_hash
            > >
        taint_sources_mapt;

typedef taint_sources_mapt
        taint_sinks_mapt;


class taint_trace_elementt
{
public:
  taint_trace_elementt(
      std::string const&  name_of_function_,
      goto_programt::targett  instruction_iterator_,
      std::string const&  message_
      );

  std::string const& get_name_of_function() const noexcept
  { return name_of_function; }

  goto_programt::targett get_instruction_iterator() const noexcept
  { return instruction_iterator; }

  std::string const& get_message() const noexcept
  { return message; }

private:
  std::string  name_of_function;
  goto_programt::targett  instruction_iterator;
  std::string  message;
};

typedef std::vector<taint_trace_elementt>
        taint_tracet;


void taint_recognise_error_traces(
      std::vector<taint_tracet>&  output_traces,
      goto_modelt const&  goto_model,
      call_grapht const&  call_graph,
      database_of_summariest const&  summaries,
      taint_sources_mapt const&  taint_sources,
      taint_sinks_mapt const&  taint_sinks,
      std::stringstream* const  log
      );


#endif
