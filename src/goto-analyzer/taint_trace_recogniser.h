/*******************************************************************\

Module: taint_trace_recogniser

Author: Marek Trtik

Date: Octomber 2016

This module is responsible for computation of error traces from
data stored in the databese of taint summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_TRACE_RECOGNISER_H
#define CPROVER_TAINT_TRACE_RECOGNISER_H

#include <goto-analyzer/taint_summary.h>
#include <summaries/summary.h>
#include <goto-programs/goto_model.h>
#include <goto-programs/goto_program.h>
#include <analyses/call_graph.h>
#include <util/irep.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <set>
#include <sstream>


typedef std::unordered_map<
          std::string,  // Name of a function in a goto-program
          std::vector<goto_programt::const_targett>,
                        // A vector of istructions of taint sources
          dstring_hash
          >
        taint_hot_locations_mapt;

typedef std::unordered_map<
          taint_svaluet::taint_symbolt,  // Name of the taint: 'taint_parse_treet::rulet::taint'
          taint_hot_locations_mapt
          >
        taint_sources_mapt;

typedef taint_sources_mapt
        taint_sinks_mapt;


class taint_trace_elementt
{
public:
  taint_trace_elementt(
      std::string const&  name_of_function_,
      goto_programt::const_targett  instruction_iterator_,
      taint_map_from_lvalues_to_svaluest const&  from_lvalues_to_svalues_,
      taint_svaluet::expressiont const&  symbols_,
      std::string const&  message_
      );

  std::string const& get_name_of_function() const noexcept
  { return name_of_function; }

  goto_programt::const_targett get_instruction_iterator() const noexcept
  { return instruction_iterator; }

  taint_map_from_lvalues_to_svaluest const&
    get_map_from_lvalues_to_svalues() const noexcept
    { return from_lvalues_to_svalues; }

  taint_svaluet::expressiont const&  get_symbols() const noexcept
  { return symbols; }

  std::string  get_file() const;
  std::size_t  get_line() const;
  std::string  get_code_annotation() const;

  std::string const& get_message() const noexcept
  { return message; }

private:
  std::string  name_of_function;
  goto_programt::const_targett  instruction_iterator;
  taint_map_from_lvalues_to_svaluest  from_lvalues_to_svalues;
  taint_svaluet::expressiont  symbols;
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
    taint_object_numbering_per_functiont&  taint_object_numbering,
    object_numbers_by_field_per_functiont&  object_numbers_by_field,
    std::stringstream* const  log
    );


void taint_recognise_error_traces(
    std::vector<taint_tracet>&  output_traces,
    goto_modelt const&  goto_model,
    call_grapht const&  call_graph,
    database_of_summariest const&  summaries,
    taint_svaluet::taint_symbolt const&  taint_name,
    std::string const&  source_function_name,
    goto_programt::const_targett const source_instruction,
    std::string const&  sink_function_name,
    goto_programt::const_targett const sink_instruction,
    taint_object_numbering_per_functiont&  taint_object_numbering,
    object_numbers_by_field_per_functiont&  object_numbers_by_field,
    std::stringstream* const  log
    );


#endif
