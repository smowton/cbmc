/*******************************************************************\

Module: taint_trace_recogniser

Author: Marek Trtik

Date: Octomber 2016

This module is responsible for computation of error traces from
data stored in the databese of taint summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_trace_recogniser.h>
#include <goto-analyzer/taint_summary.h>
#include <goto-analyzer/taint_summary_dump.h>
#include <util/msgstream.h>
#include <unordered_set>
#include <deque>
#include <limits>
#include <algorithm>
#include <iterator>
#include <cassert>


class trace_under_constructiont
{
public:
  typedef std::unordered_map<
              std::string,  //!< Name of a function.
              std::unordered_set<std::size_t> //!< A set of locations visited
                                              //!< at the function.
              >
          visited_locations_mapt;

  typedef std::pair<
              std::size_t, //!< Index into this trace where is a call statement.
              std::unordered_set<std::string> //!< A set of symbols representing
                                              //!< the tainted symbol in the
                                              //!< called function.
              >
          call_stack_valuet;

  typedef std::vector<call_stack_valuet>
          call_stackt;


  explicit trace_under_constructiont(
      taint_trace_elementt const&  element,
      std::unordered_set<std::string> const&  symbols
      );

  taint_tracet const&  get_trace() const noexcept  { return trace; }
  visited_locations_mapt const& get_visited() const noexcept { return visited; }
  call_stackt const&  get_stack() const { return call_stack; }

  /// Trace-related access/check methods
  bool  empty() const { return trace.empty(); }
  std::size_t  count(
      std::string const&  name_of_function,
      std::size_t const  location_number
      ) const;
  std::size_t  count(
      std::string const&  name_of_function,
      goto_programt::const_targett const  instruction_iterator
      ) const;
  std::size_t  count(taint_trace_elementt const&  element) const;
  void  push_back(taint_trace_elementt const&  element);
  taint_trace_elementt const&  back() const { return trace.back(); }
  taint_trace_elementt const&  at(std::size_t const  index) const
  { return trace.at(index); }

  /// Call-stack-related access/check methods
  bool  stack_has_return() const { return call_stack.size() > 1UL; }
  call_stack_valuet const& stack_top() const { return call_stack.back(); }
  void  stack_push(std::unordered_set<std::string> const&  symbols);
  void  stack_set_top(std::unordered_set<std::string> const&  symbols);
  void  stack_pop();

private:
  taint_tracet  trace;
  visited_locations_mapt  visited;
  call_stackt  call_stack;
};

trace_under_constructiont::trace_under_constructiont(
    taint_trace_elementt const&  element,
    std::unordered_set<std::string> const&  symbols
    )
  : trace{element}
  , visited{}
  , call_stack{{std::numeric_limits<std::size_t>::max(),symbols}}
{}

std::size_t  trace_under_constructiont::count(
    std::string const&  name_of_function,
    std::size_t const  location_number
    ) const
{
  auto const  fn_it = visited.find(name_of_function);
  if (fn_it == visited.cend())
    return 0UL;
  auto const  loc_it =
      fn_it->second.find(location_number);
  if (loc_it == fn_it->second.cend())
    return 0UL;
  return 1UL;
}

std::size_t  trace_under_constructiont::count(
    std::string const&  name_of_function,
    goto_programt::const_targett const  instruction_iterator
    ) const
{
  return count(name_of_function,instruction_iterator->location_number);
}

std::size_t  trace_under_constructiont::count(
    taint_trace_elementt const&  element
    ) const
{
  return count(element.get_name_of_function(),
               element.get_instruction_iterator());
}

void trace_under_constructiont::push_back(
    taint_trace_elementt const&  element
    )
{
  trace.push_back(element);
  auto const  fn_it = visited.find(element.get_name_of_function());
  if (fn_it == visited.cend())
    visited.insert({
        element.get_name_of_function(),
        {element.get_instruction_iterator()->location_number}
        });
  else
  {
    auto const  result =
      fn_it->second.insert(element.get_instruction_iterator()->location_number);
    assert(result.second == true);
  }
}

void  trace_under_constructiont::stack_push(
    std::unordered_set<std::string> const&  symbols
    )
{
  assert(!empty());
  assert(!symbols.empty());
  call_stack.push_back({trace.size() - 1UL,symbols});
}

void  trace_under_constructiont::stack_set_top(
    std::unordered_set<std::string> const&  symbols
    )
{
  assert(!empty());
  assert(!symbols.empty());
  call_stack.back().second = symbols;
}

void  trace_under_constructiont::stack_pop()
{
  assert(!call_stack.empty());
  call_stack.pop_back();
}


taint_trace_elementt::taint_trace_elementt(
    std::string const&  name_of_function_,
    goto_programt::const_targett  instruction_iterator_,
    taint_map_from_lvalues_to_svaluest const&  from_lvalues_to_svalues_,
    taint_svaluet::expressiont const&  symbols_,
    std::string const&  message_
    )
  : name_of_function(name_of_function_)
  , instruction_iterator(instruction_iterator_)
  , from_lvalues_to_svalues(from_lvalues_to_svalues_)
  , symbols(symbols_)
  , message(message_)
{}

std::string  taint_trace_elementt::get_file() const
{
  return instruction_iterator->source_location.is_nil() ? "" :
              as_string(instruction_iterator->source_location.get_file());
}

std::size_t  taint_trace_elementt::get_line() const
{
  return instruction_iterator->source_location.is_nil() ? 0UL :
              std::atol(
                  as_string(instruction_iterator->source_location.get_line())
                      .c_str()
                  );
}

std::string  taint_trace_elementt::get_code_annotation() const
{
  return as_string(instruction_iterator->source_location.get_comment());
}


static void  taint_collect_successors_inside_function(
    goto_modelt const&  goto_model,
    trace_under_constructiont const&  trace,
    taint_trace_elementt const&  elem,
    database_of_summariest const&  summaries,
    std::string const&  taint_name,
    std::string const&  sink_function_name,
    goto_programt::const_targett const sink_instruction,
    std::vector<taint_trace_elementt>&  successors,
    std::stringstream* const  log
    )
{
  goto_functionst::goto_functiont const&  fn =
      goto_model.goto_functions.function_map.at(
          elem.get_name_of_function()
          );
  goto_programt::const_targetst  succ_targets;
  fn.body.get_successors(elem.get_instruction_iterator(),succ_targets);
  std::unordered_set<std::size_t>  processed_locations;
  for (goto_programt::const_targett  succ_target : succ_targets)
  {
    if (0UL == trace.count(elem.get_name_of_function(),succ_target) &&
        0UL == processed_locations.count(succ_target->location_number))
    {
      taint_map_from_lvalues_to_svaluest  from_lvalues_to_svalues;
      taint_svaluet::expressiont  symbols;
      {
        taint_summary_domain_ptrt const  domain =
            summaries.find<taint_summaryt>(
                elem.get_name_of_function()
                )->domain();
        assert(domain.operator bool());
        for (auto const&  lvalue_svalue : domain->at(succ_target))
        {
          taint_svaluet::expressiont  symbols;
          for (auto const&  symbol : lvalue_svalue.second.expression())
            if (trace.stack_top().second.count(symbol) != 0UL)
              symbols.insert(symbol);
          if (!symbols.empty())
            from_lvalues_to_svalues.insert({
                lvalue_svalue.first,
                { symbols, false, false}
                });
        }
      }
      if (!from_lvalues_to_svalues.empty())
        successors.push_back({
              elem.get_name_of_function(),
              succ_target,
              from_lvalues_to_svalues,
              taint_svaluet::expressiont(
                  trace.stack_top().second.cbegin(),
                  trace.stack_top().second.cend()
                  ),
              ""
              });
    }
    processed_locations.insert(succ_target->location_number);
  }
}

static exprt taint_find_expression_of_rule(exprt const&  expr)
{
  if(expr.id() == "get_may")
  {
    if (expr.operands().size() != 2UL)
      return exprt(ID_empty);
    return find_taint_expression(expr.op0());
  }
  for(exprt::operandst::const_iterator it = expr.operands().begin();
      it != expr.operands().end();
      ++it)
  {
    exprt const  retval = taint_find_expression_of_rule(*it);
    if (retval != exprt(ID_empty))
      return retval;
  }
  return exprt(ID_empty);
}


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
    goto_programt::const_targett const source_instruction,
    std::string const&  sink_function_name,
    goto_programt::const_targett const sink_instruction,
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
            "    <td>" << to_html_text(source_function_name) << "</td>\n"
            "    <td>" << source_instruction->location_number << "</td>\n"
            "    <td>" << to_html_text(taint_name) << "</td>\n"
            "    <td>" << to_html_text(sink_function_name) << "</td>\n"
            "    <td>" << sink_instruction->location_number << "</td>\n"
            "  </tr>\n"
            "</table>\n"
            ;

  call_grapht  inverted_call_graph;
  compute_inverted_call_graph(call_graph,inverted_call_graph);

  if (source_function_name != sink_function_name)
  {
    std::unordered_set<irep_idt,dstring_hash>  call_roots;
    find_leaves_bellow_function(
          inverted_call_graph,
          source_function_name,
          call_roots
          );
    bool  may_path_exist = false;
    for (auto const& root_fn_name : call_roots)
      if (exists_direct_or_indirect_call(
              call_graph,
              root_fn_name,
              sink_function_name
              ))
      {
        may_path_exist = true;
        break;
      }
    if (may_path_exist == false)
    {
      if (log != nullptr)
        *log << "<p>The sink function is call-graph unreachable from the "
                "source function. So, terminating immediatelly.</p>\n"
                ;
      return;
    }
  }

  namespacet const  ns(goto_model.symbol_table);

  std::deque<trace_under_constructiont>  processed_traces;
  {
    taint_map_from_lvalues_to_svaluest  from_lvalues_to_svalues;
    {
      taint_summary_domain_ptrt const  domain =
          summaries.find<taint_summaryt>(
              source_function_name
              )->domain();
      assert(domain.operator bool());
      for (auto const&  lvalue_svalue : domain->at(source_instruction))
        if (lvalue_svalue.second.expression().count(taint_name) != 0UL)
          from_lvalues_to_svalues.insert({
              lvalue_svalue.first,
              { {taint_name}, false, false}
              });
    }
    processed_traces.push_back(trace_under_constructiont{
            {
              source_function_name,
              source_instruction,
              from_lvalues_to_svalues,
              { taint_name },
              ""
            },
            {taint_name}
        });
  }
  while (!processed_traces.empty())
  {
    trace_under_constructiont&  trace = processed_traces.front();
    taint_trace_elementt const&  elem = trace.back();

    if (elem.get_name_of_function() == sink_function_name &&
        elem.get_instruction_iterator() == sink_instruction)
    {
      bool  is_taint_expression_tainted = false;
      {
        exprt const  taint_expr =
            taint_find_expression_of_rule(sink_instruction->guard);
        taint_summary_domain_ptrt const  domain =
            summaries.find<taint_summaryt>(
                elem.get_name_of_function()
                )->domain();
        assert(domain.operator bool());
        taint_map_from_lvalues_to_svaluest const&  lvalue_svalue =
            domain->at(elem.get_instruction_iterator());
        auto const it = lvalue_svalue.find(taint_expr);
        if (it != lvalue_svalue.cend())
        {
          for (auto const&  symbol : it->second.expression())
            if (trace.stack_top().second.count(symbol) != 0UL)
            {
              is_taint_expression_tainted = true;
              break;
            }
        }
      }
      if (is_taint_expression_tainted)
      {
        output_traces.push_back(trace.get_trace());
        processed_traces.pop_front();

        if (log != nullptr)
        {
          *log << "<p>There is added the following trace into the output:</p>\n"
                  "<table>"
                  "  <tr>\n"
                  "    <th>Function</th>\n"
                  "    <th>Location</th>\n"
                  "    <th>Variables</th>\n"
                  "    <th>Symbols</th>\n"
                  "    <th>Message</th>\n"
                  "    <th>Line</th>\n"
                  "    <th>File</th>\n"
                  "    <th>Comment</th>\n"
                  "  </tr>\n"
                  ;
          for (taint_trace_elementt const&  element : output_traces.back())
          {
              *log << "  <tr>\n"
                      "    <td>"
                   << to_html_text(element.get_name_of_function()) << "</td>\n"
                      "    <td>"
                   << element.get_instruction_iterator()->location_number
                   << "</td>\n"
                      ;
              *log << "    <td>\n";
              taint_dump_lvalues_to_svalues_in_html(
                    element.get_map_from_lvalues_to_svalues(),
                    ns,
                    *log
                    );
              *log << "    </td>\n"
                      "    <td>\n";
              taint_dump_svalue_in_html(
                  {element.get_symbols(),false,false},
                  *log
                  );
              *log << "    </td>\n"
                      "    <td>" << to_html_text(element.get_message())
                   << "</td>\n"
                      "    <td>" << element.get_line()
                   << "</td>\n"
                      "    <td>" << to_html_text(element.get_file())
                   << "</td>\n"
                      "    <td>" << to_html_text(element.get_code_annotation())
                   << "</td>\n"
                      "  </tr>\n";
          }
          *log << "</table>";
        }
      }
      else
      {
        processed_traces.pop_front();

        if (log != nullptr)
          *log << "<p>No trace is generates as the taint symbol '"
               << taint_name << "' did not reach the sink.</p>\n";
      }
    }
    else if (elem.get_instruction_iterator()->type == FUNCTION_CALL)
    {
      code_function_callt const&  fn_call =
          to_code_function_call(elem.get_instruction_iterator()->code);
      if (fn_call.function().id() == ID_symbol)
      {
        std::string const  callee_ident =
            as_string(to_symbol_expr(fn_call.function()).get_identifier());

        taint_map_from_lvalues_to_svaluest  from_lvalues_to_svalues;
        std::unordered_set<std::string>  symbols;
        {
          taint_summary_domain_ptrt const  domain =
              summaries.find<taint_summaryt>(
                  elem.get_name_of_function()
                  )->domain();
          assert(domain.operator bool());
          taint_map_from_lvalues_to_svaluest const&  lvalue_svalue =
              domain->at(elem.get_instruction_iterator());

          code_typet const&  callee_type =
              goto_model.goto_functions.function_map.at(callee_ident).type;
          taint_map_from_lvalues_to_svaluest const&  callee_symbol_map =
              summaries.find<taint_summaryt>(callee_ident)->input();

          for (auto const&  callee_lvalue_svalue : callee_symbol_map)
            if (is_static(callee_lvalue_svalue.first,ns))
            {
              auto const it = lvalue_svalue.find(callee_lvalue_svalue.first);
              if (it != lvalue_svalue.cend())
              {
                taint_svaluet::expressiont  symbols_intersection;
                std::set_intersection(
                      it->second.expression().cbegin(),
                      it->second.expression().cend(),
                      trace.stack_top().second.cbegin(),
                      trace.stack_top().second.cend(),
                      std::inserter(symbols_intersection,
                                    symbols_intersection.begin())
                      );
                if (!symbols_intersection.empty())
                {
                  from_lvalues_to_svalues.insert({
                        callee_lvalue_svalue.first,
                        { symbols_intersection, false, false }
                        });
                  symbols.insert(
                      callee_lvalue_svalue.second.expression().cbegin(),
                      callee_lvalue_svalue.second.expression().cend()
                      );
                }
              }
            }

          for (std::size_t  i = 0UL;
               i < std::min(fn_call.arguments().size(),
                            callee_type.parameters().size());
               ++i)
          {
            set_of_access_pathst  paths;
            collect_access_paths(fn_call.arguments().at(i),ns,paths);
            for (auto const&  path : paths)
            {
              auto const  svalue_it = lvalue_svalue.find(path);
              if (svalue_it != lvalue_svalue.cend())
                for (auto const&  symbol : svalue_it->second.expression())
                  if (trace.stack_top().second.count(symbol) != 0UL)
                  {
                    std::string const  param_name =
                        as_string(callee_type.parameters()
                                             .at(i)
                                             .get_identifier() );
                    for (auto const& lvalue_svalue : callee_symbol_map)
                      if (is_parameter(lvalue_svalue.first,ns)
                            && name_of_symbol_access_path(lvalue_svalue.first)
                               == param_name)
                      {
                        from_lvalues_to_svalues.insert(lvalue_svalue);
                        symbols.insert(
                            lvalue_svalue.second.expression().cbegin(),
                            lvalue_svalue.second.expression().cend()
                            );
                      }
                  }
            }
          }
        }
        if (symbols.empty())
        {
          // The callee is not involved in propagation of tainted symbol.
          // So we skip over it (i.e. we do not step into).
          std::vector<taint_trace_elementt>  successors;
          taint_collect_successors_inside_function(
                goto_model,
                trace,
                elem,
                summaries,
                taint_name,
                sink_function_name,
                sink_instruction,
                successors,
                log
                );
          if (successors.empty())
            processed_traces.pop_front();
          else
          {
            assert(successors.size() == 1UL);
            processed_traces.front().push_back(successors.front());
          }
        }
        else
        {
          // The callee is involved in propagation of tainted symbol.
          // So, we step into it.
          symbols.insert(
                trace.stack_top().second.cbegin(),
                trace.stack_top().second.cend()
                );
          trace.stack_push(symbols);
          trace.push_back({
                callee_ident,
                goto_model.goto_functions
                          .function_map.at(callee_ident)
                          .body
                          .instructions
                          .cbegin(),
                from_lvalues_to_svalues,
                taint_svaluet::expressiont(
                    symbols.cbegin(),
                    symbols.cend()
                    ),
                ""
                });
        }
      }
      else
      {
        // TODO: Now we step over the call site without entering callees!
        std::vector<taint_trace_elementt>  successors;
        taint_collect_successors_inside_function(
              goto_model,
              trace,
              elem,
              summaries,
              taint_name,
              sink_function_name,
              sink_instruction,
              successors,
              log
              );
        if (successors.empty())
          processed_traces.pop_front();
        else
        {
          assert(successors.size() == 1UL);
          processed_traces.front().push_back(successors.front());
        }
      }
    }
    else if (elem.get_instruction_iterator()->type == END_FUNCTION)
    {
      if (trace.stack_has_return())
      {
        std::size_t const  call_index = trace.stack_top().first;
        trace.stack_pop();

        std::vector<taint_trace_elementt>  successors;
        taint_collect_successors_inside_function(
              goto_model,
              trace,
              trace.at(call_index),
              summaries,
              taint_name,
              sink_function_name,
              sink_instruction,
              successors,
              log
              );
        if (successors.empty())
          processed_traces.pop_front();
        else
        {
          assert(successors.size() == 1UL);
          processed_traces.front().push_back(successors.front());
        }
      }
      else
      {
        std::unordered_set<std::string>  stack_symbols(
              elem.get_symbols().cbegin(),
              elem.get_symbols().cend()
              );
        {
          taint_map_from_lvalues_to_svaluest const&  symbol_map =
              summaries.find<taint_summaryt>(elem.get_name_of_function())
                       ->input();
          for (auto const&  lvalue_svalue : symbol_map)
            for (auto const&  symbol : lvalue_svalue.second.expression())
              stack_symbols.erase(symbol);
        }
        trace.stack_set_top(stack_symbols);

        std::set< std::pair<std::string,goto_programt::const_targett> >
            possible_callers;
        {
          call_grapht::call_edges_ranget const  range =
              inverted_call_graph.out_edges(elem.get_name_of_function());
          for (auto  it = range.first; it != range.second; ++it)
          {
            goto_functionst::goto_functiont const&  fn =
                goto_model.goto_functions.function_map.at(it->second);
            for (auto  inst_it = fn.body.instructions.cbegin();
                 inst_it != fn.body.instructions.cend();
                 ++inst_it)
              if (inst_it->type == FUNCTION_CALL)
              {
                code_function_callt const&  fn_call =
                    to_code_function_call(inst_it->code);
                if (fn_call.function().id() == ID_symbol)
                {
                  std::string const  callee_ident =
                      as_string(
                          to_symbol_expr(fn_call.function()).get_identifier()
                          );
                  if (callee_ident == elem.get_name_of_function())
                    possible_callers.insert({as_string(it->second),inst_it});
                }
              }
          }
        }
        for (auto const&  func_loc : possible_callers)
        {
          taint_map_from_lvalues_to_svaluest const&  from_lvalues_to_svalues =
              summaries.find<taint_summaryt>(func_loc.first)
                       ->domain()
                       ->at(func_loc.second);
          std::vector<taint_trace_elementt>  successors;
          taint_collect_successors_inside_function(
                goto_model,
                trace,
                taint_trace_elementt(
                    func_loc.first,
                    func_loc.second,
                    from_lvalues_to_svalues,
                    taint_svaluet::expressiont(
                        stack_symbols.cbegin(),
                        stack_symbols.cend()
                        ),
                    ""
                    ),
                summaries,
                taint_name,
                sink_function_name,
                sink_instruction,
                successors,
                log
                );
          for (taint_trace_elementt const&  succ_elem : successors)
          {
            processed_traces.push_back(processed_traces.front());
            processed_traces.back().push_back(succ_elem);
          }
        }
        processed_traces.pop_front();
      }
    }
    else
    {
      std::vector<taint_trace_elementt>  successors;
      taint_collect_successors_inside_function(
            goto_model,
            trace,
            elem,
            summaries,
            taint_name,
            sink_function_name,
            sink_instruction,
            successors,
            log
            );
      if (successors.empty())
        processed_traces.pop_front();
      else
      {
        for (std::size_t  i = 1UL; i < successors.size(); ++i)
        {
          processed_traces.push_back(processed_traces.front());
          processed_traces.back().push_back(successors.at(i));
        }
        processed_traces.front().push_back(successors.front());
      }
    }
  }
}
