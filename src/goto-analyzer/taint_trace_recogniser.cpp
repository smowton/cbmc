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
#include <goto-analyzer/taint_statistics.h>
#include <util/parameter_indices.h>
#include <util/msgstream.h>
#include <unordered_set>
#include <deque>
#include <limits>
#include <algorithm>
#include <iterator>
#include <cassert>

#include <iostream>

static const namespacet* global_ns;

static void  dump_trace(taint_tracet const&  trace,
                        std::string const&  purpose,
                        namespacet const&  ns,
                        std::stringstream* const  log
                        )
{
  assert(log != nullptr);
  *log << "<p>" << purpose << ":</p>\n"
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
  for (taint_trace_elementt const&  element : trace)
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
            {}/*TODO*/,
            *log
            );
      *log << "    </td>\n"
              "    <td>\n";
      taint_dump_svalue_in_html(
          {element.get_symbols(),false,false},
          {}, // TODO: here should be propagated and used instance of:
              //     taint_svalue_symbols_to_specification_symbols_mapt
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
}

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
              std::unordered_set<taint_svaluet::taint_symbolt> //!< A set of symbols representing
                                                               //!< the tainted symbol in the
                                                               //!< called function.
              >
          call_stack_valuet;

  typedef std::vector<call_stack_valuet>
          call_stackt;

  struct backtrack_statet {
    size_t trace_size;
    call_stackt call_stack;
  };

  explicit trace_under_constructiont(
      taint_trace_elementt const&  element,
      std::unordered_set<taint_svaluet::taint_symbolt> const&  symbols
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
  void  stack_push(std::unordered_set<taint_svaluet::taint_symbolt> const&  symbols);
  void  stack_set_top(std::unordered_set<taint_svaluet::taint_symbolt> const&  symbols);
  void  stack_pop();

  backtrack_statet get_backtrack_state() { return { trace.size(), call_stack }; }
  void backtrack_to_state(const backtrack_statet& state);

private:
  taint_tracet  trace;
  visited_locations_mapt  visited;
  call_stackt  call_stack;
};

struct backtracking_trace_constructiont {

  std::vector<std::pair<trace_under_constructiont::backtrack_statet, taint_trace_elementt> >
    pending_backtracks;
  std::vector<std::pair<trace_under_constructiont::backtrack_statet, taint_trace_elementt> >
    pending_call_backtracks;
  trace_under_constructiont trace;
  bool done;

  backtracking_trace_constructiont(const taint_trace_elementt& first_elem, unsigned long first_taint) : trace(first_elem, { first_taint }), done(false) {}
  
  void backtrack()
  {
    if((!pending_backtracks.size()) && (!pending_call_backtracks.size()))
    {
      done=true;
      return;
    }
    auto& take_from=pending_backtracks.size() ? pending_backtracks : pending_call_backtracks;
    const auto& backtrack_to=take_from.back();
    trace.backtrack_to_state(backtrack_to.first);
    trace.push_back(backtrack_to.second);
    take_from.pop_back();
  }

  void add_pending_backtrack(const taint_trace_elementt& add_element, bool is_call)
  {
    auto& add_to=is_call ? pending_call_backtracks : pending_backtracks;
    add_to.push_back(std::make_pair(trace.get_backtrack_state(),add_element));
  }

  bool can_backtrack() { return pending_backtracks.size()!=0 || pending_call_backtracks.size()!=0; }

};

trace_under_constructiont::trace_under_constructiont(
    taint_trace_elementt const&  element,
    std::unordered_set<taint_svaluet::taint_symbolt> const&  symbols
    )
  : trace{element}
  , visited{}
  , call_stack{{std::numeric_limits<std::size_t>::max(),symbols}}
{}

void trace_under_constructiont::backtrack_to_state(const backtrack_statet& state)
{
  call_stack=state.call_stack;
  assert(state.trace_size <= trace.size());
  for(size_t idx=state.trace_size, idxlim=trace.size(); idx!=idxlim; ++idx)
  {
    const auto& fname=trace.at(idx).get_name_of_function();
    const auto& institer=trace.at(idx).get_instruction_iterator();
    assert(visited.at(fname).erase(institer->location_number));
  }
  // Use this method because trace_elementt doesn't have a nullary constructor:
  auto erase_from_it=std::next(trace.begin(),state.trace_size);
  trace.erase(erase_from_it,trace.end());
}

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
    std::unordered_set<taint_svaluet::taint_symbolt> const&  symbols
    )
{
  assert(!empty());
  assert(!symbols.empty());
  call_stack.push_back({trace.size() - 1UL,symbols});
}

void  trace_under_constructiont::stack_set_top(
    std::unordered_set<taint_svaluet::taint_symbolt> const&  symbols
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
    taint_svaluet::taint_symbolt const&  taint_name,
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
	const auto& summary=*summaries.find<taint_summaryt>(elem.get_name_of_function());
        const auto& domain=summary.domain();
	const auto& numbering=summary.domain_numbering();
	for (auto const&  lvalue_svalue : domain.at(succ_target))
        {
          taint_svaluet::expressiont  symbols;
          for (auto const&  symbol : lvalue_svalue.second.expression())
            if (trace.stack_top().second.count(symbol) != 0UL)
              symbols.insert(symbol);
          if (!symbols.empty())
            from_lvalues_to_svalues.insert({
                numbering[lvalue_svalue.first],
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

static void populate_distances_to_node(const call_grapht& inverted_cg,
				       irep_idt fromnode,
				       std::map<irep_idt, size_t>& result)
{
  // inverted_cg, as its name suggests, is the call graph with edges pointing from callee
  // to caller. Populate 'result' with the smallest number of calls to reach 'fromnode'.
  // Walk breadth-first to ensure finding the shortest path first (when all edges have cost 1)

  std::vector<irep_idt> worklist;
  result[fromnode]=0;
  worklist.push_back(fromnode);
  for(size_t i=0; i!=worklist.size(); ++i)
  {
    auto thiscost=result.at(worklist[i]);
    auto edges=inverted_cg.out_edges(worklist[i]);
    for(; edges.first!=edges.second; ++edges.first)
    {
      const auto& callername=edges.first->second;
      auto insit=result.insert(std::make_pair(callername,thiscost+1));
      if(insit.second)
	worklist.push_back(callername);
      // Otherwise there is already a shorter path.
    }
  }
}

static bool root_cost_lt(const std::pair<instruction_iteratort,size_t>& a,
			 const std::pair<instruction_iteratort,size_t>& b)
{
  return a.second<b.second;
}

static void populate_local_distances_to_taint_sink(
  const goto_programt& prog,
  std::map<instruction_iteratort, size_t>& costs,
  const std::map<irep_idt, size_t>& call_cost_to_sink,
  size_t return_cost_to_sink)
{
  // Calls with a path to the taint sink, and the function end, have costs given
  // by call_cost_to_sink and return_cost_to_sink respectively. All other instructions
  // get a shortest path length (measured in instructions) to reach the nearest sink.

  std::map<instruction_iteratort, std::list<instruction_iteratort> > preds;
  for(auto it=prog.instructions.begin(),itend=prog.instructions.end(); it!=itend; ++it)
  {
    std::list<instruction_iteratort> succs;
    prog.get_successors(it,succs);
    for(auto succ : succs)
      preds[succ].push_back(it);    
  }
  
  std::vector<instruction_iteratort> worklist;
  std::vector<std::pair<instruction_iteratort,size_t> > roots;

  // call_ and return_cost_to_sink measure cost in number of calls
  // whereas we measure instructions. Use a guess of 20 instructions
  // traversed per function for now (consider improving this later).
  if(return_cost_to_sink != (size_t)-1)
    roots.push_back({std::prev(prog.instructions.end()),return_cost_to_sink*20});

  for(auto it=prog.instructions.begin(),itend=prog.instructions.end(); it!=itend; ++it)
  {
    if(it->type==FUNCTION_CALL)
    {
      const auto& callee=to_code_function_call(it->code).function();
      if(callee.id()==ID_symbol)
      {
	auto findit=call_cost_to_sink.find(to_symbol_expr(callee).get_identifier());
	if(findit!=call_cost_to_sink.end())
	  roots.push_back({it,(findit->second)*20});
      }
    }
  }

  if(roots.empty())
    return;
  
  std::sort(roots.begin(),roots.end(),root_cost_lt);

  worklist.push_back(roots[0].first);
  costs[roots[0].first]=roots[0].second;
  size_t rootidx=1;

  // Roots are kept out of the map such that only instructions with their final cost
  // appear in the result map at any point.
  // Since all costs are one instruction, we can do a simple breadth-first, cheapest-root-first
  // walk to assign costs:

  for(size_t i=0;i!=worklist.size();++i)
  {
    const instruction_iteratort* thisinstp=&worklist[i];
    auto thiscost=costs.at(*thisinstp);
    // See if a root has lower cost than this worklist entry; if so process it first:
    if(rootidx<roots.size())
    {
      const auto& nextroot=roots[rootidx];
      if(nextroot.second==thiscost && !costs.count(nextroot.first))
      {
	if(costs.insert(nextroot).second)
	{
	  --i;
	  thisinstp=&nextroot.first;
	  thiscost=nextroot.second;
	}
	++rootidx;
	// Otherwise we already encountered the root with lower cost by another path.
      }
    }

    const auto& thisinst=*thisinstp;
    auto findpred=preds.find(thisinst);
    if(findpred!=preds.end())
    {
      const auto& instpreds=findpred->second;
      for(const auto& pred : instpreds)
      {
	auto insit=costs.insert({pred,thiscost+1});
	if(insit.second)
	  worklist.push_back(pred);
	// Otherwise we already found a shorter path for this instruction.
      }
    }
  }
}
				      

void taint_recognise_error_traces(
    std::vector<taint_tracet>&  output_traces,
    goto_modelt const&  goto_model,
    call_grapht const&  call_graph,
    database_of_summariest const&  summaries,
    taint_sources_mapt const&  taint_sources,
    taint_sinks_mapt const&  taint_sinks,
    taint_object_numbering_per_functiont&  taint_object_numbering,
    object_numbers_by_field_per_functiont&  object_numbers_by_field,
    const formals_to_actuals_mapt& formals_to_actuals,
    std::stringstream* const  log
    )
{
  if (log != nullptr)
    *log << "<h2>Building taint error traces</h2>\n";

  taint_statisticst::instance().begin_error_traces_recognition();

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
                    taint_object_numbering,
                    object_numbers_by_field,
		    formals_to_actuals,
                    log
                    );
      }

  taint_statisticst::instance().end_error_traces_recognition();
}


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
    const formals_to_actuals_mapt& formals_to_actuals,
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
            "    <td>" << to_html_text(i2string(taint_name)) << "</td>\n"
            "    <td>" << to_html_text(sink_function_name) << "</td>\n"
            "    <td>" << sink_instruction->location_number << "</td>\n"
            "  </tr>\n"
            "</table>\n"
            ;

  call_grapht  inverted_call_graph;
  compute_inverted_call_graph(call_graph,inverted_call_graph);

  // Get functions that can reach the taint source, and their distances:
  std::map<irep_idt, size_t> function_downward_distances_to_source;
  populate_distances_to_node(inverted_call_graph,source_function_name,
			     function_downward_distances_to_source);
  // Same but for the sink:
  std::map<irep_idt, size_t> function_downward_distances_to_sink;
  populate_distances_to_node(inverted_call_graph,sink_function_name,
			     function_downward_distances_to_sink);
  // Get functions reachable from something that can reach the sink:
  std::map<irep_idt, size_t> function_upward_distances_to_sink;
  for(const auto& fun : function_downward_distances_to_sink)
  {
    std::map<irep_idt, size_t> distance_from_this_root;
    populate_distances_to_node(call_graph,fun.first,distance_from_this_root);
    for(const auto& dist : distance_from_this_root)
    {
      auto cost=dist.second+fun.second;
      auto insertit=function_upward_distances_to_sink.insert({dist.first,cost});
      if((!insertit.second) && cost<insertit.first->second)
	insertit.first->second=cost;
    }
  }

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
      if (as_string(root_fn_name) == sink_function_name ||
          exists_direct_or_indirect_call(
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
  global_ns=&ns;
  taint_map_from_lvalues_to_svaluest  from_lvalues_to_svalues;
  {
    {
      const auto& summary=*summaries.find<taint_summaryt>(source_function_name);
      const auto& domain=summary.domain();
      const auto& numbering=summary.domain_numbering();
      for (const auto& lvalue_svalue : domain.at(source_instruction))
        if (lvalue_svalue.second.expression().count(taint_name) != 0UL)
          from_lvalues_to_svalues.insert({
              numbering[lvalue_svalue.first],
              { {taint_name}, false, false}
              });
    }
  }

  taint_trace_elementt initial_elem=
    {
       source_function_name,
       source_instruction,
       from_lvalues_to_svalues,
       { taint_name },
       ""
    };
  backtracking_trace_constructiont bt_trace(initial_elem,taint_name);

  // Entries with key.second set are used when a function has a stack (i.e. when returning
  // to get towards the sink is not viable because our caller already decided to enter
  // this function).
  std::map<std::pair<irep_idt,bool>, std::map<instruction_iteratort, size_t> >
    local_costs_to_reach_sink;

  while (!bt_trace.done)
  {
    trace_under_constructiont&  trace = bt_trace.trace;
    taint_trace_elementt const&  elem = trace.back();
    const auto& local_numbering=taint_object_numbering.at(elem.get_name_of_function());

    std::cout << trace.get_trace().size() << " " << elem.get_name_of_function() << " " << from_expr(ns,"",elem.get_instruction_iterator()->code) << "\n";

    if(trace.get_trace().size()==255)
    {
      std::cout << "HERE\n";
    }
    
    if (elem.get_name_of_function() == sink_function_name &&
        elem.get_instruction_iterator() == sink_instruction)
    {
      bool  is_taint_expression_tainted = false;
      {
        exprt const  taint_expr =
            taint_find_expression_of_rule(sink_instruction->guard);
	const auto& summary=*summaries.find<taint_summaryt>(elem.get_name_of_function());
	const auto& domain=summary.domain();
	const auto& numbering=summary.domain_numbering();
        const auto& lvalue_svalue =
            domain.at(elem.get_instruction_iterator());
	object_numberingt::number_type taint_num;
	bool missing=numbering.get_number(taint_expr,taint_num);
	const auto it=
	  (missing) ?
	  lvalue_svalue.end() :
	  lvalue_svalue.find(taint_num);
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
	std::cout << "BACKTRACK: successful trace (looking for alternatives)\n";
	bt_trace.backtrack();

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
                    {}/*TODO*/,
                    *log
                    );
              *log << "    </td>\n"
                      "    <td>\n";
              taint_dump_svalue_in_html(
                  {element.get_symbols(),false,false},
                  {}, // TODO: here should be propagated and used instance of:
                      //     taint_svalue_symbols_to_specification_symbols_mapt
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
        if (log != nullptr)
          dump_trace(trace.get_trace(),
                     "Skipping the following explored path",
                     ns,
                     log);
	std::cout << "BACKTRACK: sink without appropriate taint\n";
	bt_trace.backtrack();

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
        std::unordered_set<taint_svaluet::taint_symbolt>  symbols;
        {
	  const auto& summary=*summaries.find<taint_summaryt>(elem.get_name_of_function());
	  const auto& domain=summary.domain();
          const auto& lvalue_svalue =
	    domain.at(elem.get_instruction_iterator());
	  const auto& numbering=summary.domain_numbering();

          const code_typet& callee_type=
              goto_model.goto_functions.function_map.at(callee_ident).type;

          auto const taint_summary_ptr =
              summaries.find<taint_summaryt>(callee_ident);


          if (taint_summary_ptr.operator bool())
          {
            const auto& callee_symbol_map= taint_summary_ptr->input();
	    auto param_indices=get_parameter_indices(callee_type);
	    
	    for (auto const&  callee_lvalue_svalue : callee_symbol_map)
            {
              {
                std::set<taint_svaluet::taint_symbolt>
                    collected_symbols;
                {
                  taint_numbered_lvalues_sett  argument_lvalues;

		  if(is_parameter(callee_lvalue_svalue.first,ns))
		  {
		    // Replace with actual(s):
		    const auto& actuals_list=
		      formals_to_actuals.at({elem.get_name_of_function(),
			                     elem.get_instruction_iterator()});
		    const auto& paramsym=
		      to_symbol_expr(callee_lvalue_svalue.first).get_identifier();
		    
		    for(const auto number : actuals_list[param_indices[paramsym]])
		    {
		      std::cout << "Actual parameter for " << from_expr(ns,"",callee_lvalue_svalue.first) << ": " << from_expr(ns,"",local_numbering[number]) << "\n";
		      argument_lvalues.insert(number);
		    }
		  }
		  else
		  {
		    // Find number, and expand external object references if necessary:
		    unsigned number;
		    assert(!local_numbering.get_number(callee_lvalue_svalue.first,number));
		    argument_lvalues.insert(number);
		    expand_external_objects(
			argument_lvalues,
			object_numbers_by_field[elem.get_name_of_function()],
                        local_numbering);
		  }
                  for (auto const  number : argument_lvalues)
                  {
                    auto const lvalue_it = lvalue_svalue.find(number);
                    if (lvalue_it != lvalue_svalue.cend())
                    {
                      for (auto const  symbol : lvalue_it->second.expression())
                        collected_symbols.insert(symbol);
                    }
                  }
                }

                taint_svaluet::expressiont  symbols_intersection;
                std::set_intersection(
                      collected_symbols.cbegin(),
                      collected_symbols.cend(),
                      trace.stack_top().second.cbegin(),
                      trace.stack_top().second.cend(),
                      std::inserter(symbols_intersection,
                                    symbols_intersection.begin())
                      );
                if (!symbols_intersection.empty())
                {
                  symbols_intersection.insert(
                        callee_lvalue_svalue.second.expression().cbegin(),
                        callee_lvalue_svalue.second.expression().cend()
                        );
                  from_lvalues_to_svalues.insert(callee_lvalue_svalue);
                  symbols.insert(
                      symbols_intersection.cbegin(),
                      symbols_intersection.cend()
                      );
                }
              }
              if (is_static(callee_lvalue_svalue.first,ns))
              {
		object_numberingt::number_type lvalue_number;
                auto const it =
		  numbering.get_number(callee_lvalue_svalue.first,lvalue_number) ?
		  lvalue_svalue.cend() :
		  lvalue_svalue.find(lvalue_number);
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
            }
          }
        }

	bool already_visited=false;
	const auto& target_fun=goto_model.goto_functions.function_map.at(callee_ident);
	if(!target_fun.body.instructions.empty())
	  already_visited=trace.count(callee_ident,target_fun.body.instructions.cbegin());
	
        if (symbols.empty() || already_visited)
        {
          // The callee is not involved in propagation of tainted symbol,
	  // or has already been explored.
          // Therefore we skip over it (i.e. we do not step into).
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
          {
            if (log != nullptr)
              dump_trace(trace.get_trace(),
                         "Skipping the following explored path",
                         ns,
                         log);
	    std::cout << "BACKTRACK: uninteresting call, no successors\n";
	    bt_trace.backtrack();
          }
          else
          {
            assert(successors.size() == 1UL);
            trace.push_back(successors.front());
          }
        }
        else
        {
          // The callee is involved in propagation of tainted symbol.
          // So, we may step into it.
          symbols.insert(
	    trace.stack_top().second.cbegin(),
	    trace.stack_top().second.cend());

	  // Check if it is desirable to enter this function: does it get us closer
	  // to the sink?
	  bool callee_is_closer=false;
	  auto findit=function_downward_distances_to_sink.find(callee_ident);
	  if(findit!=function_downward_distances_to_sink.end())
	  {
	    size_t mycost=10000;
	    auto findit2=function_downward_distances_to_sink.find(elem.get_name_of_function());
	    if(findit2!=function_downward_distances_to_sink.end())
	      mycost=std::min(findit2->second,mycost);
	    if(!trace.stack_has_return())
	    {
	      // See if just returning is a faster way to the sink:
	      auto findit3=function_upward_distances_to_sink.find(elem.get_name_of_function());
	      if(findit3!=function_downward_distances_to_sink.end())
		mycost=std::min(findit3->second,mycost);		
	    }
	    callee_is_closer=(mycost > findit->second);
	    std::cout << "*** Callee " << callee_ident << " cost " << findit->second << " vs. skip cost " << mycost << "\n";
	  }
	  else
	    std::cout << "*** Callee " << callee_ident << " not on path to sink\n";

	  const auto& fstart=goto_model.goto_functions.function_map.at(callee_ident)
	    .body.instructions.cbegin();
	  taint_trace_elementt new_element {
	    callee_ident,
	    fstart,
	    from_lvalues_to_svalues,
	    taint_svaluet::expressiont(symbols.cbegin(),symbols.cend()),
            ""
	  };

          trace.stack_push(symbols);

	  if(callee_is_closer)
	  {
	    // Enter function right away:
	    trace.push_back(new_element);
	  }
	  else
	  {
	    // First try bypassing the function:
	    bt_trace.add_pending_backtrack(new_element,true);
	    trace.stack_pop();
	    // TODO: factor this.
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
	    {
	      if (log != nullptr)
		dump_trace(trace.get_trace(),
			   "Skipping the following explored path",
			   ns,
			   log);
	      std::cout << "BACKTRACK: interesting call, no successors\n";
	      bt_trace.backtrack();
	    }
	    else
	    {
	      assert(successors.size() == 1UL);
	      trace.push_back(successors.front());
	    }
	  }
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
        {
          if (log != nullptr)
            dump_trace(trace.get_trace(),
                       "Skipping the following explored path",
                       ns,
                       log);
	  std::cout << "BACKTRACK: call without summary, no successors\n";
          bt_trace.backtrack();
        }
        else
        {
          assert(successors.size() == 1UL);
          trace.push_back(successors.front());
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
        {
          if (log != nullptr)
            dump_trace(trace.get_trace(),
                       "Skipping the following explored path",
                       ns,
                       log);
	  std::cout << "BACKTRACK: function end (have stack) with no successors\n";
          bt_trace.backtrack();
        }
        else
        {
          assert(successors.size() == 1UL);
          trace.push_back(successors.front());
        }
      }
      else
      {
        std::unordered_set<taint_svaluet::taint_symbolt>  stack_symbols(
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

	// When we have a choice of callees, pick first the one that gets closer to
	// reaching a taint sink.
	
	std::vector<std::pair<std::string,goto_programt::const_targett> > sorted_callers(
	  possible_callers.begin(),possible_callers.end());
	struct compare_costs {
	  typedef std::pair<std::string,goto_programt::const_targett> keyt;
	  const std::map<irep_idt, size_t>& costs;
	  compare_costs(const std::map<irep_idt, size_t>& _costs) : costs(_costs) {}
	  bool operator()(const keyt& l, const keyt& r) const
	  {
	    const auto findl=costs.find(l.first), findr=costs.find(r.first);
	    if(findl==costs.end())
	      return false;
	    if(findr==costs.end())
	      return true;
	    return findl->second<findr->second;
	  }
	};

	compare_costs comp(function_upward_distances_to_sink);
	std::sort(sorted_callers.begin(),sorted_callers.end(),comp);

	std::cout << "*** Return costs:\n";
	for(const auto& caller : sorted_callers)
	  std::cout << caller.first << " cost " << (function_upward_distances_to_sink.count(caller.first) ? function_upward_distances_to_sink[caller.first] : 10000) << "\n";
	
        for (auto callerit=sorted_callers.rbegin(), callerend=sorted_callers.rend();
	     callerit!=callerend; ++callerit)
        {
	  const auto& func_loc=*callerit;
          auto const  summary_ptr =
              summaries.find<taint_summaryt>(func_loc.first);
          if (!summary_ptr.operator bool())
            continue;
	  const auto& summary=*summary_ptr;
          const auto& from_lvalues_to_svalues=summary.domain().at(func_loc.second);
	  const auto& numbering=summary.domain_numbering();
	  taint_map_from_lvalues_to_svaluest explicit_domain;
	  for(const auto& kv : from_lvalues_to_svalues)
	    explicit_domain.insert({numbering[kv.first],kv.second});
	  
          std::vector<taint_trace_elementt>  successors;
          taint_collect_successors_inside_function(
                goto_model,
                trace,
                taint_trace_elementt(
                    func_loc.first,
                    func_loc.second,
                    explicit_domain,
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
	    bt_trace.add_pending_backtrack(succ_elem,false);
          }
        }

        if ((!bt_trace.can_backtrack()) && log != nullptr)
          dump_trace(trace.get_trace(),
                     "Skipping the following explored path",
                     ns,
                     log);
	if(!bt_trace.can_backtrack())
	  std::cout << "BACKTRACK: function end, no callers\n";

	bt_trace.backtrack();
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
      {
        if (log != nullptr)
          dump_trace(trace.get_trace(),
                     "Skipping the following explored path",
                     ns,
                     log);
	std::cout << "BACKTRACK: Normal inst no successors\n";
	bt_trace.backtrack();
      }
      else
      {

	if(successors.size()>1)
	{

	  bool have_definite_caller=trace.stack_has_return();
	  const auto& thisfun=irep_idt(elem.get_name_of_function());
	  auto insit=local_costs_to_reach_sink.insert({{thisfun,have_definite_caller},{}});
	  if(insit.second)
	  {
	    const auto& fn = goto_model.goto_functions.function_map.at(thisfun);
	    auto return_cost=have_definite_caller ?
	      10000 : function_upward_distances_to_sink.at(thisfun);
	    populate_local_distances_to_taint_sink(fn.body,insit.first->second,
						   function_downward_distances_to_sink,
						   return_cost);
	  }

	  struct compare_local_costs {
	    const std::map<instruction_iteratort, size_t>& costs;
	    compare_local_costs(const std::map<instruction_iteratort, size_t>& _costs) :
	      costs(_costs) {}
	    bool operator()(const taint_trace_elementt& l, const taint_trace_elementt& r) const
	    {
	      const auto findl=costs.find(l.get_instruction_iterator()),
		findr=costs.find(r.get_instruction_iterator());
	      if(findl==costs.end())
		return false;
	      if(findr==costs.end())
		return true;
	      return findl->second<findr->second;
	    }
	  };
	  
	  compare_local_costs comp(insit.first->second);
	  std::sort(successors.begin(),successors.end(),comp);
	  std::cout << "Conditional branch costs:\n";
	  for(const auto& succ : successors)
	  {
	    auto succit=succ.get_instruction_iterator();
	    std::cout << from_expr(ns,"",succit->code) << ": " <<
	      (insit.first->second.count(succit) ? insit.first->second.at(succit) : 10000) << "\n";
	  }

	}
	
        for (std::size_t  i = 1UL; i < successors.size(); ++i)
          bt_trace.add_pending_backtrack(successors.at(i),false);
        trace.push_back(successors.front());
      }
    }
  }
}
