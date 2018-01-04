/*******************************************************************\

Module: Function Call Graphs

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

/// \file
/// Function Call Graphs

#include "call_graph.h"
#include "call_graph_helpers.h"

#include <util/std_expr.h>
#include <util/xml.h>

/// Create empty call graph
/// \param collect_callsites: if true, then each added graph edge will have
///   the calling instruction recorded in `callsites` map.
call_grapht::call_grapht(bool collect_callsites):
  collect_callsites(collect_callsites)
{
}

/// Create complete call graph
/// \param goto_model: model to search for callsites
/// \param collect_callsites: if true, then each added graph edge will have
///   the calling instruction recorded in `callsites` map.
call_grapht::call_grapht(const goto_modelt &goto_model, bool collect_callsites):
  call_grapht(goto_model.goto_functions, collect_callsites)
{
}

/// Create complete call graph
/// \param goto_functions: functions to search for callsites
/// \param collect_callsites: if true, then each added graph edge will have
///   the calling instruction recorded in `callsites` map.
call_grapht::call_grapht(
  const goto_functionst &goto_functions, bool collect_callsites):
  collect_callsites(collect_callsites)
{
  forall_goto_functions(f_it, goto_functions)
  {
    const goto_programt &body=f_it->second.body;
    add(f_it->first, body);
  }
}

static void forall_callsites(
  const goto_programt &body,
  std::function<void(goto_programt::const_targett, const irep_idt &)> call_task)
{
  forall_goto_program_instructions(i_it, body)
  {
    if(i_it->is_function_call())
    {
      const exprt &function_expr=to_code_function_call(i_it->code).function();
      if(function_expr.id()==ID_symbol)
      {
        const irep_idt &callee=to_symbol_expr(function_expr).get_identifier();
        call_task(i_it, callee);
      }
    }
  }
}

/// Create call graph restricted to functions reachable from `root`
/// \param goto_functions: functions to search for callsites
/// \param root: function to start exploring the graph
/// \param collect_callsites: if true, then each added graph edge will have
///   the calling instruction recorded in `callsites` map.
call_grapht::call_grapht(
  const goto_functionst &goto_functions,
  const irep_idt &root,
  bool collect_callsites)
{
  std::stack<irep_idt, std::vector<irep_idt>> pending_stack;
  pending_stack.push(root);

  while(!pending_stack.empty())
  {
    irep_idt function=pending_stack.top();
    pending_stack.pop();
    const goto_programt &goto_program=
      goto_functions.function_map.at(function).body;

    forall_callsites(
      goto_program,
      [&](goto_programt::const_targett i_it, const irep_idt &callee)
      {
        add(function, callee, i_it);
        if(graph.find(callee)==graph.end())
          pending_stack.push(callee);
      }
    ); // NOLINT
  }
}

/// Create call graph restricted to functions reachable from `root`
/// \param goto_model: model to search for callsites
/// \param root: function to start exploring the graph
/// \param collect_callsites: if true, then each added graph edge will have
///   the calling instruction recorded in `callsites` map.
call_grapht::call_grapht(
  const goto_modelt &goto_model,
  const irep_idt &root,
  bool collect_callsites):
  call_grapht(goto_model.goto_functions, root, collect_callsites)
{
}

void call_grapht::add(
  const irep_idt &function,
  const goto_programt &body)
{
  forall_callsites(
    body,
    [&](goto_programt::const_targett i_it, const irep_idt &callee)
    {
      add(function, callee, i_it);
    }
  ); // NOLINT
}

/// Add edge
/// \param caller: caller function
/// \param callee: callee function
void call_grapht::add(
  const irep_idt &caller,
  const irep_idt &callee)
{
  graph.insert(std::pair<irep_idt, irep_idt>(caller, callee));
}

/// Add edge with optional callsite information
/// \param caller: caller function
/// \param callee: callee function
/// \param callsite: call instruction responsible for this edge. Note this is
///   only stored if `collect_callsites` was specified during construction.
void call_grapht::add(
  const irep_idt &caller,
  const irep_idt &callee,
  locationt callsite)
{
  add(caller, callee);
  if(collect_callsites)
    callsites[{caller, callee}].insert(callsite);
}

/// Returns an inverted copy of this call graph
/// \return Inverted (callee -> caller) call graph
call_grapht call_grapht::get_inverted() const
{
  call_grapht result;
  for(const auto &caller_callee : graph)
    result.add(caller_callee.second, caller_callee.first);
  return result;
}

/// Helper class that maintains a map from function name to grapht node index
/// and adds nodes to the graph on demand.
class function_indicest
{
  typedef call_grapht::directed_grapht::node_indext node_indext;
  call_grapht::directed_grapht &graph;

public:
  std::unordered_map<irep_idt, node_indext, irep_id_hash> function_indices;

  explicit function_indicest(call_grapht::directed_grapht &graph):
    graph(graph)
  {
  }

  node_indext operator[](const irep_idt &function)
  {
    auto findit=function_indices.insert({function, 0});
    if(findit.second)
    {
      node_indext new_index=graph.add_node();
      findit.first->second=new_index;
      graph[new_index].function=function;
    }
    return findit.first->second;
  }
};

/// Returns a `grapht` representation of this call graph, suitable for use
/// with generic grapht algorithms. Note that parallel edges in call_grapht
/// (e.g. A { B(); B(); } appearing as two A->B edges) will be condensed in
/// the grapht output, so only one edge will appear. If `collect_callsites`
/// was set when this call-graph was constructed the edge will be annotated
/// with the call-site set.
/// \return grapht representation of this call_grapht
call_grapht::directed_grapht call_grapht::get_directed_graph() const
{
  call_grapht::directed_grapht ret;
  function_indicest function_indices(ret);

  for(const auto &edge : graph)
  {
    auto a_index=function_indices[edge.first];
    auto b_index=function_indices[edge.second];
    // Check then create the edge like this to avoid copying the callsites
    // set once per parallel edge, which could be costly if there are many.
    if(!ret.has_edge(a_index, b_index))
    {
      ret.add_edge(a_index, b_index);
      if(collect_callsites)
        ret[a_index].out[b_index].callsites=callsites.at(edge);
    }
  }

  ret.nodes_by_name=std::move(function_indices.function_indices);
  return ret;
}

/// Prints callsites responsible for a graph edge as comma-separated
/// location numbers, e.g. "{1, 2, 3}".
/// \param edge: graph edge
/// \return pretty representation of edge callsites
std::string call_grapht::format_callsites(const edget &edge) const
{
  PRECONDITION(collect_callsites);
  std::string ret="{";
  for(const locationt &loc : callsites.at(edge))
  {
    if(ret.size()>1)
      ret+=", ";
    ret+=std::to_string(loc->location_number);
  }
  ret+='}';
  return ret;
}

void call_grapht::output_dot(std::ostream &out) const
{
  out << "digraph call_graph {\n";

  for(const auto &edge : graph)
  {
    out << "  \"" << edge.first << "\" -> "
        << "\"" << edge.second << "\" "
        << " [arrowhead=\"vee\"";
    if(collect_callsites)
      out << " label=\"" << format_callsites(edge) << "\"";
    out << "];\n";
  }

  out << "}\n";
}

void call_grapht::output(std::ostream &out) const
{
  for(const auto &edge : graph)
  {
    out << edge.first << " -> " << edge.second << "\n";
    if(collect_callsites)
      out << "  (callsites: " << format_callsites(edge) << ")\n";
  }
}

void call_grapht::output_xml(std::ostream &out) const
{
  // Note I don't implement callsite output here; I'll leave that
  // to the first interested XML user.
  if(collect_callsites)
    out << "<!-- XML call-graph representation does not document callsites yet."
      " If you need this, edit call_grapht::output_xml -->\n";
  for(const auto &edge : graph)
  {
    out << "<call_graph_edge caller=\"";
    xmlt::escape_attribute(id2string(edge.first), out);
    out << "\" callee=\"";
    xmlt::escape_attribute(id2string(edge.second), out);
    out << "\">\n";
  }
}

optionalt<std::size_t> call_grapht::directed_grapht::get_node_index(
  const irep_idt &function) const
{
  auto findit=nodes_by_name.find(function);
  if(findit==nodes_by_name.end())
    return optionalt<node_indext>();
  else
    return findit->second;
}

void find_leaves_below_function(
  const call_grapht &call_graph,
  const irep_idt &function,
  std::unordered_set<irep_idt, dstring_hash> &to_avoid,
  std::unordered_set<irep_idt, dstring_hash> &output)
{
  if(to_avoid.count(function)!=0UL)
    return;
  to_avoid.insert(function);
  const auto range = call_graph.graph.equal_range(function);
  if(range.first==range.second)
    output.insert(function);
  else
  {
    for(auto it=range.first; it!=range.second; ++it)
      find_leaves_below_function(call_graph, it->second, to_avoid, output);
  }
}

/// See output
/// \par parameters: `call_graph`: call graph
/// `function`: start node
/// \return `output`: set of leaves reachable from 'function'
void find_leaves_below_function(
  const call_grapht &call_graph,
  const irep_idt &function,
  std::unordered_set<irep_idt, dstring_hash> &output)
{
  std::unordered_set<irep_idt, dstring_hash> to_avoid;
  find_leaves_below_function(call_graph, function, to_avoid, output);
}

void find_direct_or_indirect_callees_of_function(
  const call_grapht &call_graph,
  const irep_idt &function,
  std::unordered_set<irep_idt, dstring_hash> &output)
{
  std::unordered_set<irep_idt, dstring_hash> leaves;
  find_leaves_below_function(call_graph, function, output, leaves);
  output.insert(leaves.cbegin(), leaves.cend());
}

void find_nearest_common_callees(
  const call_grapht &call_graph,
  const std::set<irep_idt> &functions,
  std::set<irep_idt> &output)
{
  if(functions.empty())
    return;
  if(functions.size()==1UL)
  {
    output.insert(*functions.cbegin());
    return;
  }

  std::map<irep_idt, std::size_t> counting;
  for(const auto &elem : call_graph.graph)
  {
    counting[elem.first]=0U;
    counting[elem.second]=0U;
  }
  for(const auto &fn : functions)
  {
    std::unordered_set<irep_idt, dstring_hash> callees;
    find_direct_or_indirect_callees_of_function(call_graph, fn, callees);
    assert(callees.count(fn)==1U);
    for(const auto &callee : callees)
      ++counting[callee];
  }

  std::set<irep_idt> leaves;
  for(const auto &elem : counting)
    if(elem.second!=0U)
    {
      const auto range = call_graph.graph.equal_range(elem.first);
      if(range.first==range.second)
        leaves.insert(elem.first);
    }

  for(auto &elem : counting)
    if(leaves.count(elem.first)!=0UL)
      output.insert(elem.first);
    else if(elem.second!=0U && elem.second<functions.size())
    {
      const auto range = call_graph.graph.equal_range(elem.first);
      for(auto it=range.first; it!=range.second; ++it)
      {
        auto cit=counting.find(it->second);
        if(cit->second==functions.size())
          output.insert(cit->first);
      }
    }
}

/// See output
/// \par parameters: `call_graph`: Call graph
/// `caller`: Caller
/// `callee`: Potential callee
/// \return Returns true if call graph says caller calls callee.
bool exists_direct_call(
  const call_grapht &call_graph,
  const irep_idt &caller,
  const irep_idt &callee)
{
  const auto range =
    call_graph.graph.equal_range(caller);
  for(auto it=range.first; it!=range.second; ++it)
    if(callee==it->second)
      return true;
  return false;
}

/// See output
/// \par parameters: `call_graph`: Call graph
/// `caller`: Caller
/// `callee`: Potential callee
/// `ignored_functions`: Functions to exclude from call graph for the purposes
///   of finding a path
/// \return Returns true if call graph says caller can reach callee via any
///   intermediate sequence of callees not occurring in ignored_functions
bool exists_direct_or_indirect_call(
  const call_grapht &call_graph,
  const irep_idt &caller,
  const irep_idt &callee,
  std::unordered_set<irep_idt, dstring_hash> &ignored_functions)
{
  if(ignored_functions.count(caller)!=0UL)
    return false;
  ignored_functions.insert(caller);
  if(exists_direct_call(call_graph, caller, callee))
    return ignored_functions.count(callee)==0UL;
  const auto range =
    call_graph.graph.equal_range(caller);
  for(auto it=range.first; it!=range.second; ++it)
    if(exists_direct_or_indirect_call(
         call_graph,
         it->second,
         callee,
         ignored_functions))
      return true;
  return false;
}
