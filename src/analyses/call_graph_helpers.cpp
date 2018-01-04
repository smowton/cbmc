/*******************************************************************\

Module: Function Call Graph Helpers

Author: Chris Smowton, chris.smowton@diffblue.com

\*******************************************************************/

/// \file
/// Function Call Graph Helpers

#include "call_graph_helpers.h"

/// Get either callers or callees of a given function
/// \param graph: call graph
/// \param function: function to query
/// \param forwards: if true, get callees; otherwise get callers.
static std::set<irep_idt> get_neighbours(
  const call_grapht::directed_grapht &graph,
  const irep_idt &function,
  bool forwards)
{
  std::set<irep_idt> result;
  const auto &fnode = graph[*(graph.get_node_index(function))];
  const auto &neighbours = forwards ? fnode.out : fnode.in;
  for(const auto &succ_edge : neighbours)
    result.insert(graph[succ_edge.first].function);
  return result;
}

std::set<irep_idt> get_callees(
  const call_grapht::directed_grapht &graph, const irep_idt &function)
{
  return get_neighbours(graph, function, true);
}

std::set<irep_idt> get_callers(
  const call_grapht::directed_grapht &graph, const irep_idt &function)
{
  return get_neighbours(graph, function, false);
}

/// Get either reachable functions or functions that can reach a given function.
/// In both cases the query function itself is included.
/// \param graph: call graph
/// \param function: function to query
/// \param forwards: if true, get reachable functions; otherwise get functions
///   that can reach the given function.
static std::set<irep_idt> get_connected_functions(
  const call_grapht::directed_grapht &graph,
  const irep_idt &function,
  bool forwards)
{
  std::vector<call_grapht::directed_grapht::node_indext> connected_nodes =
    graph.get_reachable(*(graph.get_node_index(function)), forwards);
  std::set<irep_idt> result;
  for(const auto i : connected_nodes)
    result.insert(graph[i].function);
  return result;
}

std::set<irep_idt> get_reachable_functions(
  const call_grapht::directed_grapht &graph, const irep_idt &function)
{
  return get_connected_functions(graph, function, true);
}

std::set<irep_idt> get_reaching_functions(
  const call_grapht::directed_grapht &graph, const irep_idt &function)
{
  return get_connected_functions(graph, function, false);
}

std::vector<irep_idt> get_inverse_topological_order(
  const call_grapht::directed_grapht &graph)
{
  std::vector<call_grapht::directed_grapht::node_indext> node_sccs;
  node_sccs.resize(graph.size());

  // Get a topological sort of the call graph. This produces a vector
  // indicating each node's SCC; lower-numbered SCCs are nearer leaves.

  graph.SCCs(node_sccs);
  const auto &nodes_by_name = graph.get_nodes_by_name();

  // Sort a list of function names by their topological position, such that
  // leaf functions are first:

  auto compare_scc =
    [&node_sccs, &nodes_by_name](const irep_idt &a, const irep_idt &b) {
      return node_sccs[nodes_by_name.at(a)] < node_sccs[nodes_by_name.at(b)];
    };

  std::vector<irep_idt> inverted_topological_order;
  for(call_grapht::directed_grapht::node_indext i = 0; i < graph.size(); ++i)
    inverted_topological_order.push_back(graph[i].function);

  std::sort(
    inverted_topological_order.begin(),
    inverted_topological_order.end(),
    compare_scc);

  return inverted_topological_order;
}