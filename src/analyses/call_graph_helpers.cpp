
#include "call_graph_helpers.h"

static std::vector<irep_idt> get_neighbours(
  const call_grapht::directed_grapht &graph, const irep_idt &function, bool forwards)
{
  std::vector<irep_idt> result;
  const auto &fnode = graph[*(graph.get_node_index(function))];
  const auto &neighbours = forwards ? fnode.out : fnode.in;
  for(const auto &succ_edge : neighbours)
    result.push_back(graph[succ_edge.first].function);
  return result;
}

std::vector<irep_idt> get_successors(
  const call_grapht::directed_grapht &graph, const irep_idt &function)
{
  return get_neighbours(graph, function, true);
}

std::vector<irep_idt> get_predecessors(
  const call_grapht::directed_grapht &graph, const irep_idt &function)
{
  return get_neighbours(graph, function, false);
}

static std::vector<irep_idt> get_reachable_functions(
  const call_grapht::directed_grapht &graph, const irep_idt &function, bool forwards)
{
  std::vector<call_grapht::directed_grapht::node_indext> reachable_nodes =
    graph.get_reachable(*(graph.get_node_index(function)), forwards);
  std::vector<irep_idt> result;
  for(const auto i : reachable_nodes)
    result.push_back(graph[i].function);
  return result;
}

std::vector<irep_idt> get_transitive_successors(
  const call_grapht::directed_grapht &graph, const irep_idt &function)
{
  return get_reachable_functions(graph, function, true);
}

std::vector<irep_idt> get_transitive_predecessors(
  const call_grapht::directed_grapht &graph, const irep_idt &function)
{
  return get_reachable_functions(graph, function, false);
}
