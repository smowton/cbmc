/*******************************************************************\

Module: Compute dominators for CFG of goto_function

Author: Georg Weissenbacher, georg@weissenbacher.name

\*******************************************************************/

/// \file
/// Compute dominators for CFG of goto_function

#ifndef CPROVER_ANALYSES_CFG_DOMINATORS_H
#define CPROVER_ANALYSES_CFG_DOMINATORS_H

#include <set>
#include <list>
#include <map>
#include <iosfwd>
#include <cassert>

#include <goto-programs/goto_functions.h>
#include <goto-programs/goto_program.h>
#include <goto-programs/cfg.h>

/// Dominator graph. This computes a control-flow graph (see \ref cfgt) and
/// decorates it with dominator sets per program point, following
/// "A Simple, Fast Dominance Algorithm" by Cooper et al.
/// Templated over the program type (P) and program point type (T), which need
/// to be supported by \ref cfgt. Can compute either dominators or
/// postdominators depending on template parameter `post_dom`.
/// Use \ref cfg_dominators_templatet::dominates to directly query dominance,
/// or \ref cfg_dominators_templatet::get_node to get the \ref cfgt graph node
/// corresponding to a program point, including the in- and out-edges provided
/// by \ref cfgt as well as the dominator set computed by this class.
/// See also https://en.wikipedia.org/wiki/Dominator_(graph_theory)
template <class P, class T, bool post_dom>
class cfg_dominators_templatet
{
public:
  struct nodet
  {
    optionalt<std::size_t> dominator;
  };

  typedef procedure_local_cfg_baset<nodet, P, T> cfgt;
  cfgt cfg;

  void operator()(P &program);

  /// Get the graph node (which gives dominators, predecessors and successors)
  /// for \p program_point
  const typename cfgt::nodet &get_node(const T &program_point) const
  {
    return cfg.get_node(program_point);
  }

  /// Get the graph node (which gives dominators, predecessors and successors)
  /// for \p program_point
  typename cfgt::nodet &get_node(const T &program_point)
  {
    return cfg.get_node(program_point);
  }

  /// Get the graph node index for \p program_point
  typename cfgt::entryt get_node_index(const T &program_point) const
  {
    return cfg.get_node_index(program_point);
  }

  /// Returns true if the program point corresponding to \p rhs_node is
  /// dominated by program point \p lhs. Saves node lookup compared to the
  /// dominates overload that takes two program points, so this version is
  /// preferable if you intend to check more than one potential dominator.
  /// Note by definition all program points dominate themselves.
  bool dominates(T lhs, const nodet &rhs_node) const
  {
    auto target_index = cfg.get_node_index(lhs);
    auto current_index = rhs_node.dominator;
    while (current_index.has_value())
    {
      if (*current_index == target_index)
        return true;

      // Root dominates itself, so to avoid an endless loop, return.
      if (*current_index == 0)
        return false;

      current_index = cfg[*current_index].dominator;
    }

    return false;
  }

  /// Returns a set of T that are the dominators of start_node. Only use if you
  /// need the entire set of dominators from node to root.
  std::set<T> dominators(T start_node) const
  {
    auto current_index = cfg.get_node(start_node).dominator;
    std::set<T> results;
    while (current_index.has_value())
    {
      auto &current_node = cfg[*current_index];
      results.emplace(current_node.PC);

      // Root dominates itself, so to avoid an endless loop, break.
      if (*current_index == 0)
        break;

      current_index = current_node.dominator;
    }

    return results;
  }

  /// Returns true if program point \p lhs dominates \p rhs.
  /// Note by definition all program points dominate themselves.
  bool dominates(T lhs, T rhs) const
  {
    return dominates(lhs, get_node(rhs));
  }

  /// Returns true if the program point for \p program_point_node is reachable
  /// from the entry point. Saves a lookup compared to the overload taking a
  /// program point, so use this overload if you already have the node.
  bool program_point_reachable(const nodet &program_point_node) const
  {
    // Dominator analysis walks from the entry point, so a side-effect is to
    // identify unreachable program points (those which don't dominate even
    // themselves).
    return program_point_node.dominator.has_value();
  }

  /// Returns true if the program point for \p program_point_node is reachable
  /// from the entry point. Saves a lookup compared to the overload taking a
  /// program point, so use this overload if you already have the node.
  bool program_point_reachable(T program_point) const
  {
    // Dominator analysis walks from the entry point, so a side-effect is to
    // identify unreachable program points (those which don't dominate even
    // themselves).
    return program_point_reachable(get_node(program_point));
  }

  T entry_node;

  void output(std::ostream &) const;

protected:
  void initialise(P &program);
  void fixedpoint(P &program);
  std::size_t
  intersect(std::size_t potential_dominator, std::size_t edge_index);
};

/// Print the result of the dominator computation
template <class P, class T, bool post_dom>
std::ostream &operator << (
  std::ostream &out,
  const cfg_dominators_templatet<P, T, post_dom> &cfg_dominators)
{
  cfg_dominators.output(out);
  return out;
}

/// Compute dominators
template <class P, class T, bool post_dom>
void cfg_dominators_templatet<P, T, post_dom>::operator()(P &program)
{
  initialise(program);
  fixedpoint(program);
}

/// Initialises the elements of the fixed point analysis
template <class P, class T, bool post_dom>
void cfg_dominators_templatet<P, T, post_dom>::initialise(P &program)
{
  cfg(program);
}

/// Computes the MOP for the dominator analysis
template <class P, class T, bool post_dom>
void cfg_dominators_templatet<P, T, post_dom>::fixedpoint(P &program)
{
  std::list<T> worklist;

  if(cfgt::nodes_empty(program))
    return;

  if(post_dom)
    entry_node = cfgt::get_last_node(program);
  else
    entry_node = cfgt::get_first_node(program);
  typename cfgt::nodet &n = cfg.get_node(entry_node);
  n.dominator = cfg.get_node_index(entry_node);

  for(typename cfgt::edgest::const_iterator
      s_it=(post_dom?n.in:n.out).begin();
      s_it!=(post_dom?n.in:n.out).end();
      ++s_it)
    worklist.push_back(cfg[s_it->first].PC);

  while(!worklist.empty())
  {
    // get node from worklist
    T current=worklist.front();
    worklist.pop_front();

    bool changed=false;
    typename cfgt::nodet &node = cfg.get_node(current);

    auto potential_dominator = node.dominator;

    // compute intersection of predecessors
    for(const auto &edge : (post_dom ? node.out : node.in))
    {
      const typename cfgt::nodet &other = cfg[edge.first];
      if(!other.dominator)
        continue;

      if(!potential_dominator)
        potential_dominator = other.dominator;

      potential_dominator = intersect(*potential_dominator, *other.dominator);
    }

    if(!node.dominator || *potential_dominator != *node.dominator)
    {
      node.dominator = potential_dominator;
      changed = true;
    }

    if(changed) // fixed point for node reached?
    {
      for(const auto &edge : (post_dom ? node.in : node.out))
      {
        worklist.push_back(cfg[edge.first].PC);
      }
    }
  }
}

/// We can make the assumption that as we're walking back all dominators
/// will have been processed, so all de-referencing should be safe.
template <class P, class T, bool post_dom>
std::size_t cfg_dominators_templatet<P, T, post_dom>::intersect(
  std::size_t potential_dominator,
  std::size_t edge_index)
{
  while(potential_dominator != edge_index)
  {
    while(potential_dominator > edge_index)
    {
      potential_dominator = cfg[potential_dominator].dominator;
    }

    while(edge_index < potential_dominator)
    {
      edge_index = *cfg[edge_index].dominator;
    }
  }

  return potential_dominator;
}

/// Pretty-print a single node in the dominator tree. Supply a specialisation if
/// operator<< is not sufficient.
/// \par parameters: `node` to print and stream `out` to pretty-print it to
template <class T>
void dominators_pretty_print_node(const T &node, std::ostream &out)
{
  out << node;
}

inline void dominators_pretty_print_node(
  const goto_programt::targett& target,
  std::ostream& out)
{
  out << target->code.pretty();
}

/// Print the result of the dominator computation
template <class P, class T, bool post_dom>
void cfg_dominators_templatet<P, T, post_dom>::output(std::ostream &out) const
{
  for(const auto &node : cfg.entries())
  {
    auto n=node.first;

    dominators_pretty_print_node(n, out);
    if(post_dom)
      out << " post-dominated by ";
    else
      out << " dominated by ";
    bool first=true;
    for(const auto &d : cfg[node.second].dominators)
    {
      if(!first)
        out << ", ";
      first=false;
      dominators_pretty_print_node(d, out);
    }
    out << "\n";
  }
}

typedef cfg_dominators_templatet<
          const goto_programt, goto_programt::const_targett, false>
        cfg_dominatorst;

typedef cfg_dominators_templatet<
          const goto_programt, goto_programt::const_targett, true>
        cfg_post_dominatorst;

template<>
inline void dominators_pretty_print_node(
  const goto_programt::const_targett &node,
  std::ostream &out)
{
  out << node->location_number;
}

#endif // CPROVER_ANALYSES_CFG_DOMINATORS_H
