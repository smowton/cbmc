/*******************************************************************\

Module: Compute dominators for CFG of goto_function

Author: Georg Weissenbacher, georg@weissenbacher.name

\*******************************************************************/

/// \file
/// Compute dominators for CFG of goto_function

#ifndef CPROVER_ANALYSES_CFG_DOMINATORS_H
#define CPROVER_ANALYSES_CFG_DOMINATORS_H

#include <cassert>
#include <iosfwd>
#include <iterator>
#include <list>
#include <map>
#include <set>

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
    int postorder_index = -1;
  };

  typedef procedure_local_cfg_baset<nodet, P, T> cfgt;
  cfgt cfg;
  using cfg_nodet = typename cfgt::nodet;

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

  class dominators_iterablet
  {
    // Type of our containing \ref dense_integer_mapt
    typedef cfg_dominators_templatet<P, T, post_dom> cfg_dominatorst;

  public:
    class dominators_iteratort
      : public std::iterator<std::forward_iterator_tag, T>
    {
      // Type of the std::iterator support class we inherit
      typedef std::iterator<std::forward_iterator_tag, const T> base_typet;

    public:
      dominators_iteratort(
        const cfg_dominatorst &dominator_analysis,
        std::size_t index)
        : dominator_analysis(dominator_analysis), current_index(index)
      {
      }

    private:
      explicit dominators_iteratort(const cfg_dominatorst &dominator_analysis)
        : dominator_analysis(dominator_analysis), current_index{}
      {
      }

    public:
      static dominators_iteratort end(const cfg_dominatorst &dominator_analysis)
      {
        return dominators_iteratort{dominator_analysis};
      }

      dominators_iteratort operator++()
      {
        auto i = *this;
        advance();
        return i;
      }
      dominators_iteratort operator++(int junk)
      {
        advance();
        return *this;
      }
      const cfg_nodet &get_node() const
      {
        return dominator_analysis.cfg[*current_index];
      }
      typename base_typet::reference operator*() const
      {
        return get_node().PC;
      }
      typename base_typet::pointer operator->() const
      {
        return &**this;
      }
      bool operator==(const dominators_iteratort &rhs) const
      {
        return current_index == rhs.current_index;
      }
      bool operator!=(const dominators_iteratort &rhs) const
      {
        return current_index != rhs.current_index;
      }

    private:
      void advance()
      {
        INVARIANT(current_index.has_value(), "can't advance an end() iterator");
        const auto &next_dominator =
          dominator_analysis.cfg[*current_index].dominator;
        INVARIANT(
          next_dominator.has_value(),
          "dominator ancestors must end up at the root");
        if(*next_dominator == *current_index)
        {
          // Cycle; this is the root node
          current_index = optionalt<std::size_t>{};
        }
        else
        {
          current_index = next_dominator;
        }
      }

      const cfg_dominatorst &dominator_analysis;
      optionalt<std::size_t> current_index;
    };

    dominators_iterablet(
      const cfg_dominatorst &dominator_analysis,
      optionalt<std::size_t> index)
      : dominator_analysis(dominator_analysis), first_instruction_index(index)
    {
    }

    dominators_iteratort begin() const
    {
      if(first_instruction_index.has_value())
        return dominators_iteratort{dominator_analysis,
                                    *first_instruction_index};
      else
        return dominators_iteratort::end(dominator_analysis);
    }

    dominators_iteratort end() const
    {
      return dominators_iteratort::end(dominator_analysis);
    }

  private:
    const cfg_dominatorst &dominator_analysis;
    optionalt<std::size_t> first_instruction_index;
  };

  dominators_iterablet dominators(const nodet &start_node) const
  {
    return dominators_iterablet{*this, start_node.dominator};
  }

  dominators_iterablet dominators(T start_instruction) const
  {
    return dominators(cfg.get_node(start_instruction));
  }

  /// Returns true if the program point corresponding to \p rhs_node is
  /// dominated by program point \p lhs. Saves node lookup compared to the
  /// dominates overload that takes two program points, so this version is
  /// preferable if you intend to check more than one potential dominator.
  /// Note by definition all program points dominate themselves.
  bool dominates(T lhs, const nodet &rhs_node) const
  {
    const auto rhs_dominators = dominators(rhs_node);
    return std::any_of(
      rhs_dominators.begin(),
      rhs_dominators.end(),
      [&lhs](const goto_programt::const_targett dominator) {
        return lhs == dominator;
      });
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
  void assign_postordering(typename cfgt::nodet &start_node);
  const cfg_nodet &intersect(
    const cfg_nodet &potential_dominator, const cfg_nodet &edge_node);
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

/// Assigns post-order index to the nodes to garantee that all nodes' parents
/// have a lower index than they do. Normal graph generation indexes don't have
/// this constraint, so we need to apply it manually.
template <class P, class T, bool post_dom>
void cfg_dominators_templatet<P, T, post_dom>::assign_postordering(
  typename cfgt::nodet &start_node)
{
  std::size_t index = 0;
  std::list<std::reference_wrapper<typename cfgt::nodet>> worklist;
  worklist.push_back(std::reference_wrapper<typename cfgt::nodet>(start_node));
  while(!worklist.empty())
  {
    typename cfgt::nodet &current_node = worklist.front().get();
    current_node.postorder_index = index++;
    worklist.pop_front();
    for(typename cfgt::edgest::const_iterator s_it =
          (post_dom ? current_node.in : current_node.out).begin();
        s_it != (post_dom ? current_node.in : current_node.out).end();
        ++s_it)
    {
      auto &edge_node = cfg[s_it->first];
      if(edge_node.postorder_index == -1)
        worklist.push_back(
          std::reference_wrapper<typename cfgt::nodet>(cfg[s_it->first]));
    }
  }
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

  assign_postordering(n);

  for(typename cfgt::edgest::const_iterator s_it =
        (post_dom ? n.in : n.out).begin();
      s_it != (post_dom ? n.in : n.out).end();
      ++s_it)
    worklist.push_back(cfg[s_it->first].PC);

  while(!worklist.empty())
  {
    // get node from worklist
    T current = worklist.front();
    worklist.pop_front();

    bool changed = false;
    typename cfgt::nodet &node = cfg.get_node(current);

    const cfg_nodet *dominator_node =
      node.dominator ? &cfg[*node.dominator] : nullptr;

    // compute intersection of predecessors
    auto &edges = (post_dom ? node.out : node.in);
    if(edges.size() != 0)
    {
      for(const auto &edge : edges)
      {
        const typename cfgt::nodet &other = cfg[edge.first];
        if(!other.dominator)
          continue;

        if(!dominator_node)
          dominator_node = &other;
        else
          dominator_node = &intersect(*dominator_node, other);
      }
    }

    if(
      !node.dominator ||
      dominator_node->postorder_index != cfg[*node.dominator].postorder_index)
    {
      node.dominator = cfg.get_node_index(dominator_node->PC);
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

template <class P, class T, bool post_dom>
const typename cfg_dominators_templatet<P, T, post_dom>::cfgt::nodet &
cfg_dominators_templatet<P, T, post_dom>::intersect(
  const cfg_nodet &left_input_node,
  const cfg_nodet &right_input_node)
{
  auto left_node_dominators = dominators(left_input_node.PC);
  auto right_node_dominators = dominators(right_input_node.PC);
  auto left_it = left_node_dominators.begin();
  auto right_it = right_node_dominators.begin();

  while(left_it.get_node().postorder_index !=
        right_it.get_node().postorder_index)
  {
    while(left_it.get_node().postorder_index <
          right_it.get_node().postorder_index)
    {
      ++left_it;
      INVARIANT(
        left_it != left_node_dominators.end(),
        "should only move the iterator that is further from the root");
    }

    while(right_it.get_node().postorder_index <
          left_it.get_node().postorder_index)
    {
      ++right_it;
      INVARIANT(
        right_it != right_node_dominators.end(),
        "should only move the iterator that is further from the root");
    }
  }

  return left_it.get_node();
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
    for(const auto &d : dominators(n))
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
