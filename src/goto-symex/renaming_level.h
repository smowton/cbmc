/*******************************************************************\

Module: Symbolic Execution

Author: Romain Brenguier, romain.brenguier@diffblue.com

\*******************************************************************/

/// \file
/// Renaming levels

#ifndef CPROVER_GOTO_SYMEX_RENAMING_LEVEL_H
#define CPROVER_GOTO_SYMEX_RENAMING_LEVEL_H

#include <map>
#include <memory>
#include <unordered_set>

#include <util/irep.h>
#include <util/ssa_expr.h>

class path_storaget;

/// Wrapper for a \c current_names map, which maps each identifier to an SSA
/// expression and a counter.
/// This is extended by the different symex_level structures which are used
/// during symex to ensure static single assignment (SSA) form.
struct symex_renaming_levelt
{
  virtual ~symex_renaming_levelt() = default;

  /// Map identifier to ssa_exprt and counter
  typedef std::map<irep_idt, std::pair<ssa_exprt, unsigned>> current_namest;
  current_namest current_names;

  /// Counter corresponding to an identifier
  unsigned current_count(const irep_idt &identifier) const
  {
    const auto it = current_names.find(identifier);
    return it == current_names.end() ? 0 : it->second.second;
  }

  /// Increase the counter corresponding to an identifier
  static void increase_counter(const current_namest::iterator &it)
  {
    ++it->second.second;
  }

  /// Add the \c ssa_exprt of current_names to vars
  void get_variables(std::unordered_set<ssa_exprt, irep_hash> &vars) const
  {
    for(const auto &pair : current_names)
      vars.insert(pair.second.first);
  }
};

/// Functor to set the level 0 renaming of SSA expressions.
/// Level 0 corresponds to threads.
/// The renaming is built for one particular interleaving.
struct symex_level0t : public symex_renaming_levelt
{
  void operator()(ssa_exprt &ssa_expr, const namespacet &ns, unsigned thread_nr)
    const;

  symex_level0t() = default;
  ~symex_level0t() override = default;
};

/// Functor to set the level 1 renaming of SSA expressions.
/// Level 1 corresponds to function frames.
/// This is to preserve locality in case of recursion
struct symex_level1t : public symex_renaming_levelt
{
  void operator()(ssa_exprt &ssa_expr) const;

  /// Insert the content of \p other into this renaming
  void restore_from(const current_namest &other);

  symex_level1t() = default;
  ~symex_level1t() override = default;
};

/// Functor to set the level 2 renaming of SSA expressions.
/// Level 2 corresponds to SSA.
/// This is to ensure each variable is only assigned once.
struct symex_level2t : public symex_renaming_levelt
{
  symex_level2t() = default;
  ~symex_level2t() override = default;

  /// Allocates a fresh L2 name for the given L1 identifier, and makes it the
  //  latest generation on this path.
  void increase_generation(
    const irep_idt l1_identifier,
    const ssa_exprt &lhs,
    path_storaget &path_storage);

  /// Increases the generation of the L1 identifier. Does nothing if there
  /// isn't an expression keyed by it.
  void increase_generation_if_exists(
    const irep_idt identifier,
    path_storaget &path_storage);

#if 0
#include <iostream>

  /// Prints the differences between the global and local naming maps (if they
  /// exist)
  void print_differences(const std::string &addition)
  {
    if(global_names == nullptr)
      return;

    std::string output;
    for(const auto &local : current_names)
    {
      auto global_iter = global_names->find(local.first);
      if(global_iter == global_names->end())
        continue;

      auto global_count = global_iter->second.second;
      auto local_count = local.second.second;
      if(global_count != local_count)
        output += "ID: " + id2string(local.first) +
                  ", local: " + std::to_string(local_count) +
                  " global: " + std::to_string(global_count) + '\n';
    }

    if(!output.empty())
    {
      std::cout << "Printing differences between local and global generations"
                << (addition.empty() ? "" : "[" + addition + "]") << '\n';
      std::cout << output;
    }
  }
#endif
};

/// Undo all levels of renaming
void get_original_name(exprt &expr);

/// Undo all levels of renaming
void get_original_name(typet &type);

#endif // CPROVER_GOTO_SYMEX_RENAMING_LEVEL_H
