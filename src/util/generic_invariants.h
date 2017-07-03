/*******************************************************************\

Module: Generic invariants

Author: Chris Smowton, chris.smowton@diffblue.com

\*******************************************************************/

/// \file
/// Generic invariants
/// These are some classes of invariant that are expected to be of
/// general use, such as a complaint about a bad irept of some sort.
/// Specific modules should trivially subclass them so as to additionally
/// tag them as belonging to a particular module.

#include <util/invariant.h>

class irep_invariant_failedt:public invariant_failedt
{
 public:
  irept problem_node;

  irep_invariant_failedt(
    const std::string &reason,
    const irept &problem_node):
    invariant_failedt(reason),
    problem_node(problem_node)
  {
  }

  irep_invariant_failedt(
    const std::string &reason):
    invariant_failedt(reason)
  {
  }

  std::string pretty_print() const override
  {
    std::string ret=
      std::string("Invariant failed:")+
      std::logic_error::what();
    if(problem_node.is_not_nil())
    {
      ret+="\nProblem irep:\n";
      ret+=problem_node.pretty(0,0);
    }
    return ret;
  }
};
