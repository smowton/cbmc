/*******************************************************************\

Module: Concrete Goto Program

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef CPROVER_GOTO_PROGRAMS_GOTO_PROGRAM_H
#define CPROVER_GOTO_PROGRAMS_GOTO_PROGRAM_H

#include <set>

#include <util/std_code.h>

#include "goto_program_template.h"

/*! \brief A specialization of goto_program_templatet do
           goto programs in which instructions have codet type.
    \ingroup gr_goto_programs
*/
class goto_programt:public goto_program_templatet<codet, exprt>
{
public:
  std::ostream &output_instruction(
    const class namespacet &ns,
    const irep_idt &identifier,
    std::ostream &out,
    instructionst::const_iterator it) const;

  std::ostream &output_instruction(
    const class namespacet &ns,
    const irep_idt &identifier,
    std::ostream &out,
    const instructiont &instruction) const;

  goto_programt() { }

  // get the variables in decl statements
  typedef std::set<irep_idt> decl_identifierst;
  void get_decl_identifiers(decl_identifierst &decl_identifiers) const;
};

#define forall_goto_program_instructions(it, program) \
  for(goto_programt::instructionst::const_iterator \
      it=(program).instructions.begin(); \
      it!=(program).instructions.end(); it++)

#define Forall_goto_program_instructions(it, program) \
  for(goto_programt::instructionst::iterator \
      it=(program).instructions.begin(); \
      it!=(program).instructions.end(); it++)

inline bool operator<(
  const goto_programt::const_targett i1,
  const goto_programt::const_targett i2)
{
  return order_const_target<codet, exprt>(i1, i2);
}

// NOLINTNEXTLINE(readability/identifiers)
typedef struct const_target_hash_templatet<codet, exprt> const_target_hash;

std::list<exprt> objects_read(const goto_programt::instructiont &);
std::list<exprt> objects_written(const goto_programt::instructiont &);

std::list<exprt> expressions_read(const goto_programt::instructiont &);
std::list<exprt> expressions_written(const goto_programt::instructiont &);

std::string as_string(
  const namespacet &ns,
  const goto_programt::instructiont &);

/*******************************************************************\
  Class: instruction_iterator_hashert

  Purpose:
    Function class to get hash of GOTO program instruction iterator

\*******************************************************************/
class instruction_iterator_hashert
{
public:
  /*******************************************************************\
    Function: instruction_iterator_hashert::operator()

    Purpose:
      Hashes iterators based on the memory location of the item pointed
        to by the iterator

    Inputs:
      it:
        An iterator pointing to a GOTO program instruction

    Outputs:
      A hash value for the iterator

  \*******************************************************************/
  std::size_t operator() (
    goto_programt::instructiont::const_targett const it) const
  {
    return std::hash<goto_programt::instructiont const*>()(&*it);
  }
};

#endif // CPROVER_GOTO_PROGRAMS_GOTO_PROGRAM_H
