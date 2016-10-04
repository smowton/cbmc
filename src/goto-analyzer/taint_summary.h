/*******************************************************************\

Module: taint_summary

Author: Marek Trtik

Date: September 2016

This module defines interfaces and functionality for taint summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_SUMMARY_H
#define CPROVER_TAINT_SUMMARY_H

#include <summaries/summary.h>
#include <summaries/utility.h>
#include <goto-programs/goto_model.h>
#include <goto-programs/goto_functions.h>
#include <analyses/call_graph.h>
#include <util/irep.h>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <functional>
#include <string>
#include <iosfwd>

namespace sumfn { namespace taint { namespace detail {


struct  instruction_iterator_hashert
{
  std::size_t  operator()(
      goto_programt::instructiont::const_targett const  it
      ) const
  {
    return std::hash<goto_programt::instructiont const*>()(&*it);
  }
};

struct  lvalue_hashert
{
  std::size_t  operator()(
      goto_programt::instructiont::const_targett const  it
      ) const
  {
    return std::hash<goto_programt::instructiont const*>()(&*it);
  }
};


}}}

namespace sumfn { namespace taint {


/*******************************************************************\

   Class:

 Purpose:

\*******************************************************************/
class  svaluet
{
public:

  typedef  std::string  symbolt;
  typedef std::set<symbolt>  expressiont;

  svaluet(
      expressiont const&  expression,
      bool  is_bottom,
      bool  is_top
      );

  svaluet(svaluet const&  other);
  svaluet(svaluet&&  other);

  svaluet&  operator=(svaluet const&  other);
  svaluet&  operator=(svaluet&&  other);

  bool  is_top() const noexcept { return m_is_top; }
  bool  is_bottom() const noexcept { return m_is_bottom; }
  expressiont const&  expression() const noexcept { return m_expression; }

  bool  is_symbol() const noexcept
  { return !is_top() && !is_bottom() && expression().size() == 1UL; }

private:
  expressiont  m_expression;
  bool  m_is_bottom;
  bool  m_is_top;
};


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  operator==(svaluet const&  a, svaluet const&  b);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  operator<(svaluet const&  a, svaluet const&  b);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
svaluet  join(svaluet const&  a, svaluet const&  b);


/*******************************************************************\
\*******************************************************************/
typedef access_path_to_memoryt  lvaluet;

typedef std::unordered_map<lvaluet,svaluet,irep_hash,irep_full_eq>
        map_from_lvalues_to_svaluest;
typedef std::unordered_set<lvaluet,irep_hash,irep_full_eq>
        lvalues_sett;


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  operator==(
    map_from_lvalues_to_svaluest const&  a,
    map_from_lvalues_to_svaluest const&  b);

bool  operator<(
    map_from_lvalues_to_svaluest const&  a,
    map_from_lvalues_to_svaluest const&  b);

inline bool  operator<=(
    map_from_lvalues_to_svaluest const&  a,
    map_from_lvalues_to_svaluest const&  b)
{
  return a == b || a < b;
}



/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
map_from_lvalues_to_svaluest  transform(
    map_from_lvalues_to_svaluest const&  a,
    goto_programt::instructiont const&  I,
    goto_functionst::function_mapt const&  functions_map,
    database_of_summariest const&  database,
    namespacet const&  ns,
    std::ostream* const  log = nullptr
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
map_from_lvalues_to_svaluest  join(
    map_from_lvalues_to_svaluest const&  a,
    map_from_lvalues_to_svaluest const&  b
    );


/*******************************************************************\
\*******************************************************************/
typedef goto_programt::instructiont::const_targett  instruction_iteratort;




/*******************************************************************\
\*******************************************************************/
typedef std::unordered_map<instruction_iteratort,
                           map_from_lvalues_to_svaluest,
                           detail::instruction_iterator_hashert>
        domaint;

typedef std::shared_ptr<domaint>  domain_ptrt;


/*******************************************************************\

   Class:

 Purpose:

\*******************************************************************/
class  summaryt : public sumfn::summaryt
{
public:

  summaryt(map_from_lvalues_to_svaluest const&  input,
           map_from_lvalues_to_svaluest const&  output,
           domain_ptrt const domain);

  std::string  kind() const;
  std::string  description() const noexcept;

  map_from_lvalues_to_svaluest const&  input() const noexcept
  { return m_input; }
  map_from_lvalues_to_svaluest const&  output() const noexcept
  { return m_output; }

  domain_ptrt  domain() const noexcept { return m_domain; }
  void  drop_domain() { m_domain.reset(); }

private:
  map_from_lvalues_to_svaluest  m_input;
  map_from_lvalues_to_svaluest  m_output;
  domain_ptrt  m_domain;
};

typedef std::shared_ptr<summaryt const>  summary_ptrt;



/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  summarise_all_functions(
    goto_modelt const&  instrumented_program,
    database_of_summariest&  summaries_to_compute,
    call_grapht const&  call_graph,
    std::ostream* const  log = nullptr
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
summary_ptrt  summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    database_of_summariest const&  database,
    std::ostream* const  log = nullptr
    );


}}

#endif
