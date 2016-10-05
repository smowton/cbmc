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


/*******************************************************************\

   Class:

 Purpose:

\*******************************************************************/
class  instruction_iterator_hashert
{
public:
  std::size_t  operator()(
      goto_programt::instructiont::const_targett const  it
      ) const
  {
    return std::hash<goto_programt::instructiont const*>()(&*it);
  }
};


/*******************************************************************\

   Class:

 Purpose:

\*******************************************************************/
class  taint_svaluet
{
public:

  typedef  std::string  symbolt;
  typedef std::set<symbolt>  expressiont;

  taint_svaluet(
      expressiont const&  expression,
      bool  is_bottom,
      bool  is_top
      );

  taint_svaluet(taint_svaluet const&  other);
  taint_svaluet(taint_svaluet&&  other);

  taint_svaluet&  operator=(taint_svaluet const&  other);
  taint_svaluet&  operator=(taint_svaluet&&  other);

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
bool  operator==(taint_svaluet const&  a, taint_svaluet const&  b);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  operator<(taint_svaluet const&  a, taint_svaluet const&  b);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_svaluet  join(taint_svaluet const&  a, taint_svaluet const&  b);


/*******************************************************************\
\*******************************************************************/
typedef access_path_to_memoryt  taint_lvaluet;

typedef std::unordered_map<taint_lvaluet,taint_svaluet,irep_hash,irep_full_eq>
        taint_map_from_lvalues_to_svaluest;
typedef std::unordered_set<taint_lvaluet,irep_hash,irep_full_eq>
        taint_lvalues_sett;


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  operator==(
    taint_map_from_lvalues_to_svaluest const&  a,
    taint_map_from_lvalues_to_svaluest const&  b);

bool  operator<(
    taint_map_from_lvalues_to_svaluest const&  a,
    taint_map_from_lvalues_to_svaluest const&  b);

inline bool  operator<=(
    taint_map_from_lvalues_to_svaluest const&  a,
    taint_map_from_lvalues_to_svaluest const&  b)
{
  return a == b || a < b;
}



/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_map_from_lvalues_to_svaluest  transform(
    taint_map_from_lvalues_to_svaluest const&  a,
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
taint_map_from_lvalues_to_svaluest  join(
    taint_map_from_lvalues_to_svaluest const&  a,
    taint_map_from_lvalues_to_svaluest const&  b
    );


/*******************************************************************\
\*******************************************************************/
typedef goto_programt::instructiont::const_targett  instruction_iteratort;




/*******************************************************************\
\*******************************************************************/
typedef std::unordered_map<instruction_iteratort,
                           taint_map_from_lvalues_to_svaluest,
                           instruction_iterator_hashert>
        taint_symmary_domaint;

typedef std::shared_ptr<taint_symmary_domaint>  taint_summary_domain_ptrt;


/*******************************************************************\

   Class:

 Purpose:

\*******************************************************************/
class  taint_summaryt : public summaryt
{
public:

  taint_summaryt(taint_map_from_lvalues_to_svaluest const&  input,
                 taint_map_from_lvalues_to_svaluest const&  output,
                 taint_summary_domain_ptrt const domain);

  std::string  kind() const;
  std::string  description() const noexcept;

  taint_map_from_lvalues_to_svaluest const&  input() const noexcept
  { return m_input; }
  taint_map_from_lvalues_to_svaluest const&  output() const noexcept
  { return m_output; }

  taint_summary_domain_ptrt  domain() const noexcept { return m_domain; }
  void  drop_domain() { m_domain.reset(); }

private:
  taint_map_from_lvalues_to_svaluest  m_input;
  taint_map_from_lvalues_to_svaluest  m_output;
  taint_summary_domain_ptrt  m_domain;
};

typedef std::shared_ptr<taint_summaryt const>  taint_summary_ptrt;



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
taint_summary_ptrt  summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    database_of_summariest const&  database,
    std::ostream* const  log = nullptr
    );


#endif
