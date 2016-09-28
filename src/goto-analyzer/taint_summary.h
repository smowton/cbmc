/////////////////////////////////////////////////////////////////////////////
//
// Module: taint_summary
// Author: Marek Trtik
//
// This module defines interfaces and functionality for taint summaries.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef CPROVER_TAINT_SUMMARY_H
#define CPROVER_TAINT_SUMMARY_H

#include <summaries/summary.h>
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


struct  instruction_iterator_hasher
{
  std::size_t  operator()(
      goto_programt::instructiont::const_targett const  it
      ) const
  {
    return std::hash<goto_programt::instructiont const*>()(&*it);
  }
};

struct  lvalue_hasher
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



/**
 *
 *
 *
 */
struct  svaluet
{
  typedef std::set<std::string>  expressiont;

  svaluet(
      expressiont const&  expression,
      bool  is_bottom,
      bool  is_top
      );

  bool  is_top() const noexcept { return m_is_top; }
  bool  is_bottom() const noexcept { return m_is_bottom; }
  expressiont const&  expression() const noexcept { return m_expression; }

private:
  expressiont  m_expression;
  bool  m_is_bottom;
  bool  m_is_top;
};


/**
 *
 *
 *
 */
bool  operator==(svaluet const&  a, svaluet const&  b);


/**
 *
 *
 *
 */
bool  operator<(svaluet const&  a, svaluet const&  b);


/**
 *
 *
 *
 */
svaluet  join(svaluet const&  a, svaluet const&  b);


/**
 *
 *
 *
 *
 */
typedef exprt  lvaluet;

typedef std::unordered_map<lvaluet,svaluet,irep_hash,irep_full_eq>
        map_from_lvalues_to_svaluest;
typedef std::unordered_set<lvaluet,irep_hash,irep_full_eq>
        lvalues_sett;


/**
 *
 *
 *
 */
bool  operator==(
    map_from_lvalues_to_svaluest const&  a,
    map_from_lvalues_to_svaluest const&  b);


/**
 *
 *
 *
 */
bool  operator<(
    map_from_lvalues_to_svaluest const&  a,
    map_from_lvalues_to_svaluest const&  b);


inline bool  operator<=(
    map_from_lvalues_to_svaluest const&  a,
    map_from_lvalues_to_svaluest const&  b)
{
  return a == b || a < b;
}



/**
 *
 *
 */
map_from_lvalues_to_svaluest  transform(
    map_from_lvalues_to_svaluest const&  a,
    goto_programt::instructiont const&  I,
    namespacet const&  ns,
    std::ostream* const  log = nullptr
    );


/**
 *
 *
 */
map_from_lvalues_to_svaluest  join(
    map_from_lvalues_to_svaluest const&  a,
    map_from_lvalues_to_svaluest const&  b
    );


/**
 *
 */
typedef goto_programt::instructiont::const_targett  instruction_iterator_t;




/**
 *
 */
typedef std::unordered_map<instruction_iterator_t,
                           map_from_lvalues_to_svaluest,
                           detail::instruction_iterator_hasher>
        domaint;

typedef std::shared_ptr<domaint>  domain_ptrt;


/**
 *
 *
 *
 */
struct  summaryt : public sumfn::summaryt
{
  summaryt(map_from_lvalues_to_svaluest const&  input,
           map_from_lvalues_to_svaluest const&  output,
           domain_ptrt const  domain);

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


/**
 *
 *
 */
typedef std::shared_ptr<summaryt const>  summary_ptrt;



/**
 *
 *
 */
void  summarise_all_functions(
    goto_modelt const&  instrumented_program,
    database_of_summariest&  summaries_to_compute,
    call_grapht const&  call_graph,
    std::ostream* const  log = nullptr
    );


/**
 *
 *
 */
summary_ptrt  summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    database_of_summariest&  database,
    std::ostream* const  log = nullptr
    );


}}

#endif
