/////////////////////////////////////////////////////////////////////////////
//
// Module: taint_summary
// Author: Marek Trtik
//
// This module defines interfaces and functionality for tint summaries.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef CPROVER_TAINT_SUMMARY_H
#define CPROVER_TAINT_SUMMARY_H

#include <summaries/summary.h>
#include <goto-programs/goto_model.h>
#include <goto-programs/goto_functions.h>
#include <util/irep.h>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <functional>
#include <string>

namespace sumfn { namespace taint { namespace detail {


struct  instruction_iterator_hasher
{
  std::size_t  operator()(goto_programt::instructiont::const_targett const  it) const
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
using  expression_t = std::set<std::string>;


/**
 *
 */
struct  value_of_variable_t
{
  value_of_variable_t(
      expression_t const&  expression,
      bool  is_bottom,
      bool  is_top
      );

  bool  is_top() const noexcept { return m_is_top; }
  bool  is_bottom() const noexcept { return m_is_bottom; }
  expression_t const&  expression() const noexcept { return m_expression; }

private:
  expression_t  m_expression;
  bool  m_is_bottom;
  bool  m_is_top;

};


/**
 *
 *
 *
 */
bool  operator==(
    value_of_variable_t const&  a,
    value_of_variable_t const&  b);


/**
 *
 *
 *
 */
bool  operator<(
    value_of_variable_t const&  a,
    value_of_variable_t const&  b);


/**
 *
 *
 *
 */
value_of_variable_t  join(
    value_of_variable_t const&  a,
    value_of_variable_t const&  b);



/**
 *
 *
 */
using  variable_id_t = std::string;

/**
 *
 */
struct  map_from_vars_to_values_t
{
  using  dictionary_t =
      std::map<variable_id_t,value_of_variable_t>;

  explicit map_from_vars_to_values_t(
      dictionary_t const&  data
      );
  explicit map_from_vars_to_values_t(
      std::unordered_set<variable_id_t> const&  variables
      );

  dictionary_t const&  data() const noexcept { return m_from_vars_to_values; }

private:
  dictionary_t  m_from_vars_to_values;
};


/**
 *
 *
 *
 */
bool  operator==(
    map_from_vars_to_values_t const&  a,
    map_from_vars_to_values_t const&  b);


/**
 *
 *
 *
 */
bool  operator<(
    map_from_vars_to_values_t const&  a,
    map_from_vars_to_values_t const&  b);


inline bool  operator<=(
    map_from_vars_to_values_t const&  a,
    map_from_vars_to_values_t const&  b)
{
  return a == b || a < b;
}



/**
 *
 *
 */
map_from_vars_to_values_t  transform(
    map_from_vars_to_values_t const&  a,
    goto_programt::instructiont const&  I,
    namespacet const&  ns
    );


/**
 *
 *
 */
map_from_vars_to_values_t  join(
    map_from_vars_to_values_t const&  a,
    map_from_vars_to_values_t const&  b
    );


/**
 *
 */
using  instruction_iterator_t = goto_programt::instructiont::const_targett;




/**
 *
 */
using  domain_t =
    std::unordered_map<instruction_iterator_t,
                       map_from_vars_to_values_t,
                       detail::instruction_iterator_hasher>;

using  domain_ptr_t = std::shared_ptr<domain_t>;


/**
 *
 *
 *
 */
struct  summary_t : public sumfn::summary_t
{
  summary_t(domain_ptr_t const  domain);

  std::string  kind() const;
  std::string  description() const noexcept;

  domain_ptr_t  domain() const noexcept { return m_domain; }
  void  drop_domain() { m_domain.reset(); }

private:
  domain_ptr_t  m_domain;
};


/**
 *
 *
 */
using  summary_ptr_t = std::shared_ptr<summary_t const>;



/**
 *
 *
 */
void  summarise_all_functions(
    goto_modelt const&  instrumented_program,
    database_of_summaries_t&  summaries_to_compute
    );


/**
 *
 *
 */
summary_ptr_t  summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program
    );


}}

#endif
