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
#include <unordered_set>
#include <string>

namespace sumfn { namespace taint {


/**
 *
 */
struct  value_of_variable_t
{
  value_of_variable_t(
      irept const  value,
      bool  is_bottom,
      bool  is_top
      );

  bool  is_top() const noexcept { return m_is_top; }
  bool  is_bottom() const noexcept { return m_is_bottom; }
  irept  value() const noexcept { return m_value; }

private:
  irept  m_value;
  bool  m_is_bottom;
  bool  m_is_top;

};


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
      std::unordered_map<variable_id_t,value_of_variable_t>;

  explicit map_from_vars_to_values_t(
      std::unordered_set<variable_id_t> const&  variables
      );

  dictionary_t const&  data() const noexcept { return m_from_vars_to_values; }

private:
  dictionary_t  m_from_vars_to_values;
};


/**
 *
 */
using  instruction_ptr_t = goto_programt::instructiont const*;


/**
 *
 */
using  domain_t =
    std::unordered_map<instruction_ptr_t,map_from_vars_to_values_t>;

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
    goto_functionst::function_mapt const&  functions
    );


}}

#endif
