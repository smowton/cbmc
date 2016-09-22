/////////////////////////////////////////////////////////////////////////////
//
// Module: taint_summary
// Author: Marek Trtik
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////


#include <goto-analyzer/taint_summary.h>
#include <util/file_util.h>
#include <util/msgstream.h>
#include <analyses/ai.h>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cassert>

namespace sumfn { namespace taint { namespace detail { namespace {


/**
 *
 */
value_of_variable_t  make_symbol()
{
  static uint64_t  counter = 0UL;
  std::string const  symbol_name =
      msgstream() << "T" << counter;
  return {irept(symbol_name),false,false};
}

/**
 *
 */
value_of_variable_t  make_bottom()
{
  return {irept(),true,false};
}

/**
 *
 */
value_of_variable_t  make_top()
{
  return {irept(),false,true};
}


/**
 *
 */
using  solver_work_set_t =
    std::unordered_set<goto_programt::instructiont const*>;


/**
 *
 */
void  initialise_domain(
    goto_functionst::goto_functiont const&  function,
    domain_t&  domain
    )
{
  std::unordered_set<variable_id_t>  variables;
  for (auto const&  param : function.parameter_identifiers)
    variables.insert(as_string(param));
  domain.insert({
      &*function.body.instructions.cbegin(),
      map_from_vars_to_values_t(variables)
      });

  for (auto const&  instr : function.body.instructions)
    domain.insert({
        &instr,
        map_from_vars_to_values_t(std::unordered_set<variable_id_t>{})
        });
}


/**
 *
 */
void  initialise_workset(
    goto_functionst::goto_functiont const&  function,
    solver_work_set_t&  work_set
    )
{
  for (auto const&  instr : function.body.instructions)
    work_set.insert(&instr);
}



}}}}

namespace sumfn { namespace taint {


value_of_variable_t::value_of_variable_t(
    irept const  value,
    bool  is_bottom,
    bool  is_top
    )
  : m_value(value)
  , m_is_bottom(is_bottom)
  , m_is_top(is_top)
{
  assert(m_is_bottom && m_is_top == false);
}


map_from_vars_to_values_t::map_from_vars_to_values_t(
    std::unordered_set<variable_id_t> const&  variables
    )
  : m_from_vars_to_values()
{
  for (auto const&  var : variables)
    m_from_vars_to_values.insert({ var, detail::make_symbol() });
}


summary_t::summary_t(domain_ptr_t const  domain)
  : m_domain(domain)
{
  assert(m_domain.operator bool());
}


std::string  summary_t::kind() const
{
  return "sumfn::taint::summarise_function";
}

std::string  summary_t::description() const noexcept
{
  return "Function summary of taint analysis of java web applications.";
}



void  summarise_all_functions(
    goto_modelt const&  instrumented_program,
    database_of_summaries_t&  summaries_to_compute
    )
{
  for (auto const&  elem : instrumented_program.goto_functions.function_map)
    if (elem.second.body_available())
      summaries_to_compute.insert({
          as_string(elem.first),
          summarise_function(
              elem.first,
              instrumented_program.goto_functions.function_map
              )
          });
}

summary_ptr_t  summarise_function(
    irep_idt const&  function_id,
    goto_functionst::function_mapt const&  functions
    )
{
  auto const  fn_iter = functions.find(function_id);

  assert(fn_iter != functions.cend());
  assert(fn_iter->second.body_available());

  domain_ptr_t  domain = std::make_shared<domain_t>();
  detail::initialise_domain(fn_iter->second,*domain);

  detail::solver_work_set_t  work_set;
  detail::initialise_workset(fn_iter->second,work_set);
  while (!work_set.empty())
  {
    // TODO!
    break;
  }

  return std::make_shared<summary_t>(domain);
}


}}
