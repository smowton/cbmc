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
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cassert>

namespace sumfn { namespace taint { namespace detail { namespace {


/**
 *
 */
irept  generate_fresh_symbol()
{
  static uint64_t  counter = 0UL;
  std::string const  symbol_name =
      msgstream() << "T" << counter;
  return irept(symbol_name);
}


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

  static value_of_variable_t  make_fresh_symbol();
  static value_of_variable_t  make_bottom();
  static value_of_variable_t  make_top();

private:
  irept  m_value;
  bool  m_is_bottom;
  bool  m_is_top;

};

value_of_variable_t::value_of_variable_t(
    irept const  value,
    bool  is_bottom,
    bool  is_top
    )
  : m_value(generate_fresh_symbol())
  , m_is_bottom(is_bottom)
  , m_is_top(is_top)
{
  assert(m_is_bottom && m_is_top == false);
}

value_of_variable_t  value_of_variable_t::make_fresh_symbol()
{
  return {generate_fresh_symbol(),false,false};
}

value_of_variable_t  value_of_variable_t::make_bottom()
{
  return {irept(),true,false};
}

value_of_variable_t  value_of_variable_t::make_top()
{
  return {irept(),false,true};
}


/**
 *
 */
struct  map_from_vars_to_values_t
{
  explicit map_from_vars_to_values_t(
      std::unordered_set<std::string> const&  variables
      );

private:

  using  dictionary_t =
      std::unordered_map<std::string,value_of_variable_t>;

  dictionary_t  m_from_vars_to_values;
};

map_from_vars_to_values_t::map_from_vars_to_values_t(
    std::unordered_set<std::string> const&  variables
    )
  : m_from_vars_to_values()
{
  for (auto const&  var : variables)
    m_from_vars_to_values.insert({
        var,
        value_of_variable_t::make_fresh_symbol()
        });
}


/**
 *
 */
using  solver_domain_t =
    std::unordered_map<goto_programt::instructiont const*,
                       map_from_vars_to_values_t>;


/**
 *
 */
using  solver_work_set_t =
    std::unordered_set<goto_programt::instructiont const*>;


/**
 *
 */
void  initialise_solver_domain(
    goto_functionst::goto_functiont const&  function,
    solver_domain_t&  domain
    )
{
  std::unordered_set<std::string>  variables;
  for (auto const&  param : function.parameter_identifiers)
    variables.insert(as_string(param));
  domain.insert({
      &*function.body.instructions.cbegin(),
      map_from_vars_to_values_t(variables)
      });

  for (auto const&  instr : function.body.instructions)
    domain.insert({
        &instr,
        map_from_vars_to_values_t(std::unordered_set<std::string>{})
        });
}

/**
 *
 */
void  initialise_solver_workset(
    goto_functionst::goto_functiont const&  function,
    solver_work_set_t&  work_set
    )
{
  for (auto const&  instr : function.body.instructions)
    work_set.insert(&instr);
}



}}}}

namespace sumfn { namespace taint {


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

  detail::solver_domain_t  domain;
  detail::initialise_solver_domain(fn_iter->second,domain);

  detail::solver_work_set_t  work_set;
  detail::initialise_solver_workset(fn_iter->second,work_set);
  while (!work_set.empty())
  {
    // TODO!
    break;
  }

  return std::make_shared<summary_t>();
}


}}


//void  map_from_vars_to_values_t::transform(
//    locationt from,
//    locationt to,
//    ai_baset &ai,
//    const namespacet &ns
//    )
//{
//  // TODO!
//}
//
//void map_from_vars_to_values_t::make_bottom()
//{
//  std::unordered_set<std::string>  variables;
//  for (auto const&  elem : m_from_vars_to_values)
//    variables.insert(elem.first);
//  m_from_vars_to_values.clear();
//  for (auto const&  var : variables)
//    m_from_vars_to_values.insert({
//        as_string(var),
//        value_of_variable_t::make_bottom()
//        });
//}
//
//void map_from_vars_to_values_t::make_top()
//{
//  std::unordered_set<std::string>  variables;
//  for (auto const&  elem : m_from_vars_to_values)
//    variables.insert(elem.first);
//  m_from_vars_to_values.clear();
//  for (auto const&  var : variables)
//    m_from_vars_to_values.insert({
//        as_string(var),
//        value_of_variable_t::make_top()
//        });
//}
//
//void map_from_vars_to_values_t::make_entry()
//{
//  make_bottom();
//}


//summary_domain_t  merge(
//    summary_domain_t const&  left,
//    summary_domain_t const&  right,
//    goto_programt::const_targett const  from,
//    goto_programt::const_targett const  to
//    )
//{
//  // TODO!
//  return left;
//}


//struct  taint_summary_solver_t// : public ai<summary_domain_t>
//{
//
//};
