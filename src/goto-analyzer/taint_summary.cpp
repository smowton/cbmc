/////////////////////////////////////////////////////////////////////////////
//
// Module: taint_summary
// Author: Marek Trtik
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////


#include <goto-analyzer/taint_summary.h>
#include <goto-analyzer/taint_summary_dump.h>
#include <summaries/summary_dump.h>
#include <util/std_types.h>
#include <util/file_util.h>
#include <util/msgstream.h>
#include <analyses/ai.h>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cassert>
#include <stdexcept>

#include <iostream>


namespace sumfn { namespace taint { namespace detail { namespace {


/**
 *
 */
value_of_variable_t  make_symbol()
{
  static uint64_t  counter = 0UL;
  std::string const  symbol_name =
      msgstream() << "T" << ++counter;
  return {{symbol_name},false,false};
}

/**
 *
 */
value_of_variable_t  make_bottom()
{
  return {expression_t{},true,false};
}

/**
 *
 */
value_of_variable_t  make_top()
{
  return {expression_t{},false,true};
}


/**
 *
 */
using  solver_work_set_t =
    std::unordered_set<instruction_iterator_t,
                       detail::instruction_iterator_hasher>;


/**
 *
 */
void  initialise_domain(
    goto_functionst::goto_functiont const&  function,
    domain_t&  domain
    )
{
  std::unordered_set<variable_id_t>  variables;
  for (auto const&  param : to_code_type(function.type).parameters())
    variables.insert(as_string(param.get_identifier()));
  domain.insert({
      function.body.instructions.cbegin(),
      map_from_vars_to_values_t(variables)
      });

  for (auto  it = function.body.instructions.cbegin();
       it != function.body.instructions.cend();
       ++it)
    domain.insert({
        it,
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
  for (auto  it = function.body.instructions.cbegin();
       it != function.body.instructions.cend();
       ++it)
    work_set.insert(it);
}


void  __dbg_learn_goto_model_stuff(goto_modelt const&  model)
{
  //namespacet const  ns(instrumented_program.symbol_table);
  for (auto const&  id_sym : model.symbol_table.symbols)
    std::cout << "  " << id_sym.first << " -> " << id_sym.second.name << "\n";

}

void  collect_identifiers(
    exprt const&  expr,
    std::unordered_set<std::string>&  result
    )
{
  if (expr.id() == ID_symbol)
    result.insert( as_string(to_symbol_expr(expr).get_identifier()) );
  else
    for (exprt const&  op : expr.operands())
      collect_identifiers(op,result);
}


}}}}

namespace sumfn { namespace taint {


value_of_variable_t::value_of_variable_t(
    expression_t const&  expression,
    bool  is_bottom,
    bool  is_top
    )
  : m_expression(expression)
  , m_is_bottom(is_bottom)
  , m_is_top(is_top)
{
  assert((m_is_bottom && m_is_top) == false);
}


bool  operator==(
    value_of_variable_t const&  a,
    value_of_variable_t const&  b)
{
  return a.is_top() == b.is_top() &&
         a.is_bottom() == b.is_bottom() &&
         a.expression() == b.expression()
         ;
}

bool  operator<(
    value_of_variable_t const&  a,
    value_of_variable_t const&  b)
{
  if (a.is_top() || b.is_bottom())
    return false;
  if (a.is_bottom() || b.is_top())
    return true;
  return std::includes(b.expression().cbegin(),b.expression().cend(),
                       a.expression().cbegin(),a.expression().cend());
}

value_of_variable_t  join(
    value_of_variable_t const&  a,
    value_of_variable_t const&  b)
{
  if (a.is_bottom())
    return b;
  if (b.is_bottom())
    return a;
  if (a.is_top())
    return a;
  if (b.is_top())
    return b;
  expression_t  result_set = a.expression();
  result_set.insert(b.expression().cbegin(),b.expression().cend());
  return {result_set,false,false};
}


map_from_vars_to_values_t::map_from_vars_to_values_t(
    dictionary_t const&  data
    )
  : m_from_vars_to_values(data)
{}

map_from_vars_to_values_t::map_from_vars_to_values_t(
    std::unordered_set<variable_id_t> const&  variables
    )
  : m_from_vars_to_values()
{
  for (auto const&  var : variables)
    m_from_vars_to_values.insert({ var, detail::make_symbol() });
}

void  map_from_vars_to_values_t::assign(variable_id_t const&  var_name,
                                        value_of_variable_t const&  value)
{
  auto const  it = m_from_vars_to_values.find(var_name);
  if (it == m_from_vars_to_values.end())
    m_from_vars_to_values.insert({var_name,value});
  else
    it->second = value;
}

void  map_from_vars_to_values_t::erase(
    std::unordered_set<variable_id_t> const&  vars
    )
{
  for (auto const&  var : vars)
    m_from_vars_to_values.erase(var);
}


bool  operator==(
    map_from_vars_to_values_t const&  a,
    map_from_vars_to_values_t const&  b)
{
  auto  a_it = a.data().cbegin();
  auto  b_it = b.data().cbegin();
  for ( ;
       a_it != a.data().cend() && b_it != b.data().cend() &&
       a_it->first == b_it->first && a_it->second == b_it->second;
       ++a_it, ++b_it)
    ;
  return a_it == a.data().cend() && b_it == b.data().cend();
}


bool  operator<(
    map_from_vars_to_values_t const&  a,
    map_from_vars_to_values_t const&  b)
{
  if (b.data().empty())
    return false;
  for (auto  a_it = a.data().cbegin(); a_it != a.data().cend(); ++a_it)
  {
    auto const  b_it = b.data().find(a_it->first);
    if (b_it == b.data().cend())
      return false;
    if (!(a_it->second < b_it->second))
      return false;
  }
  return true;
}


map_from_vars_to_values_t  transform(
    map_from_vars_to_values_t const&  a,
    goto_programt::instructiont const&  I,
    namespacet const&  ns,
    std::ostream* const  log
    )
{
  map_from_vars_to_values_t  result = a;
  switch(I.type)
  {
  case ASSIGN:
    {
      if (log != nullptr)
        *log << "<p>\nRecognised ASSIGN instruction.\n";

      code_assignt const&  asgn = to_code_assign(I.code);

      value_of_variable_t  rvalue = detail::make_bottom();
      {
        std::unordered_set<std::string>  rhs;
        detail::collect_identifiers(asgn.rhs(),rhs);

        if (log != nullptr)
        {
          *log << "r-values identifiers are {";
          for (auto const&  ident : rhs)
            *log << ident << ", ";
          *log << "}.\n";
        }

        for (std::string const&  ident : rhs)
        {
          auto const  it = a.data().find(ident);
          if (it != a.data().cend())
            rvalue = join(rvalue,it->second);
        }
      }

      std::unordered_set<std::string>  lhs;
      detail::collect_identifiers(asgn.lhs(),lhs);

      if (log != nullptr)
      {
        *log << "l-values identifiers are {";
        for (auto const&  ident : lhs)
          *log << ident << ", ";
        *log << "}.\n</p>\n";
      }

      for (std::string const&  ident : lhs)
        result.assign(ident,rvalue);
    }
    break;
  case DEAD:
    {
      code_deadt const&  dead = to_code_dead(I.code);
      std::unordered_set<std::string>  vars;
      detail::collect_identifiers(dead.symbol(),vars);
      result.erase(vars);
//      if (dead.symbol().type().id() == ID_pointer)
//        ...
    }
    break;
  case GOTO:
  case NO_INSTRUCTION_TYPE:
  case SKIP:
  case END_FUNCTION:
  case RETURN:
  case OTHER:
  case DECL:
  case FUNCTION_CALL:
  case ASSUME:
  case ASSERT:
  case LOCATION:
  case THROW:
  case CATCH:
  case ATOMIC_BEGIN:
  case ATOMIC_END:
  case START_THREAD:
  case END_THREAD:
    break;
  default:
    throw std::runtime_error("ERROR: In 'sumfn::taint::transform' - "
                             "Unknown instruction!");
    break;
  }
  return result;
}


map_from_vars_to_values_t  join(
    map_from_vars_to_values_t const&  a,
    map_from_vars_to_values_t const&  b
    )
{
  map_from_vars_to_values_t::dictionary_t  result_dict = b.data();
  for (auto  a_it = a.data().cbegin(); a_it != a.data().cend(); ++a_it)
  {
    auto const  r_it = result_dict.find(a_it->first);
    if (r_it == result_dict.cend())
      result_dict.insert(*a_it);
    else
      r_it->second = join(a_it->second,r_it->second);
  }
  return map_from_vars_to_values_t{ result_dict };
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
    database_of_summaries_t&  summaries_to_compute,
    std::ostream* const  log
    )
{
  //detail::__dbg_learn_goto_model_stuff(instrumented_program);
  for (auto const&  elem : instrumented_program.goto_functions.function_map)
    if (elem.second.body_available())
      summaries_to_compute.insert({
          as_string(elem.first),
          summarise_function(elem.first,instrumented_program,log),
          });
}

summary_ptr_t  summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    std::ostream* const  log
    )
{
  if (log != nullptr)
    *log << "<h2>Called sumfn::taint::summarise_function( "
         << to_html_text(as_string(function_id)) << " )</h2>\n"
         ;

  goto_functionst::function_mapt const&  functions =
      instrumented_program.goto_functions.function_map;
  auto const  fn_iter = functions.find(function_id);

  namespacet const  ns(instrumented_program.symbol_table);

  assert(fn_iter != functions.cend());
  assert(fn_iter->second.body_available());

  domain_ptr_t  domain = std::make_shared<domain_t>();
  detail::initialise_domain(fn_iter->second,*domain);

  detail::solver_work_set_t  work_set;
  detail::initialise_workset(fn_iter->second,work_set);
  while (!work_set.empty())
  {
    instruction_iterator_t const  src_instr_it = *work_set.cbegin();
    work_set.erase(work_set.cbegin());

    map_from_vars_to_values_t const&  src_value = domain->at(src_instr_it);

    goto_programt::const_targetst successors;
    fn_iter->second.body.get_successors(src_instr_it, successors);
    for(auto  succ_it = successors.begin();
        succ_it != successors.end();
        ++succ_it)
      if (*succ_it != fn_iter->second.body.instructions.cend())
      {
        instruction_iterator_t const  dst_instr_it = *succ_it;
        map_from_vars_to_values_t&  dst_value = domain->at(dst_instr_it);
        map_from_vars_to_values_t const  old_dst_value = dst_value;

        if (log != nullptr)
        {
          *log << "<h3>Processing transition: "
               << src_instr_it->location_number << " ---[ "
               ;
          dump_instruction_code_in_html(
              *src_instr_it,
              instrumented_program,
              *log
              );
          *log << " ]---> " << dst_instr_it->location_number << "</h3>\n"
               ;
          *log << "<p>Source value:</p>\n";
          dump_vars_to_values_in_html(src_value,*log);
          *log << "<p>Old destination value:</p>\n";
          dump_vars_to_values_in_html(old_dst_value,*log);
        }

        map_from_vars_to_values_t const  transformed =
            transform(src_value,*src_instr_it,ns,log);
        dst_value = join(transformed,dst_value);

        if (log != nullptr)
        {
          *log << "<p>Transformed value:</p>\n";
          dump_vars_to_values_in_html(transformed,*log);
          *log << "<p>Resulting destination value:</p>\n";
          dump_vars_to_values_in_html(dst_value,*log);

//          if (src_instr_it->location_number == 3 &&
//              dst_instr_it->location_number == 4)
//          {
//            *log << "<p>COMPARE!!!</p>\n";
//            *log << "<p>old_dst_value:</p>\n";
//            dump_vars_to_values_in_html(old_dst_value,*log);
//            *log << "<p>dst_value:</p>\n";
//            dump_vars_to_values_in_html(dst_value,*log);
//            *log << "<p>dst_value <= old_dst_value:"
//                 << (dst_value <= old_dst_value)
//                 << "</p>\n";
//            *log << "<p>dst_value == old_dst_value:"
//                 << (dst_value == old_dst_value)
//                 << "</p>\n";
//            *log << "<p>dst_value < old_dst_value:"
//                 << (dst_value < old_dst_value)
//                 << "</p>\n";
//          }
        }

        if (!(dst_value <= old_dst_value))
        {
          work_set.insert(dst_instr_it);

          if (log != nullptr)
            *log << "<p>Inserting instruction at location "
                 << dst_instr_it->location_number << " into 'work_set'.</p>\n"
                 ;
        }
      }
  }
  return std::make_shared<summary_t>(domain);
}


}}
