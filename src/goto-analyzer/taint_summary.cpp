/*******************************************************************\

Module: taint_summary

Author: Marek Trtik

Date: September 2016

This module defines interfaces and functionality for taint summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_summary.h>
#include <goto-analyzer/taint_summary_dump.h>
#include <summaries/utility.h>
#include <summaries/summary_dump.h>
#include <pointer-analysis/local_value_set_analysis.h>
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


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
static void  initialise_domain(
    irep_idt const&  function_id,
    goto_functionst::goto_functiont const&  function,
    goto_functionst::function_mapt const&  functions_map,
    namespacet const&  ns,
    database_of_summariest const&  database,
    taint_symmary_domaint&  domain,
    std::ostream* const  log
    )
{
  taint_lvalues_sett  environment;
  {
    for (auto  it = function.body.instructions.cbegin();
         it != function.body.instructions.cend();
         ++it)
      if (it->type == ASSIGN)
      {
        code_assignt const&  asgn = to_code_assign(it->code);
        environment.insert(normalise(asgn.lhs(),ns));
        collect_access_paths(asgn.rhs(),ns,environment);
      }
      else if (it->type == FUNCTION_CALL)
      {
        code_function_callt const&  fn_call = to_code_function_call(it->code);
        if (fn_call.function().id() == ID_symbol)
        {
          std::string const  callee_ident =
              as_string(to_symbol_expr(fn_call.function()).get_identifier());

          auto const&  fn_type = functions_map.at(callee_ident).type;

          taint_summary_ptrt const  summary =
              database.find<taint_summaryt>(callee_ident);
          if (summary.operator bool())
            for (auto const&  lvalue_svalue : summary->input())
              if (!is_parameter(lvalue_svalue.first,ns) &&
                  !is_return_value_auxiliary(lvalue_svalue.first,ns))
                environment.insert(
                      scope_translation(
                          lvalue_svalue.first,
                          callee_ident,
                          function_id,
                          fn_call,
                          fn_type,
                          ns
                          )
                      );
        }
      }
  }

  taint_map_from_lvalues_to_svaluest  entry_map;
  taint_map_from_lvalues_to_svaluest  others_map;
  for (taint_lvaluet const&  lvalue : environment)
    if (!is_pure_local(lvalue,ns) &&
        !is_return_value_auxiliary(lvalue,ns) &&
        !is_this(lvalue,ns))
    {
      entry_map.insert({lvalue, taint_make_symbol() });
      others_map.insert({lvalue, taint_make_bottom() });
    }

  domain.insert({function.body.instructions.cbegin(),entry_map});
  for (auto  it = std::next(function.body.instructions.cbegin());
       it != function.body.instructions.cend();
       ++it)
    domain.insert({it,others_map});

  if (log != nullptr)
  {
    *log << "<h3>Initialising the domain</h3>\n"
            "<p>Domain value at the entry location:</p>\n"
         ;
    taint_dump_lvalues_to_svalues_in_html(
        domain.at(function.body.instructions.cbegin()),
        ns,
        *log
        );
    *log << "<p>Domain value at all other locations:</p>\n";
    taint_dump_lvalues_to_svalues_in_html(
        domain.at(std::prev(function.body.instructions.cend())),
        ns,
        *log
        );
  }
}


/*******************************************************************\
\*******************************************************************/
typedef std::unordered_set<instruction_iteratort,
                           instruction_iterator_hashert>
        solver_work_set_t;


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
static void  initialise_workset(
    goto_functionst::goto_functiont const&  function,
    solver_work_set_t&  work_set
    )
{
  for (auto  it = function.body.instructions.cbegin();
       it != function.body.instructions.cend();
       ++it)
    work_set.insert(it);
}


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
static void  erase_dead_lvalue(
    taint_lvaluet const&  lvalue,
    namespacet const&  ns,
    taint_map_from_lvalues_to_svaluest&  map
    )
{
  if (map.erase(lvalue) == 0ULL && lvalue.id() == ID_symbol)
  {
    irep_idt const&  ident = to_symbol_expr(lvalue).get_identifier();
    for (auto  it = map.begin(); it != map.end(); ++it)
      if (is_pure_local(it->first,ns) && it->first.id() == ID_symbol &&
          to_symbol_expr(it->first).get_identifier() == ident)
      {
        map.erase(it);
        return;
      }
  }
}


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
static void  build_symbols_substitution(
    std::unordered_map<taint_svaluet::taint_symbolt,taint_svaluet>&
        symbols_substitution,
    taint_map_from_lvalues_to_svaluest const&  a,
    taint_summary_ptrt const  summary,
    irep_idt const&  caller_ident,
    code_function_callt const&  fn_call,
    code_typet const&  fn_type,
    namespacet const&  ns,
    std::ostream* const  log
    )
{
  if (log != nullptr)
    *log << "<p>Building 'symbols substitution map':</p>\n"
            "<ul>\n";

  std::unordered_map<std::string,std::size_t>  parameter_indices;
  for (std::size_t  i = 0UL; i != fn_type.parameters().size(); ++i)
    parameter_indices.insert({
          as_string(fn_type.parameters().at(i).get_identifier()),
          i
          });

  std::string const  callee_ident =
      as_string(to_symbol_expr(fn_call.function()).get_identifier());

  for (auto const&  lvalue_svalue : summary->input())
  {
    assert(!lvalue_svalue.second.is_top());
    assert(!lvalue_svalue.second.is_bottom());
    assert(lvalue_svalue.second.expression().size() == 1UL);

    if (is_parameter(lvalue_svalue.first,ns))
    {
      std::size_t  param_idx;
      {
        auto const  it = parameter_indices.find(
              name_of_symbol_access_path(lvalue_svalue.first)
              );
        assert(it != parameter_indices.cend());
        param_idx = it->second;
      }

      assert(param_idx < fn_call.arguments().size());

      taint_svaluet  argument_svalue = taint_make_bottom();
      {
        taint_lvalues_sett  argument_lvalues;
        collect_access_paths(
              fn_call.arguments().at(param_idx),
              ns,
              argument_lvalues
              );
        for (auto const&  lvalue : argument_lvalues)
        {
          auto const  it = a.find(lvalue);
          if (it != a.cend())
            argument_svalue = join(argument_svalue,it->second);
        }
      }

      symbols_substitution.insert({
          *lvalue_svalue.second.expression().cbegin(),
          argument_svalue
          });

      if (log != nullptr)
      {
        *log << "<li>From parameter no. " << param_idx << "(lvalue=";
        taint_dump_lvalue_in_html(lvalue_svalue.first,ns,*log);
        *log << "): "
             << *lvalue_svalue.second.expression().cbegin()
             << " &rarr; "
             ;
        taint_dump_svalue_in_html(argument_svalue,*log);
        *log << "</li>\n";
      }
    }
    else
    {
      taint_lvaluet const  translated_lvalue = scope_translation(
            lvalue_svalue.first,
            callee_ident,
            caller_ident,
            fn_call,
            fn_type,
            ns
            );
      auto const  it = a.find(translated_lvalue);
      if (it != a.cend())
      {
        symbols_substitution.insert({
            *lvalue_svalue.second.expression().cbegin(),
            it->second
            });

        if (log != nullptr)
        {
          *log << "<li>From exterior scope of the function (lvalue=";
          taint_dump_lvalue_in_html(lvalue_svalue.first,ns,*log);
          *log << "): "
               << *lvalue_svalue.second.expression().cbegin()
               << " &rarr; "
               ;
          taint_dump_svalue_in_html(it->second,*log);
          *log << "</li>\n";
        }
      }
      else
        if (log != nullptr)
        {
          *log << "<li>SKIPPING lvalue '";
          taint_dump_lvalue_in_html(lvalue_svalue.first,ns,*log);
          *log << "'.</li>\n";
        }
    }
  }

  if (log != nullptr)
    *log << "</ul>\n";
}


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
static void  build_substituted_summary(
    taint_map_from_lvalues_to_svaluest&  substituted_summary,
    taint_map_from_lvalues_to_svaluest const&  original_summary,
    std::unordered_map<taint_svaluet::taint_symbolt,taint_svaluet> const&
        symbols_substitution,
    irep_idt const&  caller_ident,
    irep_idt const&  callee_ident,
    code_function_callt const&  fn_call,
    code_typet const&  fn_type,
    namespacet const&  ns,
    std::ostream* const  log
    )
{
  for (auto const&  lvalue_svalue : original_summary)
  {
    taint_lvaluet const  translated_lvalue = scope_translation(
          lvalue_svalue.first,
          callee_ident,
          caller_ident,
          fn_call,
          fn_type,
          ns
          );
    if (!is_empty(translated_lvalue))
    {
      if (lvalue_svalue.second.is_bottom() || lvalue_svalue.second.is_top())
        substituted_summary.insert({translated_lvalue,lvalue_svalue.second});
      else
      {
        taint_svaluet  substituted_svalue = taint_make_bottom();
        for (auto const&  symbol : lvalue_svalue.second.expression())
        {
          auto const  it = symbols_substitution.find(symbol);
          if (it != symbols_substitution.cend())
            substituted_svalue = join(substituted_svalue,it->second);
          else
            substituted_svalue =
                join(substituted_svalue,{{symbol},false,false});
        }
        substituted_summary.insert({translated_lvalue,substituted_svalue});
      }
    }
  }

  if (log != nullptr)
  {
    *log << "<p>Substituted summary:</p>\n";
    taint_dump_lvalues_to_svalues_in_html(substituted_summary,ns,*log);
  }
}


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
static void  build_summary_from_computed_domain(
    taint_summary_domain_ptrt const  domain,
    taint_map_from_lvalues_to_svaluest&  output,
    goto_functionst::function_mapt::const_iterator const  fn_iter,
    namespacet const&  ns,
    std::ostream* const  log
    )
{
  if (log != nullptr)
    *log << "<h3>Building summary from the computed domain</h3>\n"
         << "<p>It is computed from the symbolic value "
            "at location "
         << std::prev(fn_iter->second.body.instructions.cend())->location_number
         << ":</p>\n<ul>\n"
         ;

  taint_map_from_lvalues_to_svaluest const&  end_svalue =
      domain->at(std::prev(fn_iter->second.body.instructions.cend()));
  for (auto  it = end_svalue.cbegin(); it != end_svalue.cend(); ++it)
    if (!is_pure_local(it->first,ns) && !is_parameter(it->first,ns))
    {
      output.insert(*it);

      if (log != nullptr)
      {
        *log << "<li>";
        taint_dump_lvalue_in_html(it->first,ns,*log);
        *log << " &rarr; ";
        taint_dump_svalue_in_html(it->second,*log);
          *log << "</li>\n";
      }
    }
    else
      if (log != nullptr)
      {
        *log << "<li>!! EXCLUDING !! : ";
        taint_dump_lvalue_in_html(it->first,ns,*log);
        *log << " &rarr; ";
        taint_dump_svalue_in_html(it->second,*log);
        *log << "</li>\n";
      }

  if (log != nullptr)
    *log << "</ul>\n";
}


static void  assign(
    taint_map_from_lvalues_to_svaluest&  map,
    taint_lvaluet const&  lvalue,
    taint_svaluet const&  svalue
    )
{
  auto const  it = map.find(lvalue);
  if (it == map.end())
    map.insert({lvalue,svalue});
  else
    it->second = svalue;
}

static void  maybe_assign(
    taint_map_from_lvalues_to_svaluest&  map,
    taint_lvaluet const&  lvalue,
    taint_svaluet const&  svalue
    )
{
  auto const  it = map.find(lvalue);
  if (it == map.end())
    map.insert({lvalue,svalue});
  else
    it->second = join(it->second,svalue);
}

taint_svaluet  taint_make_symbol()
{
  static uint64_t  counter = 0UL;
  std::string const  symbol_name =
      msgstream() << "T" << ++counter;
  return {{symbol_name},false,false};
}


taint_svaluet  taint_make_bottom()
{
  return {taint_svaluet::expressiont{},true,false};
}


taint_svaluet  taint_make_top()
{
  return {taint_svaluet::expressiont{},false,true};
}


taint_svaluet::taint_svaluet(
    expressiont const&  expression,
    bool  is_bottom,
    bool  is_top
    )
  : m_expression(expression)
  , m_is_bottom(is_bottom)
  , m_is_top(is_top)
{
  assert((m_is_bottom && m_is_top) == false);
  assert(m_is_bottom || m_is_top || !m_expression.empty());
  assert(!(m_is_bottom || m_is_top) || m_expression.empty());
}


taint_svaluet::taint_svaluet(taint_svaluet const&  other)
  : m_expression(other.m_expression)
  , m_is_bottom(other.m_is_bottom)
  , m_is_top(other.m_is_top)
{}


taint_svaluet::taint_svaluet(taint_svaluet&&  other)
  : m_expression(other.m_expression)
  , m_is_bottom(other.m_is_bottom)
  , m_is_top(other.m_is_top)
{}


taint_svaluet&  taint_svaluet::operator=(taint_svaluet const&  other)
{
  m_expression = other.m_expression;
  m_is_bottom = other.m_is_bottom;
  m_is_top = other.m_is_top;
  return *this;
}


taint_svaluet&  taint_svaluet::operator=(taint_svaluet&&  other)
{
  m_expression.swap(other.m_expression);
  m_is_bottom = other.m_is_bottom;
  m_is_top = other.m_is_top;
  return *this;
}


bool  operator==(taint_svaluet const&  a, taint_svaluet const&  b)
{
  return a.is_top() == b.is_top() &&
         a.is_bottom() == b.is_bottom() &&
         a.expression() == b.expression()
         ;
}


bool  operator<(taint_svaluet const&  a, taint_svaluet const&  b)
{
  if (a.is_top() || b.is_bottom())
    return false;
  if (a.is_bottom() || b.is_top())
    return true;
  return std::includes(b.expression().cbegin(),b.expression().cend(),
                       a.expression().cbegin(),a.expression().cend());
}


taint_svaluet  join(taint_svaluet const&  a, taint_svaluet const&  b)
{
  if (a.is_bottom())
    return b;
  if (b.is_bottom())
    return a;
  if (a.is_top())
    return a;
  if (b.is_top())
    return b;
  taint_svaluet::expressiont  result_set = a.expression();
  result_set.insert(b.expression().cbegin(),b.expression().cend());
  return {result_set,false,false};
}


bool  operator==(
    taint_map_from_lvalues_to_svaluest const&  a,
    taint_map_from_lvalues_to_svaluest const&  b)
{
  auto  a_it = a.cbegin();
  auto  b_it = b.cbegin();
  for ( ;
       a_it != a.cend() && b_it != b.cend() &&
       a_it->first == b_it->first && a_it->second == b_it->second;
       ++a_it, ++b_it)
    ;
  return a_it == a.cend() && b_it == b.cend();
}


bool  operator<(
    taint_map_from_lvalues_to_svaluest const&  a,
    taint_map_from_lvalues_to_svaluest const&  b)
{
  if (b.empty())
    return false;
  for (auto  a_it = a.cbegin(); a_it != a.cend(); ++a_it)
  {
    auto const  b_it = b.find(a_it->first);
    if (b_it == b.cend())
      return false;
    if (!(a_it->second < b_it->second))
      return false;
  }
  return true;
}

static void collect_referee_access_paths(
  exprt const& e,
  namespacet const& ns,
  taint_lvalues_sett& result,
  taint_map_from_lvalues_to_svaluest const& all_keys)
{
  if(e.id()==ID_member)
  {
    taint_lvalues_sett newresults;
    collect_referee_access_paths(e.op0(),ns,newresults,all_keys);
    for(const auto& res : newresults)
      result.insert(member_exprt(res,to_member_expr(e).get_component_name(),e.type()));
  }
  else
  {
    if(e.id()=="external-value-set")
    {

      const auto& evse=to_external_value_set(e);
      const auto& label=to_constant_expr(evse.label()).get_value();
      if(label=="external_objects")
      {
        assert(evse.access_path_size()==1);
        std::string fieldname=id2string(evse.access_path_back().label());
        assert(fieldname.size()>=2);
        assert(fieldname[0]=='.');
        fieldname=fieldname.substr(1);
        // This represents a given field of all objects
        // preceding entering this function.
        // Return all known keys that match the field.
        for(const auto& keyval : all_keys)
        {
          const auto& key=keyval.first;
          if(key.id()==ID_member)
          {
            auto key_field=to_member_expr(key).get_component_name();
            if(key_field==fieldname)
              result.insert(key);
          }
        }
      }
      else
      {
        // This represents the referees of a pointer retrieved
        // from a named parameter or global variable, as they were
        // at the time the function was entered.
        const symbolt& sym=ns.lookup(label);
        auto symexpr=sym.symbol_expr();
        assert(sym.type.id()==ID_pointer);
        result.insert(dereference_exprt(symexpr,sym.type.subtype()));
      }
    }
    else
    {
      // Dynamic object expression, or static symbol.
      result.insert(e);
    }
  }
}

static void collect_lvsa_access_paths(
  exprt const& e,
  namespacet const& ns,
  taint_lvalues_sett& result,
  local_value_set_analysist& lvsa,
  taint_map_from_lvalues_to_svaluest const& all_keys,
  instruction_iteratort const& instit)
{
  value_setst::valuest referees;
  lvsa.get_values(instit,address_of_exprt(e),referees);
  for(const auto& target : referees)
    collect_referee_access_paths(target,ns,result,all_keys);
}

taint_map_from_lvalues_to_svaluest  transform(
    taint_map_from_lvalues_to_svaluest const&  a,
    instruction_iteratort const& Iit,
    irep_idt const&  caller_ident,
    goto_functionst::function_mapt const&  functions_map,
    database_of_summariest const&  database,
    local_value_set_analysist* lvsa,
    namespacet const&  ns,
    std::ostream* const  log
    )
{
  goto_programt::instructiont const&  I=*Iit;
  taint_map_from_lvalues_to_svaluest  result = a;
  switch(I.type)
  {
  case ASSIGN:
    {
      code_assignt const&  asgn = to_code_assign(I.code);

      if (log != nullptr)
      {
        *log << "<p>\nRecognised ASSIGN instruction. Left-hand-side "
                "l-value is { ";
        taint_dump_lvalue_in_html(normalise(asgn.lhs(),ns),ns,*log);
        *log << " }. Right-hand-side l-values are { ";
      }

      taint_svaluet  rvalue = taint_make_bottom();
      {
        taint_lvalues_sett  rhs;
        if(!lvsa)
          collect_access_paths(asgn.rhs(),ns,rhs);
        else
          collect_lvsa_access_paths(asgn.rhs(),ns,rhs,*lvsa,result,Iit);
        for (auto const&  lvalue : rhs)
        {
          auto const  it = a.find(lvalue);
          if (it != a.cend())
            rvalue = join(rvalue,it->second);

          if (log != nullptr)
          {
            taint_dump_lvalue_in_html(lvalue,ns,*log);
            *log << ", ";
          }
        }
      }

      if (log != nullptr)
        *log << "}.</p>\n";

      if(!lvsa)
        assign(result,normalise(asgn.lhs(),ns),rvalue);
      else {
        taint_lvalues_sett lhs;
        collect_lvsa_access_paths(asgn.lhs(),ns,lhs,*lvsa,result,Iit);
        for(const auto& path : lhs)
        {
          if(lhs.size()==1)
            maybe_assign(result,normalise(path,ns),rvalue);
          else
            assign(result,normalise(path,ns),rvalue);
        }
      }
    }
    break;
  case FUNCTION_CALL:
    {
      code_function_callt const&  fn_call = to_code_function_call(I.code);
      if (fn_call.function().id() == ID_symbol)
      {
        if (log != nullptr)
          *log << "<p>Recognised FUNCTION_CALL instruction.</p>\n";

        std::string const  callee_ident =
            as_string(to_symbol_expr(fn_call.function()).get_identifier());

        taint_summary_ptrt const  summary =
            database.find<taint_summaryt>(callee_ident);
        if (summary.operator bool())
        {
          auto const&  fn_type = functions_map.at(callee_ident).type;

          taint_map_from_lvalues_to_svaluest  substituted_summary;
          {
            std::unordered_map<taint_svaluet::taint_symbolt,taint_svaluet>
                symbols_substitution;
            build_symbols_substitution(
                  symbols_substitution,
                  a,
                  summary,
                  caller_ident,
                  fn_call,
                  fn_type,
                  ns,
                  log
                  );
            build_substituted_summary(
                  substituted_summary,
                  summary->output(),
                  symbols_substitution,
                  caller_ident,
                  callee_ident,
                  fn_call,
                  fn_type,
                  ns,
                  log
                  );
          }
          result = join(result,substituted_summary);
        }
        else
          if (log != nullptr)
            *log << "<p>!!! WARNING !!! : No summary was found for the called "
                    "function " << as_string(callee_ident) << "So, we use "
                    "identity as a transformation function.</p>\n";
      }
      else
        if (log != nullptr)
          *log << "<p>!!! WARNING !!! : Recognised FUNCTION_CALL instruction "
                  "using non-identifier call expression. Such call is not "
                  "supported. So, we use identity as a transformation "
                  "function.</p>\n";
    }
    break;
  case DEAD:
    {
      code_deadt const&  dead = to_code_dead(I.code);

      if (log != nullptr)
        *log << "<p>\nRecognised DEAD instruction. Removing these l-values { ";

      taint_lvalues_sett  lvalues;
      collect_access_paths(dead.symbol(),ns,lvalues);
      for (auto const&  lvalue : lvalues)
      {
        erase_dead_lvalue(lvalue,ns,result);

        if (log != nullptr)
        {
          taint_dump_lvalue_in_html(lvalue,ns,*log);
          *log << ", ";
        }
      }

      if (log != nullptr)
        *log << "}.</p>\n";
    }
    break;
  case NO_INSTRUCTION_TYPE:
    if (log != nullptr)
      *log << "<p>Recognised NO_INSTRUCTION_TYPE instruction. "
              "The transformation function is identity.</p>\n";
    break;
  case SKIP:
    if (log != nullptr)
      *log << "<p>Recognised SKIP instruction. "
              "The transformation function is identity.</p>\n";
    break;
  case END_FUNCTION:
    if (log != nullptr)
      *log << "<p>Recognised END_FUNCTION instruction. "
              "The transformation function is identity.</p>\n";
    break;
  case GOTO:
    if (log != nullptr)
      *log << "<p>Recognised GOTO instruction. "
              "The transformation function is identity.</p>\n";
    break;
  case RETURN:
  case OTHER:
  case DECL:
  case ASSUME:
  case ASSERT:
  case LOCATION:
  case THROW:
  case CATCH:
  case ATOMIC_BEGIN:
  case ATOMIC_END:
  case START_THREAD:
  case END_THREAD:
    if (log != nullptr)
      *log << "<p>!!! WARNING !!! : Unsupported instruction reached. "
              "So, we use identity as a transformation function.</p>\n";
    break;
    break;
  default:
    throw std::runtime_error("ERROR: In 'sumfn::taint::transform' - "
                             "Unknown instruction!");
    break;
  }
  return result;
}


taint_map_from_lvalues_to_svaluest  join(
    taint_map_from_lvalues_to_svaluest const&  a,
    taint_map_from_lvalues_to_svaluest const&  b
    )
{
  taint_map_from_lvalues_to_svaluest  result_dict = b;
  for (auto  a_it = a.cbegin(); a_it != a.cend(); ++a_it)
  {
    auto const  r_it = result_dict.find(a_it->first);
    if (r_it == result_dict.cend())
      result_dict.insert(*a_it);
    else
      r_it->second = join(a_it->second,r_it->second);
  }
  return taint_map_from_lvalues_to_svaluest{ result_dict };
}


taint_summaryt::taint_summaryt(
    taint_map_from_lvalues_to_svaluest const&  input,
    taint_map_from_lvalues_to_svaluest const&  output,
    taint_summary_domain_ptrt const  domain
    )
  : m_input(input)
  , m_output(output)
  , m_domain(domain)
{
}

std::string  taint_summaryt::kind() const noexcept
{
  return "cbmc://src/goto-analyzer/taint_summary";
}

std::string  taint_summaryt::description() const noexcept
{
  return "Function summary of taint analysis of java web applications.";
}



void  taint_summarise_all_functions(
    goto_modelt const&  instrumented_program,
    database_of_summariest&  summaries_to_compute,
    call_grapht const&  call_graph,
    std::ostream* const  log,
    const std::string& lvsa_directory,
    message_handlert& msg
    )
{
  std::vector<irep_idt>  inverted_topological_order;
  {
    std::unordered_set<irep_idt,dstring_hash>  processed;
    for (auto const&  elem : instrumented_program.goto_functions.function_map)
      inverted_partial_topological_order(
            call_graph,
            elem.first,
            processed,
            inverted_topological_order
            );
  }
  for (auto const&  fn_name : inverted_topological_order)
  {
    goto_functionst::function_mapt  const  functions_map =
        instrumented_program.goto_functions.function_map;
    auto const  fn_it = functions_map.find(fn_name);
    if (fn_it != functions_map.cend() && fn_it->second.body_available())
      summaries_to_compute.insert({
          as_string(fn_name),
          taint_summarise_function(
              fn_name,
              instrumented_program,
              summaries_to_compute,
              log,
              lvsa_directory,
              msg
              ),
          });
  }
}

taint_summary_ptrt  taint_summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    database_of_summariest const&  database,
    std::ostream* const  log,
    const std::string& lvsa_directory,
    message_handlert& msg
    )
{
  if (log != nullptr)
    *log << "<h2>Called sumfn::taint::taint_summarise_function( "
         << to_html_text(as_string(function_id)) << " )</h2>\n"
         ;

  goto_functionst::function_mapt const&  functions =
      instrumented_program.goto_functions.function_map;
  auto const  fn_iter = functions.find(function_id);

  namespacet const  ns(instrumented_program.symbol_table);

  assert(fn_iter != functions.cend());
  assert(fn_iter->second.body_available());

  local_value_set_analysist lvsainst(ns,fn_iter->second.type,id2string(function_id),
                                     lvsa_directory,LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET);
  local_value_set_analysist* lvsa=lvsa_directory=="" ? NULL : &lvsainst;
  if(lvsa)
  {
    lvsainst.set_message_handler(msg);
    lvsainst(fn_iter->second.body);
  }
  
  taint_summary_domain_ptrt  domain = std::make_shared<taint_symmary_domaint>();
  initialise_domain(
        function_id,
        fn_iter->second,
        functions, 
        ns,
        database,
        *domain,
        log
        );

  taint_map_from_lvalues_to_svaluest  input =
      domain->at(fn_iter->second.body.instructions.cbegin());

  solver_work_set_t  work_set;
  initialise_workset(fn_iter->second,work_set);
  while (!work_set.empty())
  {
    instruction_iteratort const  src_instr_it = *work_set.cbegin();
    work_set.erase(work_set.cbegin());

    taint_map_from_lvalues_to_svaluest const&  src_value =
        domain->at(src_instr_it);

    goto_programt::const_targetst successors;
    fn_iter->second.body.get_successors(src_instr_it, successors);
    for(auto  succ_it = successors.begin();
        succ_it != successors.end();
        ++succ_it)
      if (*succ_it != fn_iter->second.body.instructions.cend())
      {
        instruction_iteratort const  dst_instr_it = *succ_it;
        taint_map_from_lvalues_to_svaluest&  dst_value =
            domain->at(dst_instr_it);
        taint_map_from_lvalues_to_svaluest const  old_dst_value = dst_value;

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
          taint_dump_lvalues_to_svalues_in_html(src_value,ns,*log);
          *log << "<p>Old destination value:</p>\n";
          taint_dump_lvalues_to_svalues_in_html(old_dst_value,ns,*log);
        }

        taint_map_from_lvalues_to_svaluest const  transformed =
            transform(
                src_value,
                src_instr_it,
                function_id,
                functions,
                database,
                lvsa,
                ns,
                log
                );
        dst_value = join(transformed,old_dst_value);

        if (log != nullptr)
        {
          *log << "<p>Transformed value:</p>\n";
          taint_dump_lvalues_to_svalues_in_html(transformed,ns,*log);
          *log << "<p>Resulting destination value:</p>\n";
          taint_dump_lvalues_to_svalues_in_html(dst_value,ns,*log);
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

  taint_map_from_lvalues_to_svaluest  output;
  build_summary_from_computed_domain(
        domain,
        output,
        fn_iter,
        ns,
        log
        );
  return std::make_shared<taint_summaryt>(input,output,domain);
}
