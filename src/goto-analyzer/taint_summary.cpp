/*******************************************************************\

Module: taint_summary

Author: Marek Trtik

Date: September 2016

This module defines interfaces and functionality for taint summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_summary.h>
#include <goto-analyzer/taint_summary_dump.h>
#include <goto-analyzer/taint_statistics.h>
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
#include <chrono>

#include <iostream>

static void collect_lvsa_access_paths(
  exprt const& e,
  namespacet const& ns,
  taint_lvalues_sett& result,
  local_value_set_analysist& lvsa,
  instruction_iteratort const& instit);

struct parameter_matches_id {
  parameter_matches_id(const irep_idt& _id) : id(_id) {}
  bool operator()(const code_typet::parametert& p) const { return id==p.get_identifier(); }
protected:
  const irep_idt id;
};

typedef taint_lvalues_sett written_expressionst;

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
    written_expressionst& written,
    local_value_set_analysist* lvsa,
    std::ostream* const  log
    )
{
  // TODO: Improve this to only count as inputs those values which may be read
  // without a preceding write within the same function.
  taint_lvalues_sett  environment;
  {
    for (auto  it = function.body.instructions.cbegin();
         it != function.body.instructions.cend();
         ++it)
      if (it->type == ASSIGN)
      {
        code_assignt const&  asgn = to_code_assign(it->code);
        if(lvsa)
        {
          collect_lvsa_access_paths(asgn.lhs(),ns,environment,*lvsa,it);
          collect_lvsa_access_paths(asgn.lhs(),ns,written,*lvsa,it);          
          collect_lvsa_access_paths(asgn.rhs(),ns,environment,*lvsa,it);
        }
        else
        {
          exprt lhs=normalise(asgn.lhs(),ns);
          environment.insert(lhs);
          written.insert(lhs);
          collect_access_paths(asgn.rhs(),ns,environment);
        }
      }
      else if (it->type == FUNCTION_CALL)
      {
        code_function_callt const&  fn_call = to_code_function_call(it->code);
        if (fn_call.function().id() == ID_symbol)
        {
          std::string const  callee_ident =
              as_string(to_symbol_expr(fn_call.function()).get_identifier());

          auto const&  fn_type = functions_map.at(callee_ident).type;

	  /*
          for (exprt const&  arg : fn_call.arguments())
          {
            set_of_access_pathst  paths;
            collect_access_paths(arg,ns,paths);
            for (auto const&  path : paths)
              if (!is_pure_local(path,ns) &&
                  !is_return_value_auxiliary(path,ns) &&
                  !is_this(path,ns))
                environment.insert(
                      scope_translation(
                          path,
                          callee_ident,
                          function_id,
                          fn_call,
                          fn_type,
                          ns
                          )
                      );
          }
	  */

          taint_summary_ptrt const  summary =
              database.find<taint_summaryt>(callee_ident);
          if (summary.operator bool())
          {
            for (auto const&  lvalue_svalue : summary->input())
            {
              if (is_parameter(lvalue_svalue.first,ns))
              {
                // Collect access paths for the corresponding actual argument:
                parameter_matches_id match(to_symbol_expr(lvalue_svalue.first).get_identifier());
                auto findit=std::find_if(fn_type.parameters().begin(),
                                         fn_type.parameters().end(),
                                         match);
                assert(findit!=fn_type.parameters().end() && "Parameter symbol doesn't match?");
                const auto paramidx=std::distance(fn_type.parameters().begin(),findit);
                if(lvsa)
                  collect_lvsa_access_paths(fn_call.arguments()[paramidx],ns,environment,
                                            *lvsa,it);
                else
                  collect_access_paths(fn_call.arguments()[paramidx],ns,environment);
              }
              else if (!is_parameter(lvalue_svalue.first,ns) &&
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
            for(auto const&  lvalue_svalue : summary->output())
              written.insert(lvalue_svalue.first);            
          }
        }
      }
  }

  taint_map_from_lvalues_to_svaluest  entry_map;
  taint_map_from_lvalues_to_svaluest  others_map;
  for (taint_lvaluet const&  lvalue : environment)
    if (!is_pure_local(lvalue,ns) &&
        !is_return_value_auxiliary(lvalue,ns) &&
        !is_this(lvalue,ns) &&
        !(get_underlying_object(lvalue).id()==ID_dynamic_object))
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

struct order_by_location_number {
  bool operator()(instruction_iteratort a, instruction_iteratort b)
  {
    return a->location_number < b->location_number;
  }
};

typedef std::set<instruction_iteratort,order_by_location_number>
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

static void expand_external_objects(taint_lvalues_sett& lvalue_set,
                                    taint_map_from_lvalues_to_svaluest const& all_keys)
{
  // Whenever a value like external_value_set("external_objects.x") occurs,
  // expand that to include the 'x' fields of all objects we know about,
  // as what is external to the callee might be local to us.
  // For external_objects[], include all arrays. For now we assume that array-accessed
  // and field-accessed objects are disjoint (true in Java, true for a subset of
  // well-behaved C programs)

  // Leave the external-objects entry there, since it might refer to things that
  // are external to *us* as well.

  // TODO: figure out when an external reference made by the callee
  // is certain to be resolved here, so we can remove the external reference.

  std::vector<exprt> new_keys;
  for(const auto& lval : lvalue_set)
  {
    if(lval.id()=="external-value-set")
    {
      const auto& evse=to_external_value_set(lval);
      const auto& label=to_constant_expr(evse.label()).get_value();
      if(label=="external_objects")
      {
        assert(evse.access_path_size()==1);
        std::string fieldname=id2string(evse.access_path_back().label());
        assert(fieldname.size()>=2);
        if(fieldname[0]=='.')
        {
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
                new_keys.push_back(key);
            }
          }
        }
        else
        {
          assert(fieldname=="[]");
          // Return all array-typed objects we know about.
          // In current taint domain with LVSA, that's anything dynamic without a member operator.
          for(const auto& keyval : all_keys)
          {
            const auto& key=keyval.first;
            if(key.id()==ID_dynamic_object)
              new_keys.push_back(key);
          }
        }
      }
    }
  }

  for(const auto& key : new_keys)
    lvalue_set.insert(key);
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
    local_value_set_analysist* lvsa,
    instruction_iteratort const& Iit,
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

    taint_lvalues_sett  argument_lvalues;
    
    if (is_parameter(lvalue_svalue.first,ns))
    {
      std::size_t  param_idx;
      {
//std::string const  caller = as_string(caller_ident);
        std::string const  param_name =
            name_of_symbol_access_path(lvalue_svalue.first);
        auto const  it = parameter_indices.find(param_name);
        assert(it != parameter_indices.cend());
        param_idx = it->second;
      }

      assert(param_idx < fn_call.arguments().size());

      {
        if(lvsa)
        {
          collect_lvsa_access_paths(
              fn_call.arguments().at(param_idx),
              ns,
              argument_lvalues,
              *lvsa,
              Iit);
        }
        else
        {
          collect_access_paths(
            fn_call.arguments().at(param_idx),
            ns,
            argument_lvalues
            );
        }
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
      argument_lvalues.insert(translated_lvalue);
    }

    expand_external_objects(argument_lvalues,a);
      
    taint_svaluet  argument_svalue = taint_make_bottom();
    for (auto const&  lvalue : argument_lvalues)
    {
      auto const  it = a.find(lvalue);
      if (it != a.cend())
        argument_svalue = join(argument_svalue,it->second);
    }

    symbols_substitution.insert({
        *lvalue_svalue.second.expression().cbegin(),
        argument_svalue
    });

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
    taint_map_from_lvalues_to_svaluest const& local_lvalues,
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
      taint_lvalues_sett lhs_set;
      lhs_set.insert(translated_lvalue);
      expand_external_objects(lhs_set,local_lvalues);
      for(const auto& lhs : lhs_set)
      {
        if (lvalue_svalue.second.is_bottom() || lvalue_svalue.second.is_top())
          substituted_summary.insert({lhs,lvalue_svalue.second});
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
          substituted_summary.insert({
              lhs,
              suppression(substituted_svalue,lvalue_svalue.second.suppression())
              });
        }
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
    written_expressionst const& written,
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
    if ((!is_pure_local(it->first,ns)) && (!is_parameter(it->first,ns)) && written.count(it->first))
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
  : taint_svaluet(expression,{},is_bottom,is_top)
{}

taint_svaluet::taint_svaluet(
    expressiont const&  expression,
    expressiont const&  suppression,
    bool  is_bottom,
    bool  is_top
    )
  : m_expression(expression)
  , m_suppression(suppression)
  , m_is_bottom(is_bottom)
  , m_is_top(is_top)
{
  assert((m_is_bottom && m_is_top) == false);
  assert(m_is_bottom || m_is_top || !m_expression.empty());
  assert(!(m_is_bottom || m_is_top) || m_expression.empty());
  assert(
      [](expressiont const&  A, expressiont const&  B){
        expressiont X;
        std::set_intersection(
            A.cbegin(),A.cend(),
            B.cbegin(),B.cend(),
            std::inserter(X,X.end())
            );
        return X.empty();
      }(m_expression,m_suppression)
      );
}


taint_svaluet::taint_svaluet(taint_svaluet const&  other)
  : m_expression(other.m_expression)
  , m_suppression(other.m_suppression)
  , m_is_bottom(other.m_is_bottom)
  , m_is_top(other.m_is_top)
{}


taint_svaluet::taint_svaluet(taint_svaluet&&  other)
  : m_expression()
  , m_suppression()
  , m_is_bottom(other.m_is_bottom)
  , m_is_top(other.m_is_top)
{
  m_expression.swap(other.m_expression);
  m_suppression.swap(other.m_suppression);
}


taint_svaluet&  taint_svaluet::operator=(taint_svaluet const&  other)
{
  m_expression = other.m_expression;
  m_suppression = other.m_suppression;
  m_is_bottom = other.m_is_bottom;
  m_is_top = other.m_is_top;
  return *this;
}


taint_svaluet&  taint_svaluet::operator=(taint_svaluet&&  other)
{
  m_expression.swap(other.m_expression);
  m_suppression.swap(other.m_suppression);
  m_is_bottom = other.m_is_bottom;
  m_is_top = other.m_is_top;
  return *this;
}


bool  operator==(taint_svaluet const&  a, taint_svaluet const&  b)
{
  return a.is_top() == b.is_top() &&
         a.is_bottom() == b.is_bottom() &&
         a.expression() == b.expression() &&
         a.suppression() == b.suppression()
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
  taint_svaluet::expressiont  result_suppression;
  std::set_intersection(
      a.suppression().cbegin(),a.suppression().cend(),
      b.suppression().cbegin(),b.suppression().cend(),
      std::inserter(result_suppression,result_suppression.end())
      );
  return {result_set,result_suppression,false,false};
}

taint_svaluet  suppression(
    taint_svaluet const&  a,
    taint_svaluet::expressiont const&  sub)
{
  if (a.is_bottom() || a.is_top() || sub.empty())
    return a;

  taint_svaluet::expressiont  result_set;
  std::set_difference(
      a.expression().cbegin(),a.expression().cend(),
      sub.cbegin(),sub.cend(),
      std::inserter(result_set,result_set.end())
      );

  if (result_set.empty())
    return taint_make_bottom();

  taint_svaluet::expressiont  result_suppression;
  std::set_union(
      a.suppression().cbegin(),a.suppression().cend(),
      sub.cbegin(),sub.cend(),
      std::inserter(result_suppression,result_suppression.end())
      );

  return {result_set,result_suppression,false,false};
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
  taint_lvalues_sett& result)
{
  if(e.id()==ID_member)
  {
    taint_lvalues_sett newresults;
    collect_referee_access_paths(e.op0(),ns,newresults);
    for(const auto& res : newresults)
      result.insert(member_exprt(res,to_member_expr(e).get_component_name(),e.type()));
  }
  else
  {
    if(e.id()=="external-value-set")
    {
      const auto& evse=to_external_value_set(e);
      if(evse.label()!=constant_exprt("external_objects",string_typet()))
      {
        const symbolt& sym=ns.lookup(to_constant_expr(evse.label()).get_value());
        auto symexpr=sym.symbol_expr();
        assert(sym.type.id()==ID_pointer);
        result.insert(symexpr);
      }
      else
      {
        result.insert(e);
      }
    }
    else
    {
      // Dynamic object expression, or static symbol.
      result.insert(e);
    }
  }
}

static exprt transform_external_objects(const exprt& e)
{
  if(e.id()==ID_member && get_underlying_object(e).id()=="external-value-set")
  {
    // Rewrite member(externals, "x") as externals("x"), to make subsequent processing easier
    // Note this means we use externals("x") to mean "any x field" whereas LVSA uses it to mean
    // deref(any x field)
    auto evs_copy=to_external_value_set(get_underlying_object(e));
    access_path_entry_exprt new_entry("."+id2string(to_member_expr(e).get_component_name()),"","");
    evs_copy.extend_access_path(new_entry);
    evs_copy.label()=constant_exprt("external_objects",string_typet());
    evs_copy.type()=e.type();
    return evs_copy;
  }
  else if(e.id()=="external-value-set")
  {
    // Similarly, deref(any external), without a member operator, is assumed to be an array access,
    // and is rewritten to (any array)
    auto evs_copy=to_external_value_set(e);
    access_path_entry_exprt new_entry("[]","","");
    evs_copy.extend_access_path(new_entry);
    evs_copy.label()=constant_exprt("external_objects",string_typet());
    evs_copy.type()=e.type();
    return evs_copy;    
  }
  else
    return e;
}

static void collect_lvsa_access_paths(
  exprt const& e,
  namespacet const& ns,
  taint_lvalues_sett& result,
  local_value_set_analysist& lvsa,
  instruction_iteratort const& instit)
{
  if(e.id()==ID_symbol ||
     e.id()==ID_index ||
     e.id()==ID_member ||
     e.id()==ID_dereference)
  {
    value_setst::valuest referees;
    lvsa.get_values(instit,address_of_exprt(e),referees);
    for(const auto& target : referees)
    {
      if(target.id()==ID_unknown)
      {
        //std::cerr << "Warning: ignoring unknown value-set entry for now.\n";
        continue;
      }

      assert(target.id()==ID_object_descriptor);
      exprt const transformed_object =
          transform_external_objects(
              to_object_descriptor_expr(target).object()
              );

      if (transformed_object.id()==ID_symbol)
      {
        std::string const&  ident =
            as_string(transformed_object.get(ID_identifier));
        if (ident.find(".String.Literal.") != std::string::npos)
          continue;
      }

      result.insert(transformed_object);
    }
  }
  else
  {
    forall_operands(it,e)
      collect_lvsa_access_paths(*it,ns,result,lvsa,instit);
  }
}

std::string find_taint_value(const exprt &expr)
{
  if (expr.id() == ID_typecast)
    return find_taint_value(to_typecast_expr(expr).op());
  else if (expr.id() == ID_address_of)
    return find_taint_value(to_address_of_expr(expr).object());
  else if (expr.id() == ID_index)
    return find_taint_value(to_index_expr(expr).array());
  else if (expr.id() == ID_string_constant)
    return as_string(expr.get(ID_value));
  else
    return ""; // ERROR!
}

exprt find_taint_expression(const exprt &expr)
{
  if (expr.id() == ID_dereference)
    return to_dereference_expr(expr).pointer();
  else
    return expr;
}

static void handle_assignment(
    const code_assignt& asgn,
    taint_map_from_lvalues_to_svaluest const&  a,
    taint_map_from_lvalues_to_svaluest& result,  
    instruction_iteratort const& Iit,
    local_value_set_analysist* lvsa,
    namespacet const&  ns,
    std::ostream* const  log)
{

  const auto& lhs_type=ns.follow(asgn.lhs().type());
  if(lhs_type.id()==ID_struct)
  {
    // Process a struct assignment as multiple field assignments.
    const auto& struct_type=to_struct_type(lhs_type);
    for(const auto& c : struct_type.components())
    {
      code_assignt member_assign(member_exprt(asgn.lhs(),c.get_name(),c.type()),
				 member_exprt(asgn.rhs(),c.get_name(),c.type()));
      handle_assignment(member_assign,a,result,Iit,lvsa,ns,log);
    }
    return;
  }
  
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
      collect_lvsa_access_paths(asgn.rhs(),ns,rhs,*lvsa,Iit);
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
    collect_lvsa_access_paths(asgn.lhs(),ns,lhs,*lvsa,Iit);
    for(const auto& path : lhs)
      {
	if(lhs.size()>1 || (lhs.size()==1 && !is_singular_object(path)))
	  maybe_assign(result,normalise(path,ns),rvalue);
	else
	  assign(result,normalise(path,ns),rvalue);
      }
  }

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
    ,
    std::unordered_set<std::string>& child_summaries,
    size_t& nsummary_uses,
    size_t& ndistinct_summary_inputs
    )
{
  goto_programt::instructiont const&  I=*Iit;
  taint_map_from_lvalues_to_svaluest  result = a;
  switch(I.type)
  {
  case ASSIGN:
    {
      code_assignt const&  asgn = to_code_assign(I.code);
      handle_assignment(asgn,a,result,Iit,lvsa,ns,log);
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
          taint_statisticst::instance().on_taint_analysis_use_callee_summary(
                summary,callee_ident
                );

	  nsummary_uses++;
	  if(child_summaries.insert(callee_ident).second)
	    ndistinct_summary_inputs+=summary->input().size();

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
                  lvsa,
                  Iit,
                  log
                  );
            build_substituted_summary(
                  substituted_summary,
                  summary->output(),
                  symbols_substitution,
		  a,
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
  case OTHER:
    if (I.code.get_statement() == "set_may")
    {
      assert(I.code.operands().size() == 2UL);
      std::string const  taint_name = find_taint_value(I.code.op1());
      if (!taint_name.empty())
      {
        taint_svaluet const  rvalue({taint_name},false,false);
        taint_lvaluet const  lvalue =
            normalise(find_taint_expression(I.code.op0()),ns);
        if (lvsa == nullptr)
          assign(result,lvalue,rvalue);
        else
        {
          taint_lvalues_sett lhs;
          collect_lvsa_access_paths(lvalue,ns,lhs,*lvsa,Iit);
          for (const auto& path : lhs)
          {
            if (lhs.size() > 1UL)
              maybe_assign(result,normalise(path,ns),rvalue);
            else
              assign(result,normalise(path,ns),rvalue);
          }
        }
      }
    }
    else if (I.code.get_statement() == "clear_may")
    {
      assert(I.code.operands().size() == 2UL);
      std::string const  taint_name = find_taint_value(I.code.op1());
      if (!taint_name.empty())
      {
        taint_lvaluet const  lvalue =
            normalise(find_taint_expression(I.code.op0()),ns);
        if (lvsa == nullptr)
        {
          taint_svaluet rvalue = taint_make_bottom();
          {
            auto const  it = a.find(lvalue);
            if (it != a.end())
            {
              taint_svaluet::expressiont symbols = it->second.expression();
              symbols.erase(taint_name);
              if (!symbols.empty())
                rvalue = taint_svaluet(symbols,{taint_name},false,false);
            }
          }
          assign(result,normalise(lvalue,ns),rvalue);
        }
        else
        {
          taint_lvalues_sett lhs;
          collect_lvsa_access_paths(lvalue,ns,lhs,*lvsa,Iit);
          if (lhs.size() == 1UL)
          {
            taint_svaluet rvalue = taint_make_bottom();
            {
              auto const  it = a.find(*lhs.cbegin());
              if (it != a.end())
              {
                taint_svaluet::expressiont symbols = it->second.expression();
                symbols.erase(taint_name);
                if (!symbols.empty())
                  rvalue = taint_svaluet(symbols,{taint_name},false,false);
              }
            }
            assign(result,normalise(*lhs.cbegin(),ns),rvalue);
          }
        }
      }
    }
    else if(I.code.get_statement()==ID_array_set)
    {
      // Handle array zero-init like assigning bottom:
      code_assignt fake_assignment;
      fake_assignment.lhs()=dereference_exprt(I.code.op0(),I.code.op0().type().subtype());
      fake_assignment.rhs()=constant_exprt("0",I.code.op0().type().subtype());
      handle_assignment(fake_assignment,a,result,Iit,lvsa,ns,log);
    }
    else
      if (log != nullptr)
        *log << "<p>!!! WARNING !!! : Recognised OTHER instruction type, which "
                "is neither 'set_may' nor 'clear_may' function call. The "
                "transformation function is thus identity.</p>\n";
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
    local_value_set_analysist::dbt* lvsa_database,
    message_handlert& msg
    )
{
  std::vector<irep_idt>  inverted_topological_order;
  get_inverted_topological_order(call_graph,
                                 instrumented_program.goto_functions,
                                 inverted_topological_order);

  size_t processed=0;
  size_t total_funcs=inverted_topological_order.size();
  messaget msgout;
  msgout.set_message_handler(msg);
  for (auto const&  fn_name : inverted_topological_order)
  {
    ++processed;
    if(fn_name=="_start")
      continue;
    const goto_functionst::function_mapt& functions_map =
        instrumented_program.goto_functions.function_map;
    auto const  fn_it = functions_map.find(fn_name);
    if (fn_it != functions_map.cend() && fn_it->second.body_available())
    {
      msgout.debug() << "Start function " << fn_name << "\n";
      summaries_to_compute.insert({
          as_string(fn_name),
          taint_summarise_function(
              fn_name,
              instrumented_program,
              summaries_to_compute,
              log,
              lvsa_database,
              msg
              ),
          });
      msgout.progress() << processed << "/" << total_funcs << " functions analysed" << messaget::eom;
    }
  }
}

taint_summary_ptrt  taint_summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    database_of_summariest const&  database,
    std::ostream* const  log,
    local_value_set_analysist::dbt* lvsa_database,
    message_handlert& msg
    )
{
  messaget m;
  m.set_message_handler(msg);
 
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

  std::cout << "begin_lvsa_analysis_of_function(" << as_string(function_id) << ")\n\n\n"; std::cout.flush();
  taint_statisticst::instance().begin_lvsa_analysis_of_function(
        as_string(function_id)
        );

  local_value_set_analysist::dbt emptydb("");
  auto& use_database=lvsa_database ? *lvsa_database : emptydb;
  local_value_set_analysist lvsainst(ns,fn_iter->second.type,id2string(function_id),
                                     use_database,LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET);
  local_value_set_analysist* lvsa=lvsa_database ? &lvsainst : nullptr;
  if(lvsa)
  {
    lvsainst.set_message_handler(msg);

    auto start_time = std::chrono::high_resolution_clock::now();
    
    lvsainst(fn_iter->second.body);
    // Retain this summary for use analysing callers.
    lvsainst.save_summary(fn_iter->second.body);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration =
      std::chrono::duration_cast<std::chrono::microseconds>(end_time-start_time).count();
    
    m.progress() << "LVSA: " << function_id <<
      " -- steps " << lvsainst.nsteps <<
      " stubs " << lvsainst.nstubs <<
      " stub_assigns " << lvsainst.nstub_assignments <<
      " time " << duration / 1000 << "ms" <<
      messaget::eom;
  }

  taint_statisticst::instance().end_lvsa_analysis_of_function(
        lvsainst.nsteps,
        lvsainst.nstubs,
        lvsainst.nstub_assignments
        );
  std::cout << "end_lvsa_analysis_of_function\n\n\n"; std::cout.flush();

  auto start_time = std::chrono::high_resolution_clock::now();
  
  std::cout << "begin_taint_analysis_of_function(" << as_string(function_id) << ")\n\n\n"; std::cout.flush();
  taint_statisticst::instance().begin_taint_analysis_of_function(
        as_string(function_id)
        );

  taint_summary_domain_ptrt  domain = std::make_shared<taint_symmary_domaint>();
  written_expressionst written_lvalues;
  
  initialise_domain(
        function_id,
        fn_iter->second,
        functions, 
        ns,
        database,
        *domain,
        written_lvalues,
        lvsa,
        log
        );

  taint_map_from_lvalues_to_svaluest  input =
      domain->at(fn_iter->second.body.instructions.cbegin());

  size_t domain_size=input.size();
  size_t steps=0;
  size_t nsummary_uses=0;
  size_t ndistinct_summary_inputs=0;
  std::unordered_set<std::string> children_with_summaries;
  
  solver_work_set_t  work_set;
  initialise_workset(fn_iter->second,work_set);
  while (!work_set.empty())
  {
    taint_statisticst::instance().on_fixpoint_step_of_taint_analysis();

    instruction_iteratort const  src_instr_it = *work_set.cbegin();
    work_set.erase(work_set.cbegin());

    ++steps;

    taint_map_from_lvalues_to_svaluest const&  src_value =
        domain->at(src_instr_it);

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
          ,
		children_with_summaries,
		nsummary_uses,
		ndistinct_summary_inputs
          );

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
        written_lvalues,
        output,
        fn_iter,
        ns,
        log
        );

  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration =
    std::chrono::duration_cast<std::chrono::microseconds>(end_time-start_time).count();
  
  size_t this_summary_size=output.size();

  m.progress() << "TA: " << function_id <<
    " insts " << fn_iter->second.body.instructions.size() <<
    " steps " << steps <<
    " indomsize " << domain_size <<
    " outdomsize " << this_summary_size <<
    " summary_uses " << nsummary_uses <<
    " unique_summary_uses " << children_with_summaries.size() <<
    " child_summary_inputs " << ndistinct_summary_inputs <<
    " time " << duration / 1000 << "ms" <<
    messaget::eom;

  taint_statisticst::instance().end_taint_analysis_of_function(
        input,output,domain
        );
  std::cout << "end_taint_analysis_of_function\n\n\n"; std::cout.flush();

  return std::make_shared<taint_summaryt>(input,output,domain);
}
