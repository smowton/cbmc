/*******************************************************************	\

Module: taint_summary

Author: Marek Trtik

Date: September 2016

This module defines interfaces and functionality for taint summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <goto-analyzer/taint_summary.h>
#include <goto-analyzer/taint_summary_libmodels.h>
#include <goto-analyzer/taint_summary_dump.h>
#include <goto-analyzer/taint_statistics.h>
#include <summaries/utility.h>
#include <summaries/summary_dump.h>
#include <pointer-analysis/local_value_set_analysis.h>
#include <util/std_types.h>
#include <util/file_util.h>
#include <util/msgstream.h>
#include <util/string2int.h>
#include <util/parameter_indices.h>
#include <analyses/ai.h>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cassert>
#include <stdexcept>
#include <chrono>

#include <iostream>

typedef taint_numbered_lvalues_sett written_expressionst;

static void collect_lvsa_access_paths(
  exprt const& e,
  namespacet const& ns,
  taint_numbered_lvalues_sett& result,
  local_value_set_analysist& lvsa,
  instruction_iteratort const& instit,
  object_numberingt&);

struct parameter_matches_id {
  parameter_matches_id(const irep_idt& _id) : id(_id) {}
  bool operator()(const code_typet::parametert& p) const { return id==p.get_identifier(); }
protected:
  const irep_idt id;
};

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
    taint_numbered_domaint&  domain,
    written_expressionst& written,
    local_value_set_analysist* lvsa,
    std::ostream* const  log,
    object_numberingt& taint_object_numbering,
    object_numbers_by_fieldnamet& object_numbers_by_field,
    const std::map<goto_programt::const_targett, goto_programt::const_targetst>& inst_predecessors
    )
{
  // TODO: Improve this to only count as inputs those values which may be read
  // without a preceding write within the same function.
  taint_numbered_lvalues_sett  environment;
  {
    for (auto  it = function.body.instructions.cbegin();
         it != function.body.instructions.cend();
         ++it)
      if (it->type == ASSIGN)
      {
        code_assignt const&  asgn = to_code_assign(it->code);
        if(lvsa)
        {
          collect_lvsa_access_paths(asgn.lhs(),ns,environment,*lvsa,it,taint_object_numbering);
          collect_lvsa_access_paths(asgn.lhs(),ns,written,*lvsa,it,taint_object_numbering);
          collect_lvsa_access_paths(asgn.rhs(),ns,environment,*lvsa,it,taint_object_numbering);
        }
        else
        {
	  /*          exprt lhs=normalise(asgn.lhs(),ns);
          environment.insert(lhs);
          written.insert(lhs);
          collect_access_paths(asgn.rhs(),ns,environment);*/
        }
      }
      else if (it->type == ASSERT)
      {
	collect_lvsa_access_paths(it->guard,ns,environment,*lvsa,it,taint_object_numbering);
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
                                            *lvsa,it,taint_object_numbering);
                else {
		  //collect_access_paths(fn_call.arguments()[paramidx],ns,environment);
		}
              }
              else if (!is_parameter(lvalue_svalue.first,ns) &&
                       !is_return_value_auxiliary(lvalue_svalue.first,ns))
	      {
    environment.insert(taint_object_numbering.number(lvalue_svalue.first));
	      }
	      if(lvalue_svalue.first.id()=="external-value-set")
	      {
		const auto& evse=to_external_value_set(lvalue_svalue.first);
		if(evse.access_path_size()==1)
		  object_numbers_by_field.insert({evse.access_path_back().label(),{}});
	      }
            }
            for(auto const&  lvalue_svalue : summary->output())
              written.insert(taint_object_numbering.number(lvalue_svalue.first));
          }
        }
      }
  }

  taint_numbered_lvalue_svalue_mapt entry_map;
  taint_numbered_lvalue_svalue_mapt others_map;
  for (const auto  lvaluenum : environment)
  {
    const auto& lvalue=taint_object_numbering[lvaluenum];
    if (!is_pure_local(lvalue,ns) &&
        !is_return_value_auxiliary(lvalue,ns) &&
        !is_this(lvalue,ns) &&
        !(get_underlying_object(lvalue).id()==ID_dynamic_object))
    {
      entry_map.insert({lvaluenum, taint_make_symbol() });
      others_map.insert({lvaluenum, taint_make_bottom() });
    }
  }

  domain.insert({function.body.instructions.cbegin(),entry_map});
  for (auto  it = std::next(function.body.instructions.cbegin());
       it != function.body.instructions.cend();
       ++it)
  {
    domain.insert({it,others_map});
  }

  // Now that all maps have been created, replace those with a unique predecessor
  // with a reference to that predecessor.
  for (auto  it = std::next(function.body.instructions.cbegin());
       it != function.body.instructions.cend();
       ++it)
  {
    auto findit=inst_predecessors.find(it);
    if(findit!=inst_predecessors.end() &&
       findit->second.size()==1 &&
       findit->second.back()!=function.body.instructions.cbegin() &&
       domain.at(findit->second.back()).map_depth()<10)
      domain.at(it).set_base(&domain.at(findit->second.back()));
  }

  // Now populate object-numbers-by-field, which maps field names mentioned in
  // child call summaries onto the set of value-numbers at local scope referring to the
  // same fields:

  for(const auto lvaluenum : environment)
  {
    const auto& lvalue=taint_object_numbering[lvaluenum];
    irep_idt fieldname;
    if(lvalue.id()==ID_member)
      fieldname="."+as_string(to_member_expr(lvalue).get_component_name());
    else if(lvalue.id()==ID_dynamic_object)
      fieldname="[]";
    if(fieldname!=irep_idt())
    {
      auto findit=object_numbers_by_field.find(fieldname);
      if(findit!=object_numbers_by_field.end())
	findit->second.insert(lvaluenum);
    }
  }

  
  if (log != nullptr)
  {
    *log << "<h3>Initialising the domain</h3>\n"
            "<p>Domain value at the entry location:</p>\n"
         ;
    taint_dump_numbered_lvalues_to_svalues_as_html(
        domain.at(function.body.instructions.cbegin()),
        ns,
	taint_object_numbering,
        {}/*TODO*/,
        *log
        );

    *log << "<p>Domain value at all other locations:</p>\n";
    taint_dump_numbered_lvalues_to_svalues_as_html(
        domain.at(std::prev(function.body.instructions.cend())),
        ns,
	taint_object_numbering,
        {}/*TODO*/,
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
    taint_numbered_lvalue_svalue_mapt&  map,
    object_numberingt& object_numbering
    )
{
  auto num=object_numbering.number(lvalue);
  map.erase(num);
}

void expand_external_objects(taint_numbered_lvalues_sett& lvalue_set,
                                    const object_numbers_by_fieldnamet& by_fieldname,
				    const object_numberingt& taint_object_numbering)
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

  std::vector<unsigned> new_keys;
  for(const auto& lval_number : lvalue_set)
  {
    const auto& lval=taint_object_numbering[lval_number];
    if(lval.id()=="external-value-set")
    {
      const auto& evse=to_external_value_set(lval);
      const auto& label=to_constant_expr(evse.label()).get_value();
      if(label=="external_objects")
      {
        assert(evse.access_path_size()==1);
        const auto fieldname=evse.access_path_back().label();
	auto findit=by_fieldname.find(fieldname);
	if(findit!=by_fieldname.end())
	  new_keys.insert(new_keys.end(),findit->second.begin(),findit->second.end());
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
    taint_numbered_lvalue_svalue_mapt const&  a,
    taint_summary_ptrt const  summary,
    irep_idt const&  caller_ident,
    code_function_callt const&  fn_call,
    code_typet const&  fn_type,
    namespacet const&  ns,
    local_value_set_analysist* lvsa,
    instruction_iteratort const& Iit,
    std::ostream* const  log,
    object_numberingt& taint_object_numbering,
    const object_numbers_by_fieldnamet& object_numbers_by_field
    )
{
  if (log != nullptr)
    *log << "<p>Building 'symbols substitution map':</p>\n"
            "<ul>\n";

  auto parameter_indices=get_parameter_indices(fn_type);

  std::string const  callee_ident =
      as_string(to_symbol_expr(fn_call.function()).get_identifier());

  for (auto const&  lvalue_svalue : summary->input())
  {
    assert(!lvalue_svalue.second.is_top());
    assert(!lvalue_svalue.second.is_bottom());
    assert(lvalue_svalue.second.expression().size() == 1UL);

    taint_numbered_lvalues_sett  argument_lvalues;
    
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
              Iit,
	      taint_object_numbering);
        }
        else
        {
	  /*
          collect_access_paths(
            fn_call.arguments().at(param_idx),
            ns,
            argument_lvalues
            );*/
        }
      }
    }
    else
    {
      auto const lvalue = taint_object_numbering.number(lvalue_svalue.first);
      argument_lvalues.insert(lvalue);
    }

    expand_external_objects(argument_lvalues,object_numbers_by_field,taint_object_numbering);
      
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
    taint_numbered_lvalue_svalue_mapt& substituted_summary,
    taint_map_from_lvalues_to_svaluest const&  original_summary,
    std::unordered_map<taint_svaluet::taint_symbolt,taint_svaluet> const&
        symbols_substitution,
    irep_idt const&  caller_ident,
    irep_idt const&  callee_ident,
    code_function_callt const&  fn_call,
    code_typet const&  fn_type,
    namespacet const&  ns,
    std::ostream* const  log,
    object_numberingt& taint_object_numbering,
    const object_numbers_by_fieldnamet& object_numbers_by_fieldname
    )
{
  for (auto const&  lvalue_svalue : original_summary)
  {
    const auto& lvalue=lvalue_svalue.first;
    if (!is_empty(lvalue))
    {
      taint_numbered_lvalues_sett lhs_set;
      lhs_set.insert(taint_object_numbering.number(lvalue));
      expand_external_objects(lhs_set,object_numbers_by_fieldname,taint_object_numbering);
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
    taint_dump_numbered_lvalues_to_svalues_as_html(substituted_summary,ns,
                                                   taint_object_numbering,
                                                   {}/*TODO*/,*log);
  }
}


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
static void  build_summary_from_computed_domain(
    taint_numbered_domaint const&  domain,
    written_expressionst const& written,
    taint_map_from_lvalues_to_svaluest&  output,
    goto_functionst::function_mapt::const_iterator const  fn_iter,
    namespacet const&  ns,
    std::ostream* const  log,
    const object_numberingt& taint_object_numbering
    )
{
  if (log != nullptr)
    *log << "<h3>Building summary from the computed domain</h3>\n"
         << "<p>It is computed from the symbolic value "
            "at location "
         << std::prev(fn_iter->second.body.instructions.cend())->location_number
         << ":</p>\n<ul>\n"
         ;

  auto const&  end_svalue =
      domain.at(std::prev(fn_iter->second.body.instructions.cend()));
  for (auto  it = end_svalue.cbegin(); it != end_svalue.cend(); ++it)
  {
    const auto& lval=taint_object_numbering[it->first];
    if ((!is_pure_local(lval,ns)) && (!is_parameter(lval,ns)) && written.count(it->first))
    {
      output.insert(std::make_pair(lval,it->second));

      if (log != nullptr)
      {
        *log << "<li>";
        taint_dump_lvalue_in_html(lval,ns,*log);
        *log << " &rarr; ";
        taint_dump_svalue_in_html(it->second,{}/*TODO*/,*log);
          *log << "</li>\n";
      }
    }
    else
      if (log != nullptr)
      {
        *log << "<li>!! EXCLUDING !! : ";
        taint_dump_lvalue_in_html(lval,ns,*log);
        *log << " &rarr; ";
        taint_dump_svalue_in_html(it->second,{}/*TODO*/,*log);
        *log << "</li>\n";
      }
  }

  if (log != nullptr)
    *log << "</ul>\n";
}


static void  assign(
    taint_numbered_lvalue_svalue_mapt&  map,
    unsigned const  lvalue,
    taint_svaluet const&  svalue
    )
{
  auto const  it = map.find(lvalue);
  if (it == map.end())
  {
    if (!svalue.is_bottom())
      map.insert({lvalue,svalue});
  }
  else
    map[lvalue]=svalue;
}

static void  maybe_assign(
    taint_numbered_lvalue_svalue_mapt&  map,
    unsigned const  lvalue,
    taint_svaluet const&  svalue
    )
{
  auto const  it = map.find(lvalue);
  if (it == map.end())
  {
    if (!svalue.is_bottom())
      map.insert({lvalue,svalue});
  }
  else
    map[lvalue]=join(it->second,svalue);
}

taint_svaluet  taint_make_symbol()
{
  static uint64_t  counter = 0UL;
  taint_svaluet::taint_symbolt const  symbol_name = ++counter;
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


taint_svaluet const&  taint_get_symbol_of_NONDET()
{
  static taint_svaluet  symbol = taint_make_symbol();
  return symbol;
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


static bool  svalue_proper_subset(taint_svaluet const&  a, taint_svaluet const&  b)
{
  if (a == b)
    return false;
  if (a.is_top() || b.is_bottom())
    return false;
  if (a.is_bottom() || b.is_top())
    return true;
  return b.expression().size() > a.expression().size() &&
	       std::includes(b.expression().cbegin(),b.expression().cend(),
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

static bool taint_map_proper_subset(
    taint_numbered_lvalue_svalue_mapt const&  a,
    taint_numbered_lvalue_svalue_mapt const&  b)
{
  if (b.empty())
    return false;
  bool common_base=a.get_base()==b.get_base();
  for (auto  a_it = a.cbegin(); a_it != a.cend(); ++a_it)
  {
    auto const  b_it = b.find(a_it->first);
    if (b_it == b.cend())
      return false;
    // Necessarily equal?
    if(common_base && a_it.points_to_base() && b_it.points_to_base())
      continue;
    if (svalue_proper_subset(a_it->second,b_it->second))
      return true;
  }
  return false;
}

static bool taint_map_subset(
    taint_numbered_lvalue_svalue_mapt const&  a,
    taint_numbered_lvalue_svalue_mapt const&  b)
{
  return a == b || taint_map_proper_subset(a,b);
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
    evs_copy.remove("modified");
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
    evs_copy.remove("modified");
    return evs_copy;    
  }
  else
    return e;
}

static void collect_lvsa_access_paths(
  exprt const& querye_in,
  namespacet const& ns,
  taint_numbered_lvalues_sett& result,
  local_value_set_analysist& lvsa,
  instruction_iteratort const& instit,
  object_numberingt& taint_object_numbering)
{
  const exprt* querye=&querye_in;
  while(querye->id()==ID_typecast)
    querye=&querye->op0();
  const exprt& e = *querye;
  
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
      else if(get_underlying_object(transformed_object).id()=="NULL-object")
	continue;

      result.insert(taint_object_numbering.number(transformed_object));
    }
  }
  else
  {
    forall_operands(it,e)
      collect_lvsa_access_paths(*it,ns,result,lvsa,instit,taint_object_numbering);
  }
}

static const taint_svaluet::taint_symbolt invalid_taint=(unsigned long)-1;

taint_svaluet::taint_symbolt find_taint_value(
    const exprt &expr,
    taint_specification_symbol_names_to_svalue_symbols_mapt const&
        taint_spec_names
    )
{
  if (expr.id() == ID_typecast)
    return find_taint_value(to_typecast_expr(expr).op(),taint_spec_names);
  else if (expr.id() == ID_address_of)
    return find_taint_value(to_address_of_expr(expr).object(),taint_spec_names);
  else if (expr.id() == ID_index)
    return find_taint_value(to_index_expr(expr).array(),taint_spec_names);
  else if (expr.id() == ID_string_constant)
    return taint_spec_names.at(as_string(expr.get(ID_value)));
  else
    return invalid_taint; // ERROR!
}

exprt find_taint_expression(const exprt &expr)
{
  if (expr.id() == ID_dereference)
    return find_taint_expression(to_dereference_expr(expr).pointer());
  if (expr.id() == ID_typecast)
    return find_taint_expression(to_typecast_expr(expr).op());
  else
    return expr;
}

static void handle_assignment(
    const code_assignt& asgn,
    taint_numbered_lvalue_svalue_mapt const&  a,
    taint_numbered_lvalue_svalue_mapt& result,  
    instruction_iteratort const& Iit,
    local_value_set_analysist* lvsa,
    namespacet const&  ns,
    std::ostream* const  log,
    object_numberingt& taint_object_numbering)
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
      handle_assignment(member_assign,a,result,Iit,lvsa,ns,log,taint_object_numbering);
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
    taint_numbered_lvalues_sett  rhs;
    if(!lvsa)
    {
      //      collect_access_paths(asgn.rhs(),ns,rhs);
    }
    else
      collect_lvsa_access_paths(asgn.rhs(),ns,rhs,*lvsa,Iit,taint_object_numbering);
    for (auto const&  lvalue : rhs)
    {
      auto const  it = a.find(lvalue);
      if (it != a.cend())
        rvalue = join(rvalue,it->second);

      if (log != nullptr)
      {
        taint_dump_lvalue_in_html(taint_object_numbering[lvalue],ns,*log);
        *log << ", ";
      }
    }
  }

  if (log != nullptr)
    *log << "}.</p>\n";

  if(!lvsa)
  {
    //assign(result,normalise(asgn.lhs(),ns),rvalue);
  }
  else
  {
    taint_numbered_lvalues_sett lhs;
    collect_lvsa_access_paths(asgn.lhs(),ns,lhs,*lvsa,Iit,taint_object_numbering);
    for(const auto& path : lhs)
    {
      if(lhs.size()>1 || (lhs.size()==1 && !is_singular_object(taint_object_numbering[path])))
        maybe_assign(result,path,rvalue);
      else
        assign(result,path,rvalue);
    }
  }
}

taint_numbered_lvalue_svalue_mapt  transform(
    taint_numbered_lvalue_svalue_mapt const&  a,
    instruction_iteratort const& Iit,
    irep_idt const&  caller_ident,
    goto_functionst::function_mapt const&  functions_map,
    database_of_summariest const&  database,
    local_value_set_analysist* lvsa,
    namespacet const&  ns,
    object_numberingt& taint_object_numbering,
    const object_numbers_by_fieldnamet& object_numbers_by_field,
    taint_specification_symbol_names_to_svalue_symbols_mapt const&
        taint_spec_names,
    std::ostream* const  log
    )
{
  goto_programt::instructiont const&  I=*Iit;
  taint_numbered_lvalue_svalue_mapt result;
  // Take a cheap read-only view of the incoming domain:
  result.set_base(&a);
  switch(I.type)
  {
  case ASSIGN:
    {
      code_assignt const&  asgn = to_code_assign(I.code);
      if (asgn.rhs().id() == ID_side_effect)
      {
        side_effect_exprt const  see = to_side_effect_expr(asgn.rhs());
        if(see.get_statement()==ID_nondet)
        {
          if (lvsa == nullptr)
            assign(result,taint_object_numbering.number(asgn.lhs()),
                   taint_get_symbol_of_NONDET());
          else
          {
            taint_numbered_lvalues_sett lhs;
            collect_lvsa_access_paths(asgn.lhs(),ns,lhs,*lvsa,Iit,taint_object_numbering);
            for (const auto& path : lhs)
            {
              if (lhs.size() > 1UL)
                maybe_assign(result,path,
                             taint_get_symbol_of_NONDET());
              else
                assign(result,path,
                       taint_get_symbol_of_NONDET());
            }
          }
          return result;
        }
      }
      handle_assignment(asgn,a,result,Iit,lvsa,ns,log,taint_object_numbering);
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

          auto const&  fn_type = functions_map.at(callee_ident).type;

          taint_numbered_lvalue_svalue_mapt  substituted_summary;
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
                  log,
                  taint_object_numbering,
                  object_numbers_by_field
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
                  log,
                  taint_object_numbering,
                  object_numbers_by_field
                  );
          }
          result = assign(result,substituted_summary);
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
      auto const  taint_name = find_taint_value(I.code.op1(),taint_spec_names);
      if (taint_name!=invalid_taint)
      {
        taint_svaluet const  rvalue({taint_name},false,false);
        auto const  lvalue =
          normalise(find_taint_expression(I.code.op0()),ns);
        if (lvsa == nullptr)
          assign(result,taint_object_numbering.number(lvalue),rvalue);
        else
        {
          taint_numbered_lvalues_sett lhs;
          collect_lvsa_access_paths(lvalue,ns,lhs,*lvsa,Iit,taint_object_numbering);
          for (const auto& path : lhs)
          {
            if (lhs.size() > 1UL)
              maybe_assign(result,path,rvalue);
            else
              assign(result,path,rvalue);
          }
        }
      }
    }
    else if (I.code.get_statement() == "clear_may")
    {
      assert(I.code.operands().size() == 2UL);
      auto const  taint_name = find_taint_value(I.code.op1(),taint_spec_names);
      if (taint_name!=invalid_taint)
      {
        taint_lvaluet const  lvalue =
        normalise(find_taint_expression(I.code.op0()),ns);
        if (lvsa == nullptr)
        {
          auto lvalue_number=taint_object_numbering.number(lvalue);
          taint_svaluet rvalue = taint_make_bottom();
          {
            auto const  it = a.find(lvalue_number);
            if (it != a.end())
            {
              taint_svaluet::expressiont symbols = it->second.expression();
              symbols.erase(taint_name);
              if (!symbols.empty())
                rvalue = taint_svaluet(symbols,{taint_name},false,false);
            }
          }
          assign(result,lvalue_number,rvalue);
        }
        else
        {
          taint_numbered_lvalues_sett lhs;
          collect_lvsa_access_paths(lvalue,ns,lhs,*lvsa,Iit,taint_object_numbering);
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
            assign(result,*lhs.cbegin(),rvalue);
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
      handle_assignment(fake_assignment,a,result,Iit,lvsa,ns,log,taint_object_numbering);
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
        erase_dead_lvalue(lvalue,ns,result,taint_object_numbering);

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

taint_numbered_lvalue_svalue_mapt join(
    taint_numbered_lvalue_svalue_mapt const&  a,
    taint_numbered_lvalue_svalue_mapt const&  b)
{
  taint_numbered_lvalue_svalue_mapt  result_dict;
  if(a.get_base()==b.get_base())
  {
    result_dict.set_base(a.get_base());
    if(a.removed_key_valid || b.removed_key_valid)
    {
      // DEAD statement. Effects cannot change.
      if(a.removed_key_valid && b.removed_key_valid)
	assert(a.removed_key == b.removed_key);
      result_dict.erase(a.removed_key_valid ? a.removed_key : b.removed_key);
      return result_dict;
    }
  }
  taint_numbered_lvalue_svalue_mapt::const_iterator a_it,a_end,b_it,b_end;
  a_it=a.cbegin();
  a_end=a.cend();
  b_it=b.cbegin();
  b_end=b.cend();    
  while(a_it!=a_end || b_it!=b_end)
  {
    if(a_it!=a_end && b_it!=b_end && a_it->first==b_it->first)
    {
      // Implicitly copied by sharing the underlying map?
      if(!(result_dict.get_base() && a_it.points_to_base() && b_it.points_to_base()))
	result_dict.insert({a_it->first,join(a_it->second,b_it->second)});
      ++a_it; ++b_it;
    }
    else if(b_it==b_end || (a_it!=a_end && a_it->first < b_it->first))
    {
      result_dict.insert(*a_it);
      ++a_it;
    }
    else
    {
      result_dict.insert(*b_it);
      ++b_it;
    }
  }
  return result_dict;
}


taint_numbered_lvalue_svalue_mapt  assign(
    taint_numbered_lvalue_svalue_mapt const&  a,
    taint_numbered_lvalue_svalue_mapt const&  b
    )
{
  taint_numbered_lvalue_svalue_mapt  result = a;
  for (auto  b_it = b.cbegin(); b_it != b.cend(); ++b_it)
    assign(result,b_it->first,b_it->second);
  return result;
}


taint_summaryt::taint_summaryt(
    taint_map_from_lvalues_to_svaluest const&  input,
    taint_map_from_lvalues_to_svaluest const&  output,
    const taint_numbered_domaint& domain,
    const object_numberingt& _numbering
    )
  : m_input(input)
  , m_output(output)
  , m_domain(domain)
  , numbering(_numbering)
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

static void populate_formals_to_actuals(
    local_value_set_analysist& lvsa,
    const irep_idt& fname,
    const goto_programt& prog,
    const namespacet& ns,
    object_numberingt& taint_object_numbering,
    formals_to_actuals_mapt& formals_to_actuals)
{
  for(auto instit=prog.instructions.begin(),instend=prog.instructions.end();
      instit!=instend; ++instit)
  {
    if(instit->type!=FUNCTION_CALL)
      continue;
    auto& actuals=formals_to_actuals[{fname,instit}];
    const auto& fcall=to_code_function_call(instit->code);
    for(const auto& arg : fcall.arguments())
    {
      actuals.push_back({});
      collect_lvsa_access_paths(arg,ns,actuals.back(),lvsa,instit,taint_object_numbering);
    }
  }
}

void  taint_summarise_all_functions(
    goto_modelt const&  instrumented_program,
    database_of_summariest&  summaries_to_compute,
    call_grapht const&  call_graph,
    local_value_set_analysist::dbt* lvsa_database,
    taint_specification_symbol_names_to_svalue_symbols_mapt const&
        taint_spec_names,
    taint_object_numbering_per_functiont&  taint_object_numbering,
    object_numbers_by_field_per_functiont&  object_numbers_by_field,
    formals_to_actuals_mapt& formals_to_actuals,
    message_handlert&  msg,
    double  timeout,
    std::ostream* const  log
    )
{
  std::vector<irep_idt>  inverted_topological_order;
  get_inverted_topological_order(call_graph,
                                 instrumented_program.goto_functions,
                                 inverted_topological_order);

  messaget msgout;
  msgout.set_message_handler(msg);
  size_t processed = 0UL;
  size_t modelled = 0UL;
  size_t skipped = 0UL;

  auto start_time = std::chrono::high_resolution_clock::now();
  for (auto const&  fn_name : inverted_topological_order)
  {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double>(end_time-start_time).count();
    if (duration >= timeout)
    {
      msgout.progress()
          << "["
          << std::fixed << std::setprecision(1) << std::setw(5)
          << (inverted_topological_order.size() == 0UL ? 100.0 :
                100.0 * (double)(processed + skipped) /
                        (double)inverted_topological_order.size())
          << "%] "
          << " TIMEOUT! ("
          << processed << " processed, "
          << modelled << " modelled, "
          << inverted_topological_order.size() - processed - modelled
          << " skipped)."
          << messaget::eom; std::cout.flush();
      return;
    }

    const goto_functionst::function_mapt& functions_map =
        instrumented_program.goto_functions.function_map;
    auto const  fn_it = functions_map.find(fn_name);
    if (taint_summary_libmodelst::instance().has_model_of_function(fn_name))
    {
      msgout.progress()
          << "["
          << std::fixed << std::setprecision(1) << std::setw(5)
          << (inverted_topological_order.size() == 0UL ? 100.0 :
                100.0 * (double)(processed + skipped) /
                        (double)inverted_topological_order.size())
          << "%] Retrieving model of: "
          << fn_name
          << messaget::eom; std::cout.flush();
      summaries_to_compute.insert({
          as_string(fn_name),
          taint_summary_libmodelst::instance().get_model_of_function(fn_name)
          });
      ++modelled;
    }
    else if (fn_it != functions_map.cend() && fn_it->second.body_available() &&
             fn_name != "_start")
    {
      msgout.progress()
          << "["
          << std::fixed << std::setprecision(1) << std::setw(5)
          << (inverted_topological_order.size() == 0UL ? 100.0 :
                100.0 * (double)(processed + skipped) /
                        (double)inverted_topological_order.size())
          << "%] "
          << fn_name
          << messaget::eom; std::cout.flush();

      summaries_to_compute.insert({
          as_string(fn_name),
          taint_summarise_function(
              fn_name,
              instrumented_program,
              summaries_to_compute,
              lvsa_database,
              taint_spec_names,
              taint_object_numbering[as_string(fn_name)],
              object_numbers_by_field[as_string(fn_name)],
	      formals_to_actuals,
              msg,
              log
              ),
          });

      ++processed;
    }
    else
    {
      msgout.progress()
          << "["
          << std::fixed << std::setprecision(1) << std::setw(5)
          << (inverted_topological_order.size() == 0UL ? 100.0 :
                100.0 * (double)(processed + skipped) /
                        (double)inverted_topological_order.size())
          << "%] Skipping"
          << (fn_it != functions_map.cend() && !fn_it->second.body_available() ?
                " (function without body)" : "")
          << ": "
          << fn_name
          << messaget::eom; std::cout.flush();
      ++skipped;
    }
  }
  msgout.progress()
      << "[100.0%] Taint analysis has finished successfully ("
      << processed << " processed, "
      << modelled << " modelled, "
      << skipped << " skipped)."
      << messaget::eom; std::cout.flush();
}

taint_summary_ptrt  taint_summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    database_of_summariest const&  database,
    local_value_set_analysist::dbt* lvsa_database,
    taint_specification_symbol_names_to_svalue_symbols_mapt const&
        taint_spec_names,
    object_numberingt&  taint_object_numbering,
    object_numbers_by_fieldnamet&  object_numbers_by_field,
    formals_to_actuals_mapt& formals_to_actuals,
    message_handlert& msg,
    std::ostream* const  log
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

    lvsainst(fn_iter->second.body);
    // Retain this summary for use analysing callers.
    lvsainst.save_summary(fn_iter->second.body);
  }

  populate_formals_to_actuals(lvsainst,fn_iter->first,fn_iter->second.body,
			      ns,taint_object_numbering,formals_to_actuals);

  taint_statisticst::instance().end_lvsa_analysis_of_function(
        lvsainst.nsteps,
        lvsainst.nstubs,
        lvsainst.nstub_assignments
        );

  taint_statisticst::instance().begin_taint_analysis_of_function(
        as_string(function_id)
        );

  auto resultp=std::make_shared<taint_summaryt>();
  auto& result=*resultp;
  auto& domain=result.domain();

  written_expressionst written_lvalues;

  const auto& function=fn_iter->second;
  std::map<goto_programt::const_targett, goto_programt::const_targetst> inst_predecessors;
  for(auto it=function.body.instructions.cbegin(),itend=function.body.instructions.cend();
      it!=itend;++it)
  {
    goto_programt::const_targetst succs;
    function.body.get_successors(it,succs);
    for(auto succit : succs)
      inst_predecessors[succit].push_back(it);
  }

  initialise_domain(
        function_id,
        fn_iter->second,
        functions, 
        ns,
        database,
        domain,
        written_lvalues,
        lvsa,
        log,
	taint_object_numbering,
	object_numbers_by_field,
        inst_predecessors
        );

  auto  input =
    domain.at(fn_iter->second.body.instructions.cbegin());
  solver_work_set_t  work_set;
  initialise_workset(fn_iter->second,work_set);
  while (!work_set.empty())
  {
    taint_statisticst::instance().on_fixpoint_step_of_taint_analysis();

    instruction_iteratort const  src_instr_it = *work_set.cbegin();
    work_set.erase(work_set.cbegin());

    auto const&  src_value =
        domain.at(src_instr_it);

    auto const  transformed =
      transform(
          src_value,
          src_instr_it,
          function_id,
          functions,
          database,
          lvsa,
          ns,
          taint_object_numbering,
          object_numbers_by_field,
          taint_spec_names,
          log
          );

    goto_programt::const_targetst successors;
    fn_iter->second.body.get_successors(src_instr_it, successors);
    for(auto  succ_it = successors.begin();
        succ_it != successors.end();
        ++succ_it)
      if (*succ_it != fn_iter->second.body.instructions.cend())
      {
        instruction_iteratort const  dst_instr_it = *succ_it;
        auto&  dst_value =
            domain.at(dst_instr_it);

        auto const  old_dst_value = dst_value;

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
          taint_dump_numbered_lvalues_to_svalues_as_html(
                src_value,ns,taint_object_numbering,{}/*TODO*/,*log);
          *log << "<p>Old destination value:</p>\n";
    taint_dump_numbered_lvalues_to_svalues_as_html(
          old_dst_value,ns,taint_object_numbering,{}/*TODO*/,*log);
	}

        // First instruction is a loop head in this case,
        // since callers are also predecessors.
        if(dst_instr_it!=function.body.instructions.begin() &&
           inst_predecessors.at(dst_instr_it).size()==1)
        {
          dst_value=std::move(transformed);
          if(dst_value.map_depth()>=10)
            dst_value.flatten();
        }
        else
        {
          dst_value=join(transformed,old_dst_value);
        }

	if (log != nullptr)
	{
          *log << "<p>Transformed value:</p>\n";
          taint_dump_numbered_lvalues_to_svalues_as_html(
                transformed,ns,taint_object_numbering,{}/*TODO*/,*log);
          *log << "<p>Resulting destination value:</p>\n";
          taint_dump_numbered_lvalues_to_svalues_as_html(
                dst_value,ns,taint_object_numbering,{}/*TODO*/,*log);
	}

        if (!taint_map_subset(dst_value,old_dst_value))
        {
          work_set.insert(dst_instr_it);

          if (log != nullptr)
            *log << "<p>Inserting instruction at location "
                 << dst_instr_it->location_number << " into 'work_set'.</p>\n"
                 ;
        }
      }
  }

  taint_map_from_lvalues_to_svaluest& output=result.output();
  build_summary_from_computed_domain(
        domain,
        written_lvalues,
        output,
        fn_iter,
        ns,
        log,
	taint_object_numbering
        );

  taint_statisticst::instance().end_taint_analysis_of_function(
        input,output,domain
  );

  auto& expr_input=result.input();
  for(const auto& p : input)
    expr_input.insert({taint_object_numbering[p.first],p.second});

  result.domain_numbering()=taint_object_numbering;
  
  return resultp;

}

