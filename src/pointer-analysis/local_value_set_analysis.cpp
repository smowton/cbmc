
#include "local_value_set_analysis.h"

#include <util/prefix.h>
#include <util/json_irep.h>
#include <util/suffix.h>
#include <util/string2int.h>
#include <util/arith_tools.h>
#include <util/std_expr.h>
#include <goto-programs/remove_returns.h>

#include <algorithm>

static void gather_external_symbols(
  const exprt& e, const namespacet& ns, std::vector<symbol_exprt>& result)
{
  if(e.id()==ID_symbol)
  {
    auto& symexpr=to_symbol_expr(e);
    if(ns.lookup(symexpr.get_identifier()).is_static_lifetime &&
       !has_suffix(id2string(symexpr.get_identifier()),RETURN_VALUE_SUFFIX))
      result.push_back(symexpr);
  }
  else
  {
    forall_operands(it,e)
      gather_external_symbols(*it,ns,result);
  }
}

static void gather_external_symbols(
  const goto_programt& fun, const namespacet& ns, std::vector<symbol_exprt>& result)
{
  forall_goto_program_instructions(it,fun) gather_external_symbols(it->code,ns,result);
}

void local_value_set_analysist::initialize(const goto_programt& fun)
{
  summarydb.set_message_handler(get_message_handler());
  // TODO: replace this with something less ugly.
  value_sett::use_malloc_type=true;
  value_sett::use_dead_statements=true;
  value_set_analysist::initialize(fun);

  if(fun.instructions.size()==0)
    return;

  std::vector<symbol_exprt> external_symbols;

  for(const auto& param : function_type.parameters())
    external_symbols.push_back(symbol_exprt(param.get_identifier(),param.type()));

  gather_external_symbols(fun,ns,external_symbols);

  std::sort(external_symbols.begin(),external_symbols.end());
  external_symbols.erase(std::unique(external_symbols.begin(),external_symbols.end()),
                         external_symbols.end());

  auto& initial_state=(*this)[fun.instructions.begin()].value_set;
  
  // Now insert fresh symbols for each external symbol,
  // indicating an unknown external points-to set.
  for(const auto& extsym : external_symbols)
  {
    if(extsym.type().id()==ID_pointer)
    {
      const auto& extsym_name=extsym.get_identifier();
      value_sett::entryt extsym_entry_blank(id2string(extsym_name),"");
      auto& extsym_entry=initial_state.get_entry(extsym_entry_blank, extsym.type().subtype(), ns);
      external_value_set_exprt extsym_var(
        extsym.type().subtype(),constant_exprt(extsym_name,string_typet()),mode,false);
      initial_state.insert(extsym_entry.object_map,extsym_var);
    }
  }
}

static void get_all_field_value_sets(
  const std::string& fieldname,
  value_sett& state,
  std::vector<value_sett::entryt*>& entrylist)
{
  // Find all value sets we're currently aware of that may be affected by
  // a write to the given field:
  for(auto& entry : state.values)
  {
    if(entry.second.suffix==fieldname)
      entrylist.push_back(&entry.second);
  }
}

void local_value_set_analysist::transform_function_stub_single_external_set(
  const irep_idt& fname, statet& state, locationt l_call, locationt l_return)
{

  ++nstubs;
  
  const symbolt& function_symbol=ns.lookup(fname);
  const code_function_callt& fcall=to_code_function_call(l_call->code);
  
  const auto& call_summary=static_cast<const lvsaa_single_external_set_summaryt&>(
    *(summarydb[id2string(fname)]));

  // The summary gives a list of inclusions, in the form symbol1 <- symbol2,
  // indicating that values reachable before the call from symbol2
  // may now be reachable from symbol1. The assignments are simeltaneous.
  // Thus start by reading all RHS values, before any changes are made:

  auto& valuesets=static_cast<value_set_domaint&>(state).value_set;
  std::map<exprt, value_sett::object_mapt> pre_call_rhs_value_sets;
  const std::string external_objects_basename="external_objects";

  for(const auto& assignment : call_summary.field_assignments)
  {
    ++nstub_assignments;
    const auto& rhs_expr=assignment.second;
    if(pre_call_rhs_value_sets.count(rhs_expr))
      continue;
    auto& rhs_map=pre_call_rhs_value_sets[rhs_expr];
    if(assignment.second.id()=="external-value-set")
    {
      auto& evse=to_external_value_set(assignment.second);
      if(to_constant_expr(evse.label()).get_value()==external_objects_basename)
      {
        std::vector<value_sett::entryt*> rhs_entries;
        std::string suffix=
          id2string(
            to_external_value_set(assignment.second).access_path_back().label());
        get_all_field_value_sets(suffix,valuesets,rhs_entries);
        for(const auto& rhs_entry : rhs_entries)
          valuesets.make_union(rhs_map,rhs_entry->object_map);
        // Also add the external set itself, representing the possibility that the read
        // comes from outside *this* function as well:
        valuesets.insert(rhs_map,evse);
      }
      else {
        // This should be an external value set assigned to initialise some global or parameter.
        assert(evse.access_path_size()==0);
        const symbolt& inflow_symbol=ns.lookup(to_constant_expr(evse.label()).get_value());
	exprt inflow_expr;
        if(inflow_symbol.is_static_lifetime)
        {
          // Global variable. Read its actual incoming value set:	  
	  inflow_expr=inflow_symbol.symbol_expr();
        }
        else
        {
          // Parameter. Get the value-set for the actual argument:
          size_t paramidx=(size_t)-1;
          const auto& params=to_code_type(function_symbol.type).parameters();
          for(size_t i=0, ilim=params.size(); i!=ilim; ++i)
          {
            if(params[i].get_identifier()==inflow_symbol.name)
            {
              paramidx=i;
              break;
            }
          }
	  if(paramidx==(size_t)-1)
	  {
	    error() << "Failed to find parameter " << inflow_symbol.name << "(evse label: " << to_constant_expr(evse.label()).get_value() << eom;
	  }
          assert(paramidx!=(size_t)-1 && "Unknown parameter symbol?");
	  inflow_expr=fcall.arguments()[paramidx];
        }
	pointer_typet expect_type(evse.type());
	if(inflow_expr.type()!=expect_type)
	  inflow_expr.make_typecast(expect_type);
	valuesets.get_value_set(inflow_expr,rhs_map,ns,false);
      }
    }
    else
    {
      // Ordinary value set member; just add to the RHS map.
      valuesets.insert(rhs_map,assignment.second);
    }
  }

  // OK, read all the RHS sets, now assign to the LHS symbols:
  
  for(const auto& assignment : call_summary.field_assignments)
  {
    const auto& rhs_values=pre_call_rhs_value_sets.at(assignment.second);
    
    if(assignment.first.basename==external_objects_basename)
    {
      std::vector<value_sett::entryt*> lhs_entries;
      // Also assign to the external set itself, representing a write to an object
      // outside this scope:
      value_sett::entryt entry(assignment.first.basename,assignment.first.fieldname);
      auto wholename=assignment.first.basename+assignment.first.fieldname;
      valuesets.values.insert({irep_idt(wholename),entry});      
      get_all_field_value_sets(assignment.first.fieldname,valuesets,lhs_entries);
      for(auto lhs_entry : lhs_entries)
        valuesets.make_union(lhs_entry->object_map,rhs_values);
    }
    else if(has_prefix(assignment.first.basename,"value_set::dynamic_object"))
    {
      std::string objkey=assignment.first.basename+assignment.first.fieldname;
      value_sett::entryt dynobj_entry_name(assignment.first.basename,assignment.first.fieldname);
      auto insertit=valuesets.values.insert(std::make_pair(objkey, dynobj_entry_name));
      valuesets.make_union(insertit.first->second.object_map,rhs_values);
    }
    else
    {
      // The only other kind of symbols mentioned in summary LHS are global variables.
      assert(assignment.first.fieldname=="");
      const auto& global_sym=ns.lookup(assignment.first.basename);
      value_sett::entryt global_entry_name(assignment.first.basename,"");
      auto& global_entry=valuesets.get_entry(global_entry_name,global_sym.type,ns);
      valuesets.make_union(global_entry.object_map,rhs_values);
    }
  }
}

void local_value_set_analysist::transform_function_stub(
  const irep_idt& fname, statet& state, locationt l_call, locationt l_return)
{
  // Execute a summary description for function fname.
  if(!summarydb.load(id2string(fname),/*quiet=*/true))
    return;
  switch(mode)
  {
  case LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET:
    transform_function_stub_single_external_set(fname,state,l_call,l_return);
    break;
  default:
    throw "Summaries not implemented";
  }
}

void local_value_set_analysist::save_summary(const goto_programt& goto_program)
{
  assert(goto_program.instructions.size()!=0);
  locationt last_loc=std::prev(goto_program.instructions.end());
  const auto& final_state=static_cast<const value_set_domaint&>(get_state(last_loc));
  auto summaryptr=std::make_shared<lvsaa_single_external_set_summaryt>();
  bool export_return_value=function_type.return_type().id()==ID_pointer;
  summaryptr->from_final_state(final_state.value_set,ns,export_return_value);
  summarydb.insert(std::make_pair(function_name,summaryptr));
  summarydb.save(function_name);
  summarydb.save_index();
}

static void get_reachable_objects(
  const unsigned long root,
  const std::map<unsigned long, std::vector<unsigned long> >& edges,
  std::set<unsigned long>& reachable)
{
  if(reachable.insert(root).second)
  {
    const auto findit=edges.find(root);
    if(findit!=edges.end())
      for(const auto otherend : findit->second)
	get_reachable_objects(otherend,edges,reachable);
  }
}

static void escape_analysis(
  const std::vector<value_sett::valuest::const_iterator>& values,
  std::set<unsigned long>& escaped)
{
  std::vector<unsigned long> roots;
  std::map<unsigned long, std::vector<unsigned long> > edges;
  const std::string dynobj_prefix="value_set::dynamic_object";
  const auto prefixlen=dynobj_prefix.size();

  // Build a pointer graph of dynamic objects, considering anything reachable
  // from a global or external value set as a root:
  for(const auto& entryp : values)
  {
    const auto& entry=*entryp;
    const auto& pointsto=entry.second.object_map.read();
    auto entryname=id2string(entry.first);
    bool lhs_dynamic=has_prefix(entryname,dynobj_prefix);
    unsigned long lhs_number=0;
    if(lhs_dynamic)
    {
      size_t fieldsepidx=entryname.find('.');
      if(fieldsepidx==std::string::npos)
	fieldsepidx=entryname.size();
      lhs_number=safe_string2unsigned(entryname.substr(prefixlen,fieldsepidx-prefixlen));
    }
    for(const auto& pointsto_number : pointsto)
    {
      const auto& pointsto_expr=value_sett::object_numbering[pointsto_number.first];
      if(pointsto_expr.id()==ID_dynamic_object)
      {
	mp_integer rhs_number;
	assert(!to_integer(to_dynamic_object_expr(pointsto_expr).instance(),rhs_number));
	assert(rhs_number.is_long());
	if(lhs_dynamic)
	  edges[lhs_number].push_back((unsigned long)rhs_number.to_long());
	else
	  roots.push_back((unsigned long)rhs_number.to_long());
      }
    }
  }

  // Find the transitively reachable objects:
  for(const auto root : roots)
    get_reachable_objects(root,edges,escaped);
  
}

void lvsaa_single_external_set_summaryt::from_final_state(
  const value_sett& final_state, const namespacet& ns, bool export_return_value)
{
  // Just save a list of fields that may be overwritten by this function, and the values
  // they may be assigned.

  std::vector<value_sett::valuest::const_iterator> to_export;
  
  for(auto it=final_state.values.begin(), itend=final_state.values.end(); it!=itend; ++it)
  {
    const auto& entry=*it;
    const std::string prefix="external_objects";
    const std::string entryname=id2string(entry.first);
    bool export_this_entry=false;
    if(has_prefix(entryname,prefix))
      export_this_entry=true;
    if((!export_this_entry) && has_prefix(entryname,"value_set::dynamic_object"))
    {
      export_this_entry=true;
    }
    if((!export_this_entry) && entryname=="value_set::return_value")
    {
      if(export_return_value)
        export_this_entry=true;
      else
        continue;
    }
    if(!export_this_entry)
    {
      const symbolt& sym=ns.lookup(entry.second.identifier);
      if(sym.is_static_lifetime)
        export_this_entry=true;
    }
    if(export_this_entry)
      to_export.push_back(it);
  }

  std::set<unsigned long> escaped_dynamic_objects;
  escape_analysis(to_export,escaped_dynamic_objects);

  for(const auto entryp : to_export)
  {
    const auto& entry=*entryp;
    const auto& pointsto=entry.second.object_map.read();
    for(const auto& pointsto_number : pointsto)
    {
      const auto& pointsto_expr=final_state.object_numbering[pointsto_number.first];
      // Remove any subclass qualifiers-- for our purposes, "points to A cast to a B"
      // is equivalent to just "points to A".
      const exprt* toexport=&pointsto_expr;
      while(toexport->id()==ID_member)
	toexport=&toexport->op0();

      bool export_this_expr=false;
      if(toexport->id()=="external-value-set")
      {
        // The is_modified tag is only used for the case where an ext-value-set
        // is written to another one, to disambiguate the case of some_ext.x = some_ext.x
        // (with possible side-effects) from the case where it some_ext.x is read-only.
        // Otherwise the tag is meaningless and the entry should always be exported.
        if(to_external_value_set(*toexport).is_modified())
          export_this_expr=true;
        else if(!has_prefix(id2string(entry.first),"external_objects"))
          export_this_expr=true;
      }
      else if(toexport->id()==ID_dynamic_object)
      {
	mp_integer object_number;
	assert(!to_integer(to_dynamic_object_expr(*toexport).instance(),object_number));
	assert(object_number.is_long());
	if(escaped_dynamic_objects.count(object_number.to_long()))
	  export_this_expr=true;
      }
      else if(toexport->id()==ID_symbol)
	export_this_expr=true;
	
      if(!export_this_expr)
	continue;
	
      struct fieldname thisname = {id2string(entry.second.identifier), entry.second.suffix};
      field_assignments.push_back(std::make_pair(thisname,*toexport));
    }
  }
}

json_objectt lvsaa_single_external_set_summaryt::to_json() const
{
  json_arrayt assigns;
  for(const auto& entry : field_assignments)
  {
    json_objectt assign;
    assign["lhs_basename"]=json_stringt(entry.first.basename);
    assign["lhs_fieldname"]=json_stringt(entry.first.fieldname);    
    assign["rhs"]=irep_to_json(entry.second);
    assigns.push_back(assign);
  }
  json_objectt ret;
  ret["assigns"]=std::move(assigns);
  return ret;
}

void lvsaa_single_external_set_summaryt::from_json(const json_objectt& json)
{
  assert(json.is_object());
  assert(json.object.at("assigns").is_array());
  for(const auto& entry : json.object.at("assigns").array)
  {
    assert(entry.object.at("lhs_basename").is_string());
    assert(entry.object.at("lhs_fieldname").is_string());    
    irept rhs_irep=irep_from_json(entry.object.at("rhs"));
    field_assignments.resize(field_assignments.size()+1);
    field_assignments.back().first=
      {
        entry.object.at("lhs_basename").value,
        entry.object.at("lhs_fieldname").value
      };
    field_assignments.back().second=
      static_cast<const exprt&>(rhs_irep);
  }
}

