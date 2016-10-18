
#include "local_value_set_analysis.h"

void local_value_set_analysist::initialize(const goto_programt& fun)
{
  value_set_analysist::initialize(fun);
  
  if(fun.instructions.size()!=0)
  {
    auto& initial_state=(*this)[fun.instructions.begin()].value_set;
  
    // Now insert fresh symbols for each parameter, indicating an unknown external points-to set.
    for(const auto& param : function_type.parameters())
    {
      if(param.type().id()==ID_pointer)
      {
        const auto& param_name=param.get_identifier();
        value_sett::entryt param_entry_blank(id2string(param_name),"");
        auto& param_entry=initial_state.get_entry(param_entry_blank, param.type().subtype(), ns);
        irep_idt initial_content;
        switch(mode) {
        case LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET:
          initial_content="external_objects";
          break;
        case LOCAL_VALUE_SET_ANALYSIS_EXTERNAL_SET_PER_ACCESS_PATH:
          initial_content=param_name;
          break;
        default:
          throw "Missing mode in switch";          
        }
        external_value_set_exprt param_var(
          param.type().subtype(),constant_exprt(initial_content,string_typet()),mode);
        initial_state.insert(param_entry.object_map,param_var);
      }
    }

  }
}

void local_value_set_analysist::transform_function_stub_single_external_set(
  const irep_idt& fname, statet& state, locationt l_call, locationt l_return)
{
  

}

void local_value_set_analysist::transform_function_stub(
  const irep_idt& fname, statet& state, locationt l_call, locationt l_return)
{
  // Execute a summary description for function fname.
  switch(mode)
  {
  case LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET:
    transform_function_stub_single_external_set(fname,state,l_call,l_return);
    break;
  default:
    throw "Summaries not implemented";
  }
}

void save_summary_single_external_set(
  const statet& final_state, json_arrayt& assigns)
{
  // Just save a list of fields that may be overwritten by this function, and the values
  // they may be assigned.
  json_arrayt assigns;
  for(const auto& entry : final_state.values)
  {
    const std::string prefix="external_objects.";
    const std::string entryname=id2string(entry.first);
    if(has_prefix(entryname,prefix))
    {
      json_objectt assign;
      assign["lhs"]=json_stringt(entry.second.suffix);
      std::string fieldname=entryname.substr(prefix.length());
      const auto& pointsto=entry.second.object_map.read();
      for(const auto& pointsto_number : pointsto)
      {
        const auto& pointsto_expr=object_numbering[pointsto_number.first];
        json_objectt pointsto_json=irep_to_json(pointsto_expr);
        assign["rhs"]=std::move(pointsto_json);
        assigns.push_back(assign);
      }
    }
  }
}

void local_value_set_analysist::save_summary(const goto_programt& goto_program)
{
  assert(goto_program.instructions.size()!=0);
  locationt last_loc=std::prev(goto_program.instructions.end());
  const auto& final_state=get_state(last_loc);
  auto summary=std::make_shared<lvsaa_summaryt>(final_state);
  database_of_summariest db;
  db.insert(std::make_pair(irep_idt(function_name),summary));
  
  switch(mode)
  {
  case LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET:
    write_database_as_json(db,save_summary_single_external_set,database_dirname);
    break;
  default:
    throw "Summaries not supported";
  }    
}
