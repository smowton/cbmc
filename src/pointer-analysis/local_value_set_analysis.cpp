
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
        external_value_set_exprt param_var(
          param.type().subtype(),constant_exprt(param_name,string_typet()));
        initial_state.insert(param_entry.object_map,param_var);
      }
    }

  }
}
