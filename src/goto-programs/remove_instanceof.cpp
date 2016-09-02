
#include "class_hierarchy.h"
#include "class_identifier.h"
#include "remove_instanceof.h"

#include <sstream>

class remove_instanceoft {

  symbol_tablet& symbol_table;
  namespacet ns;
  class_hierarchyt class_hierarchy;
  goto_functionst& goto_functions;
  
  // Single program (returns changed)
  bool lower_instanceof(goto_programt&);

  // Single instruction (returns changed)
  bool lower_instanceof(
    goto_programt &goto_program,
    goto_programt::targett target);

  // Expression (returns changed)
  bool lower_instanceof(
    exprt& e,
    goto_programt &goto_program,
    goto_programt::targett this_inst);

public:

  remove_instanceoft(
    symbol_tablet &_symbol_table,
    goto_functionst &_goto_functions):
    symbol_table(_symbol_table),
    ns(_symbol_table),
    goto_functions(_goto_functions) {
    class_hierarchy(_symbol_table);
  }
 
  // All functions
  void lower_instanceof();

};

bool remove_instanceoft::lower_instanceof(
  exprt& e,
  goto_programt &goto_program,
  goto_programt::targett this_inst)
{
  static int lowered_count=0;
  bool changed=false;
 
  if(e.id()=="java_instanceof")
  {
    const exprt& check_ptr=e.op0();
    assert(check_ptr.type().id()==ID_pointer);
    const exprt& target_arg=e.op1();
    assert(target_arg.id()==ID_type);
    const typet& target_type=target_arg.type();

    // Find all types we know about that satisfy the given requirement:
    assert(target_type.id()==ID_symbol);
    const irep_idt& target_name=to_symbol_type(target_type).get_identifier();
    std::vector<irep_idt> children=class_hierarchy.get_children_trans(target_name);
    children.push_back(target_name);

    if(children.empty())
    {
      // We don't know about this type at all? Give in.
      //warning() << "Unable to execute instanceof class " << target_name <<
      //"; returning false" << eom;
      e=false_exprt();
      return true;      
    }
      
    // Insert an instruction before this one that assigns the clsid we're checking
    // against to a temporary, as GOTO program if-expressions should not contain derefs.

    symbol_typet jlo("java::java.lang.Object");
    exprt object_clsid=get_class_identifier_field(check_ptr,jlo,ns);
     
    std::ostringstream symname;
    symname << "instanceof_tmp::instanceof_tmp" << (++lowered_count);
    auxiliary_symbolt newsym;
    newsym.name=symname.str();
    newsym.type=object_clsid.type();
    newsym.base_name=newsym.name;
    newsym.mode=ID_java;
    newsym.is_type=false;
    assert(!symbol_table.add(newsym));

    code_assignt clsid_tmp(newsym.symbol_expr(),object_clsid);
    auto newinst=goto_program.insert_before(this_inst);
    newinst->make_assignment();
    newinst->code=std::move(clsid_tmp);
    newinst->source_location=this_inst->source_location;

    // Replace the instanceof construct with a big-or.
    or_exprt big_or;
    for(const auto& clsname : children)
    {
      constant_exprt clsexpr(clsname,string_typet());
      equal_exprt test(newsym.symbol_expr(),clsexpr);
      big_or.move_to_operands(test);
    }
    if(big_or.operands().size()==1)
      e=big_or.op0();
    else
      e=big_or;

    changed=true;
  }
  else
  {
    Forall_operands(opiter,e)
      changed|=lower_instanceof(*opiter,goto_program,this_inst);
  }

  return changed;
}
 
bool remove_instanceoft::lower_instanceof(
  goto_programt &goto_program,
  goto_programt::targett target)
{
  return lower_instanceof(target->code,goto_program,target) |
    lower_instanceof(target->guard,goto_program,target);
}

bool remove_instanceoft::lower_instanceof(goto_programt &goto_program)
{
  bool changed=false;
  Forall_goto_program_instructions(target,goto_program)
    changed|=lower_instanceof(goto_program,target);
  if(changed)
    goto_program.update();
  return changed;
}

void remove_instanceoft::lower_instanceof()
{
  bool changed=false;
  for(auto& f : goto_functions.function_map)
    changed|=lower_instanceof(f.second.body);
  if(changed)
    goto_functions.compute_location_numbers();
}

void remove_instanceof(
  symbol_tablet &symbol_table,
  goto_functionst &goto_functions)
{
  remove_instanceoft rem(symbol_table,goto_functions);
  rem.lower_instanceof();
}
