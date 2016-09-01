
#include <util/std_expr.h>
#include <util/std_code.h>
#include <util/pointer_offset_size.h>
#include <util/i2string.h>
#include <util/namespace.h>
#include <util/prefix.h>

#include "java_object_factory.h"
#include "java_pointer_casts.h"

namespace
{ // Anon namespace for insert-nondet support functions

void insert_nondet_opaque_fields_at(const typet &expected_type,
                                    const exprt &ptr,
                                    symbol_tablet &symbol_table,
                                    code_blockt *parent_block,
                                    unsigned insert_before_index,
                                    bool is_constructor,
				    bool assume_non_null,
				    int max_nondet_array_length,
                                    const source_locationt &loc)
{

  // At this point we know 'ptr' points to an opaque-typed object. We should
  // nondet-initialise it
  // and insert the instructions *after* the offending call at
  // (*parent_block)[insert_before_index].

  assert(expected_type.id()==ID_pointer &&
         "Nondet initialiser should have pointer type");
  assert(parent_block &&
         "Must have an existing block to insert nondet-init code");

  namespacet ns(symbol_table);

  const auto &expected_base=ns.follow(expected_type.subtype());
  if(expected_base.id()!=ID_struct)
    return;

  const exprt cast_ptr=make_clean_pointer_cast(ptr,expected_type,ns);
  code_blockt new_instructions;

  exprt to_init=cast_ptr;
  // If it's a constructor the thing we're constructing has already
  // been allocated by this point.
  if(is_constructor)
    to_init=dereference_exprt(to_init,expected_base);

  gen_nondet_init(to_init,new_instructions,symbol_table,loc,false,true,
		  assume_non_null,max_nondet_array_length);

  if(new_instructions.operands().size()!=0)
  {

    auto institer=parent_block->operands().begin();
    std::advance(institer,insert_before_index);
    parent_block->operands().insert(institer,
                                    new_instructions.operands().begin(),
                                    new_instructions.operands().end());
  }
}

void assign_parameter_names(code_typet &ftype,const irep_idt &name_prefix,
                            symbol_tablet &symbol_table)
{

  code_typet::parameterst &parameters=ftype.parameters();

  // Mostly borrowed from java_bytecode_convert.cpp; maybe factor this out.
  // assign names to parameters
  for(std::size_t i=0; i<parameters.size(); ++i)
  {
    irep_idt base_name,identifier;

    if(i==0 && parameters[i].get_this())
      base_name="this";
    else
      base_name="stub_ignored_arg" + i2string(i);

    identifier=id2string(name_prefix) + "::" + id2string(base_name);
    parameters[i].set_base_name(base_name);
    parameters[i].set_identifier(identifier);

    // add to symbol table
    parameter_symbolt parameter_symbol;
    parameter_symbol.base_name=base_name;
    parameter_symbol.mode=ID_java;
    parameter_symbol.name=identifier;
    parameter_symbol.type=parameters[i].type();
    symbol_table.add(parameter_symbol);
  }
}

void insert_nondet_opaque_fields(symbolt &sym,symbol_tablet &symbol_table,
                                 code_blockt *parent,unsigned parent_index,
                                 bool assume_non_null,int max_nondet_array_length,
                                 const source_locationt &loc)
{

  code_blockt new_instructions;
  code_typet &required_type=to_code_type(sym.type);
  namespacet ns(symbol_table);

  bool is_constructor=sym.type.get_bool(ID_constructor);

  if(!is_constructor)
  {
    const auto &needed=required_type.return_type();
    if(needed==empty_typet())
      return;
  }

  assign_parameter_names(required_type,sym.name,symbol_table);

  if(is_constructor)
  {
    const auto &thisarg=required_type.parameters()[0];
    const auto &thistype=thisarg.type();
    auto &init_symbol=new_tmp_symbol(symbol_table,"to_construct");
    init_symbol.type=thistype;
    const auto init_symexpr=init_symbol.symbol_expr();
    auto getarg=
        code_assignt(init_symexpr,symbol_exprt(thisarg.get_identifier()));
    getarg.add_source_location() = loc;
    new_instructions.copy_to_operands(getarg);
    insert_nondet_opaque_fields_at(thistype,init_symexpr,symbol_table,
                                   &new_instructions,1,true,assume_non_null,
				   max_nondet_array_length,
                                   loc);
    sym.type.set("opaque_method_capture_symbol",init_symbol.name);
  }
  else
  {
    auto &toreturn_symbol=new_tmp_symbol(symbol_table,"to_return");
    toreturn_symbol.type=required_type.return_type();
    auto toreturn_symexpr=toreturn_symbol.symbol_expr();
    if(toreturn_symbol.type.id()!=ID_pointer)
    {
      gen_nondet_init(toreturn_symexpr,new_instructions,symbol_table,loc,false,false);
    }
    else
      insert_nondet_opaque_fields_at(
	required_type.return_type(),toreturn_symexpr,symbol_table,
	&new_instructions,0,false,assume_non_null,max_nondet_array_length,loc);
    new_instructions.copy_to_operands(code_returnt(toreturn_symexpr));
    sym.type.set("opaque_method_capture_symbol",toreturn_symbol.name);
  }

  sym.value=new_instructions;
}

void insert_nondet_opaque_fields(symbolt &sym,symbol_tablet &symbol_table,
                                 bool assume_non_null, int max_nondet_array_length,
                                 const source_locationt &loc)
{

  if(sym.is_type)
    return;
  if(sym.value.id()!=ID_nil)
    return;
  if(sym.type.id()!=ID_code)
    return;

  insert_nondet_opaque_fields(sym,symbol_table,0,0,assume_non_null,max_nondet_array_length,loc);
}

} // End anon namespace for insert-nondet support functions

void java_generate_opaque_method_stubs(symbol_tablet &symbol_table,
                                       bool assume_non_null,
				       int max_nondet_array_length,
                                       const source_locationt &loc)
{

  std::vector<irep_idt>identifiers;
  identifiers.reserve(symbol_table.symbols.size());
  forall_symbols(s_it,symbol_table.symbols) identifiers.push_back(s_it->first);

  for(auto &id : identifiers)
    insert_nondet_opaque_fields(symbol_table.symbols[id],symbol_table,
                                assume_non_null, max_nondet_array_length, loc);
}
