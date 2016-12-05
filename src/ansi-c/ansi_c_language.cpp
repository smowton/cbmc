/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#include <cstring>
#include <sstream>
#include <fstream>

#include <util/expr_util.h>
#include <util/config.h>
#include <util/get_base_name.h>
#include <util/symbol.h>

#include <linking/linking.h>
#include <linking/remove_internal_symbols.h>

#include "ansi_c_entry_point.h"
#include "ansi_c_language.h"
#include "ansi_c_typecheck.h"
#include "ansi_c_parser.h"
#include "expr2c.h"
#include "c_preprocess.h"
#include "ansi_c_internal_additions.h"
#include "type2name.h"

/*******************************************************************\

Function: ansi_c_languaget::extensions

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

std::set<std::string> ansi_c_languaget::extensions() const
{
  std::set<std::string> s;
  s.insert("c");
  s.insert("i");
  return s;
}

/*******************************************************************\

Function: ansi_c_languaget::modules_provided

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void ansi_c_languaget::modules_provided(std::set<std::string> &modules)
{
  modules.insert(get_base_name(parse_path, true));
}

/*******************************************************************\

Function: ansi_c_languaget::generate_opaque_stub_body

  Inputs:
          symbol - the function symbol which is opaque
          symbol_table - the symbol table

 Outputs: The identifier of the return variable. ID_nil if the function
          doesn't return anything.

 Purpose: To generate the stub function for the opaque function in
          question. The identifier is used in the flag to the interpreter
          that the function is opaque. In C, providing the function returns
          something, the id will be to_return_function_name.
          The GOTO code will simply create a NONDET instruction as the
          return value.

\*******************************************************************/

irep_idt ansi_c_languaget::generate_opaque_stub_body(
  symbolt &symbol,
  symbol_tablet &symbol_table)
{
  code_blockt new_instructions;
  code_typet &function_type=to_code_type(symbol.type);
  const typet &return_type=function_type.return_type();

  if(return_type.id()!=ID_nil)
  {
    auxiliary_symbolt return_symbol;
    return_symbol.name=get_stub_return_symbol_name(symbol.name);
    return_symbol.base_name=return_symbol.name;
    return_symbol.mode=ID_C;
    return_symbol.type=return_type;

    symbolt *symbol_ptr=nullptr;
    symbol_table.move(return_symbol, symbol_ptr);
    assert(symbol_ptr);

    exprt return_symbol_expr=side_effect_expr_nondett(return_type);
    new_instructions.copy_to_operands(code_returnt(return_symbol_expr));
    symbol.value=new_instructions;
    return symbol_ptr->name;
  }

  return ID_nil;
}

/*******************************************************************\

Function: ansi_c_languaget::build_stub_parameter_symbol

  Inputs:
          function_symbol - the symbol of an opaque function
          parameter_index - the index of the parameter within the
                            the parameter list
          parameter_type - the type of the parameter

 Outputs: A named symbol to be added to the symbol table representing
          one of the parameters in this opaque function.

 Purpose: To build the parameter symbol and choose its name. For C
          we do not have to worry about this pointers so can just
          name the parameters according to index.
          Builds a parameter with name stub_ignored_arg0,...

\*******************************************************************/

parameter_symbolt ansi_c_languaget::build_stub_parameter_symbol(
  const symbolt &function_symbol,
  size_t parameter_index,
  const code_typet::parametert &parameter)
{
  irep_idt base_name="stub_ignored_arg"+i2string(parameter_index);
  irep_idt identifier=id2string(function_symbol.name)+"::"+id2string(base_name);

  parameter_symbolt parameter_symbol;
  parameter_symbol.base_name=base_name;
  parameter_symbol.mode=ID_C;
  parameter_symbol.name=identifier;
  parameter_symbol.type=parameter.type();

  return parameter_symbol;
}

/*******************************************************************\

Function: ansi_c_languaget::preprocess

  Inputs:

 Outputs:

 Purpose: ANSI-C preprocessing

\*******************************************************************/

bool ansi_c_languaget::preprocess(
  std::istream &instream,
  const std::string &path,
  std::ostream &outstream)
{
  // stdin?
  if(path=="")
    return c_preprocess(instream, outstream, get_message_handler());

  return c_preprocess(path, outstream, get_message_handler());
}

/*******************************************************************\

Function: ansi_c_languaget::parse

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool ansi_c_languaget::parse(
  std::istream &instream,
  const std::string &path)
{
  // store the path
  parse_path=path;

  // preprocessing
  std::ostringstream o_preprocessed;

  if(preprocess(instream, path, o_preprocessed))
    return true;

  std::istringstream i_preprocessed(o_preprocessed.str());

  // parsing

  std::string code;
  ansi_c_internal_additions(code);
  std::istringstream codestr(code);

  ansi_c_parser.clear();
  ansi_c_parser.set_file(ID_built_in);
  ansi_c_parser.in=&codestr;
  ansi_c_parser.set_message_handler(get_message_handler());
  ansi_c_parser.for_has_scope=config.ansi_c.for_has_scope;
  ansi_c_parser.cpp98=false; // it's not C++
  ansi_c_parser.cpp11=false; // it's not C++
  ansi_c_parser.mode=config.ansi_c.mode;

  ansi_c_scanner_init();

  bool result=ansi_c_parser.parse();

  if(!result)
  {
    ansi_c_parser.set_line_no(0);
    ansi_c_parser.set_file(path);
    ansi_c_parser.in=&i_preprocessed;
    ansi_c_scanner_init();
    result=ansi_c_parser.parse();
  }

  // save result
  parse_tree.swap(ansi_c_parser.parse_tree);

  // save some memory
  ansi_c_parser.clear();

  return result;
}

/*******************************************************************\

Function: ansi_c_languaget::typecheck

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool ansi_c_languaget::typecheck(
  symbol_tablet &symbol_table,
  const std::string &module)
{
  symbol_tablet new_symbol_table;

  if(ansi_c_typecheck(parse_tree, new_symbol_table, module, get_message_handler()))
    return true;

  remove_internal_symbols(new_symbol_table);

  if(linking(symbol_table, new_symbol_table, get_message_handler()))
    return true;

  return false;
}

/*******************************************************************\

Function: ansi_c_languaget::final

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool ansi_c_languaget::final(symbol_tablet &symbol_table)
{
  generate_opaque_method_stubs(symbol_table);

  if(ansi_c_entry_point(symbol_table, "main", get_message_handler()))
    return true;

  return false;
}

/*******************************************************************\

Function: ansi_c_languaget::show_parse

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void ansi_c_languaget::show_parse(std::ostream &out)
{
  parse_tree.output(out);
}

/*******************************************************************\

Function: new_ansi_c_language

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

languaget *new_ansi_c_language()
{
  return new ansi_c_languaget;
}

/*******************************************************************\

Function: ansi_c_languaget::from_expr

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool ansi_c_languaget::from_expr(
  const exprt &expr,
  std::string &code,
  const namespacet &ns)
{
  code=expr2c(expr, ns);
  return false;
}

/*******************************************************************\

Function: ansi_c_languaget::from_type

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool ansi_c_languaget::from_type(
  const typet &type,
  std::string &code,
  const namespacet &ns)
{
  code=type2c(type, ns);
  return false;
}

/*******************************************************************\

Function: ansi_c_languaget::type_to_name

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool ansi_c_languaget::type_to_name(
  const typet &type,
  std::string &name,
  const namespacet &ns)
{
  name=type2name(type, ns);
  return false;
}

/*******************************************************************\

Function: ansi_c_languaget::to_expr

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool ansi_c_languaget::to_expr(
  const std::string &code,
  const std::string &module,
  exprt &expr,
  const namespacet &ns)
{
  expr.make_nil();

  // no preprocessing yet...

  std::istringstream i_preprocessed(
    "void __my_expression = (void) (\n"+code+"\n);");

  // parsing

  ansi_c_parser.clear();
  ansi_c_parser.set_file(irep_idt());
  ansi_c_parser.in=&i_preprocessed;
  ansi_c_parser.set_message_handler(get_message_handler());
  ansi_c_parser.mode=config.ansi_c.mode;
  ansi_c_scanner_init();

  bool result=ansi_c_parser.parse();

  if(ansi_c_parser.parse_tree.items.empty())
    result=true;
  else
  {
    expr=ansi_c_parser.parse_tree.items.front().declarator().value();

    // typecheck it
    result=ansi_c_typecheck(expr, get_message_handler(), ns);
  }

  // save some memory
  ansi_c_parser.clear();

  // now remove that (void) cast
  if(expr.id()==ID_typecast &&
     expr.type().id()==ID_empty &&
     expr.operands().size()==1)
    expr=expr.op0();

  return result;
}

/*******************************************************************\

Function: ansi_c_languaget::~ansi_c_languaget

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

ansi_c_languaget::~ansi_c_languaget()
{
}
