
#include <ctype.h>

#include <algorithm>
#include <set>
#include <iostream>
#include <string>

#include <util/substitute.h>
#include <util/std_types.h>
#include <util/std_expr.h>
#include <util/symbol_table.h>
#include <util/namespace.h>
#include <util/prefix.h>

#include <java_bytecode/expr2java.h>
#include <java_bytecode/java_types.h>

#include <test_gen/java_test_source_factory.h>
#include <test_gen/mock_environment_builder.h>

#include <goto-programs/remove_returns.h>

#define INDENT_SPACES "  "
#define JAVA_NS_PREFIX_LEN 6u

namespace
{

class java_call_descriptor;
  
// Class to carry mock_classes and the mock environment builder around so that any
// attempt to generate a new object can easily find out whether it needs a real
// object or a mock.
class reference_factoryt {

public:

  std::set<std::string> must_mock_classes;
  std::set<std::string> no_mock_classes;
  bool disable_mocks;
  std::set<std::string> mock_classes;
  mock_environment_builder mockenv_builder;
  const symbol_tablet& symbol_table;
  const interpretert::dynamic_typest& dynamic_types;

  reference_factoryt(int indent, const symbol_tablet& st,
                     const interpretert::dynamic_typest& dt) :
    mockenv_builder(indent),
    symbol_table(st),
    dynamic_types(dt) {}

  const typet& get_symbol_type(const irep_idt&);
  const symbolt& get_or_fake_symbol(const irep_idt&, symbolt& fake);
  void add_value(std::string &result, const symbol_tablet &st,
		 const exprt &value, const std::string var_name="");
  void add_value(std::string &result, const symbol_tablet &st,
		 const struct_exprt &value, const std::string &this_name);
  void add_array_value(std::string &result, const symbol_tablet &st,
		 const struct_exprt &value, const std::string &this_name);  
  void add_assign_value(std::string &result, const symbol_tablet &st,
			const symbolt &symbol, const exprt &value);
  void add_declare_and_assign_noarray(std::string &result, const symbol_tablet &st,
                                      const symbolt& symbol, const exprt& value,
                                      bool should_declare);
  void add_declare_and_assign(std::string &result, const symbol_tablet &st,
                              const symbolt& symbol, const exprt& value,
                              bool should_declare);
  void add_global_state_assignments(std::string &result, const symbol_tablet &st,
				    inputst &in, const interpretert::input_var_functionst&);
  bool add_func_call_parameters(std::string &result, const symbol_tablet &st,
				const irep_idt &func_id, inputst &inputs);
  void add_mock_call(const interpretert::function_assignments_contextt,
		     const java_call_descriptor& desc, const symbol_tablet&);
  void defined_symbols_to_java(const interpretert::function_assignmentst& defined_symbols,
                               const symbol_tablet& st, std::vector<init_statement>& statements);
  void defined_symbols_to_java_fieldlists(
    const interpretert::function_assignmentst& defined_symbols,
    const symbol_tablet& st, std::vector<init_statement>& statements);
  void struct_to_fieldlist(const irep_idt& listname, const struct_exprt& in_struct,
                           const symbol_tablet& st, std::vector<init_statement>& statements);
  void add_mock_objects(const symbol_tablet &st,
			const interpretert::list_input_varst& opaque_function_returns);
  void expand_wildcard(const std::string& s, std::vector<std::string>& out);
  void configure_mocks(bool disable_mocks,
                       const optionst::value_listt& mock_classes,
                       const optionst::value_listt& no_mock_classes);
  bool shouldnt_mock_class(const std::string&);
  void gather_referenced_symbols(const exprt& rhs, inputst& in, const symbol_tablet&,
                                 std::vector<symbolt>& needed);
  void gather_referenced_symbols(const symbolt& symbol, inputst& in, const symbol_tablet&,
                                 std::vector<symbolt>& needed);
  std::string verify_mock_objects(const symbol_tablet &st,
                                  const interpretert::list_input_varst& opaque_function_returns);
};

bool is_array_tag(const irep_idt& tag)
{
  return has_prefix(id2string(tag),"java::array[");
}
  
// Various overrides to produce valid Java rather than expr2java's Java-with-explicit-pointers.
// Also a good opportunity to convert array structures appropriately.
class expr2cleanjava:public expr2javat {

  virtual std::string convert(const exprt &src, unsigned &precedence)
  {
    if(src.id()==ID_symbol)
    {
      std::string result=expr2javat::convert(src,precedence);
      return result.substr(0,result.rfind('!'));
    }
    // Address-of should be implicit
    else if(src.id()==ID_address_of)
      return convert(src.op0(),precedence);
    else {
      return expr2javat::convert(src,precedence);
    }
  }

  virtual std::string convert_rec(const typet& src, const c_qualifierst& qualifiers,
                                  const std::string& declarator)
  {
    // Write java::array[x] as x[]
    if(src.id()==ID_symbol && is_array_tag(to_symbol_type(src).get_identifier()))
    {
      const auto& st=to_symbol_type(src);
      const irept &element_irep=st.find(ID_C_element_type);
      assert(element_irep!=irept());
      const typet &element_type=static_cast<const typet&>(element_irep);
      return convert_rec(array_typet(element_type,nil_exprt()),qualifiers,declarator);
    }
    // Write 'struct A' as 'A'
    else if(src.id()==ID_symbol)
    {
      std::string ctype=expr2ct::convert_rec(src,qualifiers,declarator);
      if(has_prefix(ctype,"struct "))
        return ctype.substr(7);
      else
        return ctype;
    }
    else if(src.id()==ID_struct && is_array_tag(to_struct_type(src).get_tag()))
    {
      // Can't get the true element type from here. Settle for Object[] if a reference type.
      const auto& st=to_struct_type(src);
      array_typet datamem(st.get_component("data").type().subtype(),nil_exprt());
      return convert_rec(datamem,qualifiers,declarator);
    }
    // Write struct literals in brief form:
    else if(src.id()==ID_struct)
    {
      std::string tag=id2string(to_struct_type(src).get_tag());
      // Structs appear to be inconsistently tagged with and without namespace just now.
      if(!has_prefix(tag,"java::"))
        tag = "java::"+tag;
      return convert_rec(symbol_typet(tag),qualifiers,declarator);
    }
    // Write void*[] as Object[]
    else if(src.id()==ID_array && src.subtype()==pointer_typet(empty_typet()))
      return convert_rec(pointer_typet(symbol_typet("java::java.lang.Object"))
                         ,qualifiers,declarator+"[]");
    // Never write Java types with an explicit array size
    else if(src.id()==ID_array) 
      return convert_rec(src.subtype(),qualifiers,declarator+"[]");
    // Write references without an explicit * operator
    else if(src.id()==ID_pointer)
      return convert_rec(src.subtype(),qualifiers,declarator);
    
    return expr2javat::convert_rec(src,qualifiers,declarator);
  }

public:
 
  virtual std::string convert(const exprt &src)
  {
    return expr2javat::convert(src);
  }

  virtual std::string convert(const typet &src)
  {
    return expr2javat::convert(src);
  }  

  expr2cleanjava(const namespacet& ns) : expr2javat(ns) {}
  
};

void expr2java(std::string &result, const exprt &value, const namespacet &ns)
{
  expr2cleanjava e2j(ns);
  e2j.get_shorthands(value);
  std::string item=e2j.convert(value);
  result+=item;
}

// true if type is anonymous, i.e., declared within a class and ends on
// "$NUMBER"
bool is_anonymous_type(std::string &typeName)
{
  size_t index = typeName.find('$');
  if(index==std::string::npos)
    return false;

  return (typeName.substr(index + 1, std::string::npos)
          .find_first_not_of("0123456789")==std::string::npos);
}

void type2java(std::string &result, const typet &type, const namespacet &ns, bool javaSourceSep=true)
{
  expr2cleanjava e2j(ns);
  std::string item=e2j.convert(type);
  // replace '$' in java source code
  // has to remain for class file loading, e.g., via Reflector
  if(javaSourceSep && !is_anonymous_type(item))
    qualified2identifier(item,'$','.');
  result+=item;
}
  
std::string &indent(std::string &result, const size_t num_indent=1u)
{
  for (size_t i=0u; i < num_indent; ++i)
    result+=INDENT_SPACES;
  return result;
}

void add_test_method_name(std::string &result, const std::string &func_name)
{
  //result+="public class ";
  //result+=func_name;
  //result+="Test {\n";
  //indent(result)+="public void test";
  indent(result,2u)+="@org.junit.Test public void ";
  result+=func_name;
  result+="() throws Exception {\n";
}

void add_symbol(std::string &result, const symbolt &s)
{
  // XXX: Should be expr2java(...) once functional.
  const irep_idt &n=s.pretty_name.empty() ? s.base_name : s.pretty_name;
  result+=id2string(n);
}

void add_decl_from_type(std::string& result, const symbol_tablet &st, const typet &type, bool* out_is_primitive=0)
{
  const namespacet ns(st);
  const irep_idt &type_id=type.id();
  if(out_is_primitive)
    *out_is_primitive=
      type_id!=ID_symbol &&
      type_id!=ID_struct &&
      type_id!=ID_pointer &&
      type_id!=ID_array;
  type2java(result,type,ns);
}

void add_decl_with_init_prefix(std::string &result, const symbol_tablet &st,
			       const symbolt &symbol)
{
  add_decl_from_type(result, st, symbol.type);
  result+=' ';
}

void reference_factoryt::add_value(std::string &result, const symbol_tablet &st, const exprt &value,
    const std::string var_name)
{
  const namespacet ns(st);
  const irep_idt &id=value.id();
  if (ID_address_of == id) add_value(result, st,
      to_address_of_expr(value).object());
  else if (ID_struct == id) add_value(result, st, to_struct_expr(value), var_name);
  else if (ID_constant == id && !value.operands().empty()) add_value(result, st,
      value.op0(), var_name);
  else expr2java(result, value, ns);
}

bool is_synthetic_comp(const struct_typet::componentt &comp,
    const size_t index)
{
  return (ID_string == comp.type().id() && index == 0) ||
    comp.get_name()=="@lock";
}

class member_factoryt
{
  std::string &result;
  const symbol_tablet &st;
  const std::string &this_name;
  const struct_typet::componentst &comps;
  size_t comp_index;
  bool line_terminated;
  reference_factoryt& ref_factory;

public:
  member_factoryt(std::string &result, const symbol_tablet &st,
      const std::string &this_name, const typet &type, reference_factoryt& _ref_factory) :
      result(result), st(st), this_name(this_name), comps(
          to_struct_type(type).components()), comp_index(0u), line_terminated(
          true), ref_factory(_ref_factory)
  {
  }

  bool is_line_terminated() const
  {
    return line_terminated;
  }

  void operator()(const exprt &value)
  {
    assert(comp_index < comps.size());
    if (ID_struct == value.id())
    {
      member_factoryt mem_fac(result, st, this_name, value.type(), ref_factory);
      const struct_exprt::operandst &ops=value.operands();
      std::for_each(ops.begin(), ops.end(), mem_fac);
      if (result.back() != '\n') result+=";\n";
    } else
    {
      const struct_typet::componentt &comp=comps[comp_index];
      if (!is_synthetic_comp(comp, comp_index))
      {
        indent(result, 2u)+="Reflector.setInstanceField(";
        result+=this_name;
        result+=",\"";
        result+=id2string(comp.get_pretty_name());
        result+="\",";
        ref_factory.add_value(result, st, value);
        result+=")";
        if (comp_index < comps.size() - 1) result+=";\n";
      }
    }
    ++comp_index;
  }
};

const typet& reference_factoryt::get_symbol_type(const irep_idt& id)
{
  auto findit=dynamic_types.find(id);
  if(findit==dynamic_types.end())
    return symbol_table.lookup(id).type;
  else
    return findit->second;
}

static std::string force_instantiate(const std::string& classname)
{
  return "Reflector.forceInstance(\"" + classname + "\")";
}
  
void reference_factoryt::add_value(std::string &result, const symbol_tablet &st,
    const struct_exprt &value, const std::string &this_name)
{
  const namespacet ns(st);
  const typet &type=value.type();

  std::string qualified_class_name;
  type2java(qualified_class_name,type,ns);

  std::string qualified_class_file_name;
  type2java(qualified_class_file_name,type,ns,false);

  std::string instance_expr;
  bool should_mock = mock_classes.count(qualified_class_name);
  if(should_mock)
    instance_expr = mockenv_builder.instantiate_mock(qualified_class_name, false);
  else
    instance_expr = force_instantiate(qualified_class_file_name);

  result+='(' + qualified_class_name + ") " + instance_expr;

  if(should_mock)
    result+=mockenv_builder.register_mock_instance(qualified_class_name, this_name);

  member_factoryt mem_fac(result, st, this_name, type, *this);
  const struct_exprt::operandst &ops=value.operands();
  std::for_each(ops.begin(), ops.end(), mem_fac);
}

void reference_factoryt::add_assign_value(std::string &result, const symbol_tablet &st,
    const symbolt &symbol, const exprt &value)
{
  std::string symbol_name;
  add_symbol(symbol_name, symbol);
  result+=symbol_name;
  result+='=';
  namespacet ns(st);
  std::string printed_type;
  add_decl_from_type(printed_type, st, symbol.type);
  if(value.id()==ID_array)
    // if value is an array, create new object array instance
    // elements names are created in add_value below
    result += "new " + printed_type;
  else if(printed_type.size() >= 2 && printed_type.substr(printed_type.size()-2) == "[]")
  {
    result+='(';
    result += printed_type;
    result+=')';
  }
  add_value(result, st, value, symbol_name);
  result+=";\n";
}

symbol_exprt try_find_underlying_symbol_expr(exprt e)
{
  while(e.id()!=ID_symbol)
  {
    assert(e.operands().size()<=1);
    if(e.operands().size()==0)
      return symbol_exprt();
    e=e.op0();
  }
  // Make up a symbol with name of 'symbol' but type of the 'data' member:
  std::string symid=id2string(to_symbol_expr(e).get_identifier());
  size_t bangoff=symid.rfind('!');
  if(bangoff!=std::string::npos)
    symid=symid.substr(0,bangoff);
  return symbol_exprt(symid,e.type());
}

void reference_factoryt::add_declare_and_assign_noarray(std::string &result, const symbol_tablet &st,
                                                        const symbolt& symbol, const exprt& _value,
                                                        bool should_declare)
{
  if (should_declare) add_decl_with_init_prefix(result, st, symbol);
  exprt value=_value;
  if(value==irept() && symbol.type.id()==ID_array)
    value=array_exprt(to_array_type(symbol.type));

  add_assign_value(result, st, symbol, value);
}

void reference_factoryt::add_declare_and_assign(std::string &result, const symbol_tablet &st,
                                                const symbolt& symbol, const exprt& value,
                                                bool should_declare)
{
  // Special case arrays, which are internally represented as
  // structs with length and data members but need to turn back into simple arrays.
  namespacet ns(st);
  const typet& underlying=ns.follow(symbol.type);
  if(underlying.id()==ID_struct && is_array_tag(to_struct_type(underlying).get_tag()))
  {
    // No need to worry about the type; our custom expr2java will write that correctly;
    // just use the data-member (op2) value directly instead of writing .length=x, .data=y.
    add_declare_and_assign_noarray(result,st,symbol,value.op2(),should_declare);
  }
  else
  {
    add_declare_and_assign_noarray(result,st,symbol,value,should_declare);
  }
}
  
bool is_input_struct(const symbolt &symbol, const symbol_tablet& st,
    const interpretert::input_var_functionst input_defn_functions)
{
  const irep_idt& symtype=namespacet(st).follow(symbol.type).id();
  return (symtype==ID_struct||symtype==ID_pointer||symtype==ID_array) &&
    input_defn_functions.find(symbol.name)!=input_defn_functions.end() &&
    input_defn_functions.at(symbol.name)=="_start";
}

const symbolt& reference_factoryt::get_or_fake_symbol(const irep_idt& id, symbolt& fake_symbol)
{
  auto findit=symbol_table.symbols.find(id);
  if(findit==symbol_table.symbols.end())
  {
    // Dynamic object names are not in the symtab at the moment.
    fake_symbol.type=get_symbol_type(id);
    fake_symbol.name=id;
    std::string namestr=as_string(id);
    size_t findidx=namestr.find("::");
    if(findidx==std::string::npos)
      fake_symbol.base_name=fake_symbol.name;
    else
    {
      assert(namestr.size() >= findidx + 3);
      fake_symbol.base_name=namestr.substr(findidx + 2);
    }
    return fake_symbol;
  }
  else
    return findit->second;
}

void reference_factoryt::gather_referenced_symbols(const exprt& rhs, inputst& in,
                                                   const symbol_tablet& st,
                                                   std::vector<symbolt>& needed)
{
  forall_operands(op_iter,rhs)
  {
    if(op_iter->type().id()==ID_pointer || rhs.id()==ID_address_of)
    {
      symbol_exprt underlying=try_find_underlying_symbol_expr(*op_iter);
      if(underlying!=symbol_exprt())
      {
        symbolt fake_symbol;
        const symbolt &op_symbol=get_or_fake_symbol(underlying.get_identifier(),fake_symbol);
        gather_referenced_symbols(op_symbol,in,st,needed);
      }
    }
    else if(op_iter->type().id()==ID_struct)
    {
      gather_referenced_symbols(*op_iter,in,st,needed);
    }
  }
}
  
void reference_factoryt::gather_referenced_symbols(const symbolt& symbol, inputst& in,
                                                   const symbol_tablet& st,
                                                   std::vector<symbolt>& needed)
{
  const exprt& rhs=in[symbol.name];
  gather_referenced_symbols(rhs,in,st,needed);
  needed.push_back(symbol);
}
  
void reference_factoryt::add_global_state_assignments(std::string &result, const symbol_tablet &st,
    inputst &in, const interpretert::input_var_functionst &input_defn_functions)
{
  std::vector<symbolt> needed;
  for (inputst::const_reverse_iterator it=in.rbegin(); it != in.rend(); ++it)
  {
    symbolt fake_symbol;
    const symbolt &symbol=get_or_fake_symbol(it->first,fake_symbol);
    if (!symbol.is_static_lifetime) continue;
    if (!is_input_struct(symbol,st,input_defn_functions)) continue;
    gather_referenced_symbols(symbol,in,st,needed);
  }
  std::set<irep_idt> already_done;

  result+="\n";
  indent(result,2u) += "/* Populate class variables */\n";
  for(const auto& symbol : needed)
  {
    if(!already_done.insert(symbol.name).second)
      continue;
    indent(result, 2u);
    add_declare_and_assign(result,st,symbol,in[symbol.name],true);
  }
}

std::vector<irep_idt> get_parameters(const symbolt &func)
{
  std::vector<irep_idt> result;
  const code_typet &code_type=to_code_type(func.type);
  const code_typet::parameterst &params=code_type.parameters();
  for (const code_typet::parametert &param : params)
    result.push_back(param.get_identifier());
  return result;
}

bool is_instance_method(const symbol_tablet &st, const irep_idt &func_id)
{
  const symbolt &func=st.lookup(func_id);
  const std::vector<irep_idt> params(get_parameters(func));
  if(params.size() > 0)
    for (const irep_idt &param : params)
      {
        const symbolt &symbol=st.lookup(param);
        if (symbol.base_name=="this")
          return true;
      }
  return false;
}

bool reference_factoryt::add_func_call_parameters(std::string &result, const symbol_tablet &st,
    const irep_idt &func_id, inputst &inputs)
{
  const symbolt &func=st.lookup(func_id);
  const std::vector<irep_idt> params(get_parameters(func));

  result+="\n";
  indent(result,2u) += "/* initialize test parameters */\n";
  for (const irep_idt &param : params)
  {
    const symbolt &symbol=st.lookup(param);
    const inputst::iterator value=inputs.find(param);
    if(inputs.end()==value) 
    {
      return false;
    }
    else
    {
      if(symbol.base_name=="this")
        // do not declare "this" variable  for instance method
        continue;
      else
        add_declare_and_assign(indent(result,2u),st,symbol,value->second,true);
    }
  }
  return true;
}

std::string symbol_to_function_name(const symbolt &s, bool instance_method=false) {
  if(instance_method)
    return id2string(s.base_name);
  else
    {
      const std::string func_name_with_brackets(id2string(s.pretty_name));
      const size_t sz=func_name_with_brackets.size();
      assert(sz >= 2u);
      return func_name_with_brackets.substr(0, sz - 2);
    }
}
  
void add_func_call(std::string &result, const symbol_tablet &st,
                   const irep_idt &func_id, bool instance_method=false)
{
  // XXX: Should be expr2java(...) once functional.
  const symbolt &s=st.lookup(func_id);
  if(instance_method)
    result += '.' + symbol_to_function_name(s, instance_method);
  else
    result += symbol_to_function_name(s, instance_method);
  result+='(';
  const std::vector<irep_idt> params(get_parameters(s));
  unsigned nparams = 0;
  for (const irep_idt &param : params)
  {
    const symbolt &symbol=st.lookup(param);
    if(symbol.base_name=="this")
      // skip "this" parameter
      continue;
    if(nparams++ != 0)
      result+=", ";
    add_symbol(result, symbol);
  }
  result+=");";
}

std::string get_escaped_func_name(const symbolt &symbol)
{
  std::string result(id2string(symbol.pretty_name));
  substitute(result, ".", "_");
  substitute(result, "(", "X");
  substitute(result, ")", "Y");
  return result;
}

bool reference_factoryt::shouldnt_mock_class(const std::string& classname)
{
  assert(!disable_mocks); // Shouldn't get here at all in this case.
  // Priority 1: explicitly forced to mock something:
  if(must_mock_classes.count(classname))
    return false;
  // Priority 2: default exclude the standard library:
  if(has_prefix(classname,"java."))
    return true;
  // Priority 3: explicitly forbidden to mock:
  if(no_mock_classes.count(classname))
    return true;
  // Default allowed:
  return false;
}

void string_to_statements(const std::string& instring,
			  std::vector<init_statement>& out)
{
  // Break the declaration into lines, for formatting purposes.
  // (Todo: gather the init code this way everywhere, instead of as a long string)
  for(size_t last_semi=0, this_semi=instring.find(';', 1);
      last_semi!=std::string::npos;
      last_semi=this_semi, this_semi=instring.find(';', last_semi+1))
  {
    size_t takefrom=last_semi + 1;
    while(takefrom < this_semi &&
	  takefrom < instring.length() &&
	  isspace(instring[takefrom]))
      ++takefrom;
	    
    if(takefrom < this_semi && takefrom < instring.length())
    {
      std::string thisline=instring.substr(
	takefrom, this_semi==std::string::npos ? std::string::npos : this_semi - takefrom);
      out.push_back(init_statement::statement(thisline));
    }
  }
}

struct java_call_descriptor {
  std::string classname;
  std::string funcname;
  code_typet original_type;
  std::vector<java_type> java_arg_types;
  java_type java_ret_type;
};

void populate_descriptor_names(const symbolt& func, java_call_descriptor& desc)
{
  auto class_and_function_name=symbol_to_function_name(func);
  size_t sepidx=class_and_function_name.rfind('.');
  assert(sepidx!=std::string::npos && "Unqualified call in Java code?");
  desc.classname=class_and_function_name.substr(0, sepidx);
  desc.funcname=class_and_function_name.substr(sepidx + 1);
}

void populate_descriptor_types(const symbolt& func, const typet& ret_type,
  java_call_descriptor& desc, const symbol_tablet& st)
{
  const code_typet &code_type=to_code_type(func.type);
  desc.original_type=code_type;
 
  for(auto &param : code_type.parameters())
  {
    std::string thisparam;
    bool type_is_primitive;
    // Skip implicit 'this' parameter
    if(param.get_this())
      continue;
    add_decl_from_type(thisparam,st,param.type(),&type_is_primitive);
    desc.java_arg_types.push_back({thisparam,type_is_primitive});
  }

  add_decl_from_type(desc.java_ret_type.classname,st,
		     ret_type,&desc.java_ret_type.is_primitive);
}

void reference_factoryt::expand_wildcard(const std::string& s, std::vector<std::string>& out)
{
  if(s.length()==0 || s[s.length()-1]!='*')
  {
    out.push_back(s);
    return;
  }

  std::string prefix=s.substr(0,s.length()-1);
  for(const auto& it : symbol_table.symbols)
  {
    const auto& sym=it.second;
    if(!sym.is_type)
      continue;
    if(sym.type.id()!=ID_struct)
      continue;
    std::string basename=as_string(sym.base_name);
    if(has_prefix(basename,prefix))
      out.push_back(basename);
  }
  
}
  
void reference_factoryt::configure_mocks(
  bool disable_mocks,
  const optionst::value_listt& mock_classes_list,
  const optionst::value_listt& no_mock_classes_list)
{

  this->disable_mocks=disable_mocks;
  if(disable_mocks && (mock_classes_list.size() || no_mock_classes_list.size()))
    throw "java-mock-class and java-no-mock-class are incompatible with java-disable-mocks";
  
  for(const auto& c : mock_classes_list)
  {
    std::vector<std::string> expanded;
    expand_wildcard(c,expanded);
    for(const auto& c2 : expanded)
      must_mock_classes.insert(c2);
  }
  for(const auto& c : no_mock_classes_list)
  {
    std::vector<std::string> expanded;
    expand_wildcard(c,expanded);
    for(const auto& c2 : expanded)
    {
      no_mock_classes.insert(c2);
      if(must_mock_classes.count(c2))
      {
        std::ostringstream msg;
        msg << "Class " << c2 << " specified for both java-mock-class and java-no-mock-class";
        throw msg.str();
      }
    }
  }

}

void reference_factoryt::defined_symbols_to_java(
  const interpretert::function_assignmentst& defined_symbols,
  const symbol_tablet& st,
  std::vector<init_statement>& statements)
{
  for(auto defined : defined_symbols)
  {
    symbolt fake_symbol;
    const symbolt& use_symbol=get_or_fake_symbol(defined.id,fake_symbol);

    // Initial empty statement makes 'string_to_statements' easier
    std::string this_object_init=";";
    add_declare_and_assign(this_object_init,st,use_symbol,defined.value,true);

    string_to_statements(this_object_init, statements);
  }  
}

void reference_factoryt::struct_to_fieldlist(
  const irep_idt& listname, const struct_exprt& in_struct,
  const symbol_tablet& st, std::vector<init_statement>& statements)
{
  namespacet ns(st);
  // Make a FieldList object documenting the name-value pairs we
  // expect from this object:
  const auto& comps=to_struct_type(ns.follow(in_struct.type())).components();
  const auto& ops=in_struct.operands();
  assert(comps.size()==ops.size());
      
  for(size_t fieldidx=0,fieldlim=ops.size(); fieldidx!=fieldlim; ++fieldidx)
  {
    std::string compname=id2string(comps[fieldidx].get_pretty_name());
    assert(compname.size()>=1);
    if(ns.follow(comps[fieldidx].type()).id()==ID_struct)
    {
      // Superclass, I hope.
      assert(compname[0]=='@');
      struct_to_fieldlist(listname,to_struct_expr(ops[fieldidx]),st,statements);
    }
    else if(compname[0]=='@')
    {
      // Internal detail, do not check
      continue;
    }
    else {

      std::string valstr;
      std::string empty;
      add_value(valstr, st, ops[fieldidx], empty);
        
      std::ostringstream add_field_statement;
      add_field_statement << listname << ".add(\"" <<
        id2string(comps[fieldidx].get_pretty_name()) << "\", " <<
        valstr << ")";

      statements.push_back(init_statement::statement(add_field_statement.str()));
    }
  }
}
  
void reference_factoryt::defined_symbols_to_java_fieldlists(
  const interpretert::function_assignmentst& defined_symbols,
  const symbol_tablet& st,
  std::vector<init_statement>& statements)
{
  for(auto defined : defined_symbols)
  {
    symbolt fake_symbol;
    const symbolt& use_symbol=get_or_fake_symbol(defined.id,fake_symbol);
    std::string pretty_name;
    add_symbol(pretty_name,fake_symbol);

    if(use_symbol.type.id()==ID_struct && !is_array_tag(to_struct_type(use_symbol.type).get_tag()))
    {
      std::ostringstream new_statement;
      new_statement << "com.diffblue.java_testcase.FieldList " << pretty_name <<
        " = new com.diffblue.java_testcase.FieldList()";
      statements.push_back(init_statement::statement(new_statement.str()));
      struct_to_fieldlist(pretty_name,to_struct_expr(defined.value),st,statements);
    }
    else {
      // Initial empty statement makes 'string_to_statements' easier
      std::string this_object_init=";";
      add_declare_and_assign(this_object_init,st,use_symbol,defined.value,true);

      string_to_statements(this_object_init, statements);
    }
  }  
}
  
void reference_factoryt::add_mock_call(
  const interpretert::function_assignments_contextt defined_symbols_context,
  const java_call_descriptor& desc,
  const symbol_tablet& st)
{

  const auto& defined_symbols=defined_symbols_context.return_assignments;
  std::string return_value;
  assert(defined_symbols.size()!=0);
      
  if(desc.java_ret_type.is_primitive)
  {
    // defined_symbols should be simply [ some_identifier = some_primitive ]
    assert(defined_symbols.size()==1);
    add_value(return_value,st,defined_symbols.back().value);
  }
  else
  {
    // defined_symbols may be something like [ id1 = { x = 1, y = "Hello" },
    //                                         id2 = { a = id1, b = "World" } ]
    std::vector<init_statement> init_statements;

    std::ostringstream mocknameoss;
    static unsigned mocknumber=0;
    mocknameoss << "mock_instance_" << (++mocknumber);
    std::string mockname=mocknameoss.str();
    init_statements.push_back(
      init_statement::statement(desc.java_ret_type.classname + " " + mockname));

    // Start an anonymous scope, as the symbol names defined below may not be unique
    // if the same method stub was used more than once.
    init_statements.push_back(init_statement::scopeOpen());

    // Define each symbol from the trace:
    defined_symbols_to_java(defined_symbols,st,init_statements);

    const irep_idt& last_sym_name=defined_symbols.back().id;
    init_statements.push_back(
      init_statement::statement(mockname + "=" + as_string(last_sym_name)));

    // End anonymous scope.
    init_statements.push_back(init_statement::scopeClose());
	
    return_value=as_string(mockname);
	  
    mockenv_builder.add_to_prelude(init_statements);
  }

  bool is_static=!desc.original_type.has_this();
  bool is_constructor=desc.original_type.get_bool(ID_constructor);
      
  if(is_static)
    mockenv_builder.static_call(desc.classname, desc.funcname, desc.java_arg_types,
                                desc.java_ret_type, return_value);
  else if(is_constructor)
  {
    std::string caller=as_string(defined_symbols_context.calling_function);
    size_t namespace_idx=caller.find("java::");
    size_t classname_idx=namespace_idx + 6;
    size_t method_idx=caller.rfind('.');
    assert(namespace_idx==0 && method_idx!=std::string::npos);
    mockenv_builder.constructor_call(caller.substr(classname_idx, method_idx - classname_idx),
				     desc.classname, desc.java_arg_types, return_value);
  }
  else
    mockenv_builder.instance_call(desc.classname, desc.funcname,
      desc.java_arg_types, desc.java_ret_type, return_value);

}
  
void reference_factoryt::add_mock_objects(const symbol_tablet &st,
  const interpretert::list_input_varst& opaque_function_returns)
{

  if(disable_mocks)
    return;
  
  mock_classes.clear();

  for(auto fn_and_returns : opaque_function_returns)
  {

    const symbolt &func=st.lookup(fn_and_returns.first);    
    struct java_call_descriptor desc;
    populate_descriptor_names(func,desc);

    if(shouldnt_mock_class(desc.classname))
      continue;

    // Note that this class must be mocked whenever we try to generate a reference to it:
    mock_classes.insert(desc.classname);

  }

  for(auto fn_and_returns : opaque_function_returns)
  {

    const symbolt &func=st.lookup(fn_and_returns.first);    
    struct java_call_descriptor desc;
    populate_descriptor_names(func,desc);

    if(shouldnt_mock_class(desc.classname))
      continue;

    assert(fn_and_returns.second.size() != 0);
    // Get type from replacement value,
    // as remove_returns passlet has scrubbed the function return type by this point.
    const auto& last_definition_list=fn_and_returns.second.back().return_assignments;
    const auto& last_toplevel_assignment=last_definition_list.back().value;
    
    populate_descriptor_types(func,last_toplevel_assignment.type(),desc,st);

    for(auto defined_symbols_context : fn_and_returns.second)
      add_mock_call(defined_symbols_context,desc,st);
      
  }

  forall_symbols(it,symbol_table.symbols)
  {
    const auto& sym=it->second;
    if((!sym.is_type) && 
       sym.value.id()==ID_code && 
       sym.type.id()==ID_code &&
       has_prefix(as_string(sym.name),"java::") &&
       sym.type.get("opaque_method_capture_symbol")==irep_idt())
    {
      struct java_call_descriptor desc;
      populate_descriptor_names(sym,desc);
      populate_descriptor_types(sym,empty_typet(),desc,st);
      bool is_static=!desc.original_type.has_this();
      bool is_constructor=desc.original_type.get_bool(ID_constructor);
      // Can't have partial mocks for static methods or constructors--
      // either the whole namespace is available or it isn't.
      if(is_static || is_constructor)
	continue;
      mockenv_builder.note_elaborated_instance_method(desc.classname,
						      desc.funcname,
						      desc.java_arg_types);
    }
  }

}

std::string reference_factoryt::verify_mock_objects(const symbol_tablet &st,
  const interpretert::list_input_varst& opaque_function_returns)
{

  namespacet ns(st);
  std::vector<init_statement> verify_statements;
  
  for(auto fn_and_returns : opaque_function_returns)
  {

    const symbolt &func=st.lookup(fn_and_returns.first);    
    struct java_call_descriptor desc;
    populate_descriptor_names(func,desc);

    if(shouldnt_mock_class(desc.classname))
      continue;

    assert(fn_and_returns.second.size() != 0);
    // Get type from replacement value,
    // as remove_returns passlet has scrubbed the function return type by this point.
    const auto& last_definition_list=fn_and_returns.second.back().return_assignments;
    const auto& last_toplevel_assignment=last_definition_list.back().value;
    
    populate_descriptor_types(func,last_toplevel_assignment.type(),desc,st);

    bool is_static=!desc.original_type.has_this();
    bool is_constructor=desc.original_type.get_bool(ID_constructor);
    
    // Translate call parameters from exprt to Java expressions:
    // (For now just do primitive types)
    std::vector<verification_envt> verify_calls;
    for(const auto& call : fn_and_returns.second)
    {
      verify_calls.resize(verify_calls.size()+1);
      assert(call.param_assignments.size() >= desc.java_arg_types.size());

      // Seperate auxiliary defintions and direct parameters:
      std::vector<interpretert::function_assignmentt> aux_assignments;
      std::vector<interpretert::function_assignmentt> direct_assignments;

      auto first_aux=call.param_assignments.begin();
      size_t param_offset=call.param_assignments.size()-desc.java_arg_types.size();
      auto first_direct=first_aux;
      std::advance(first_direct,param_offset);

      aux_assignments.insert(aux_assignments.begin(),
                             first_aux,
                             first_direct);

      // Omit implicit 'this' argument for now:
      if((!is_static) && !is_constructor)
      {
        assert(param_offset>0);
        aux_assignments.pop_back();
      }
      
      direct_assignments.insert(direct_assignments.begin(),
                                first_direct,
                                call.param_assignments.end());

      // Render the aux assignments down to a Java statement list:
      defined_symbols_to_java_fieldlists(aux_assignments,st,verify_calls.back().aux_statements);
      
      // Create the direct parameters:
      for(size_t paramidx=0, paramlim=desc.java_arg_types.size(); paramidx!=paramlim; ++paramidx)
      {
        const auto& argtype=desc.java_arg_types[paramidx];
        const auto& param_assignment=call.param_assignments[paramidx+param_offset];
        std::string argstring;
        expr2java(argstring,param_assignment.value,ns);
        verify_calls.back().arg_strings.push_back(std::move(argstring));
      }
    }
    
    if(is_static)
      mockenv_builder.verify_static_calls(desc.classname,desc.funcname,desc.java_arg_types,
                                          verify_calls,verify_statements);
    else if(is_constructor)
      mockenv_builder.verify_constructor_calls(desc.classname,desc.funcname,desc.java_arg_types,
                                               verify_calls,verify_statements);
    else
      mockenv_builder.verify_instance_calls(desc.classname,desc.funcname,desc.java_arg_types,
                                            verify_calls,verify_statements);

  }

  std::ostringstream statement_stream;
  mockenv_builder.print_statements(verify_statements,statement_stream);
  return statement_stream.str();
  
}
  
} // End of anonymous namespace

std::string generate_java_test_case_from_inputs(const symbol_tablet &st, const irep_idt &func_id,
    bool enters_main, inputst inputs, const interpretert::list_input_varst& opaque_function_returns,
    const interpretert::input_var_functionst& input_defn_functions,
    const interpretert::dynamic_typest& dynamic_types,
    const std::string &test_func_name,
    const interpretert::side_effects_differencet &valuesDifference,
    const std::string &assertCompare, bool emitAssert,
    bool disable_mocks,
    bool disable_verify_mocks,                                                
    const optionst::value_listt& mock_classes,
    const optionst::value_listt& no_mock_classes,            
    const std::vector<std::string>& goals_reached,
    const std::string& expect_exception)
{
  namespacet ns(st);
  const symbolt &func=st.lookup(func_id);
  std::string result;

  if(goals_reached.size()!=0)
  {
    result="/** This test case reaches the following goals:\n";
    for(const auto& g : goals_reached)
      result+=("  " + g + "\n");
    result+="*/\n";
  }

  // Do this first since the mock object creation can require annotations on the test class.
  // Parameter is the indent level on generated code.
  reference_factoryt ref_factory(4,st,dynamic_types);

  ref_factory.configure_mocks(disable_mocks, mock_classes, no_mock_classes);
  ref_factory.add_mock_objects(st, opaque_function_returns);

  result += ref_factory.mockenv_builder.get_class_annotations() + "\n";
  add_test_method_name(result, test_func_name);

  std::string post_mock_setup_result;
  
  ref_factory.add_global_state_assignments(post_mock_setup_result, st, inputs, input_defn_functions);
  bool exists_func_call = false;
  if(enters_main)
    exists_func_call = ref_factory.add_func_call_parameters(post_mock_setup_result, st, func_id, inputs);
  else
  {
    indent(post_mock_setup_result) += "// NOTE: the given entry-point is not called, perhaps because\n";
    indent(post_mock_setup_result) += "// we encountered a fault during static initialisation. Instantiating\n";
    indent(post_mock_setup_result) += "// the target class to cause static initialisers run.\n\n";
    java_call_descriptor desc;
    populate_descriptor_names(func,desc);
    indent(post_mock_setup_result)+=force_instantiate(desc.classname);
    post_mock_setup_result+=";\n";
  } 
  // Finalise happens here because add_func_call_parameters et al
  // may have generated mock objects.
  std::string mock_final = ref_factory.mockenv_builder.finalise_instance_calls();
  result += "\n" + ref_factory.mockenv_builder.get_mock_prelude() +
    "\n" + post_mock_setup_result + "\n" + mock_final + '\n';

  if(!disable_verify_mocks)
  {
    indent(result,2)+="/* Verify that mock-object interactions were as expected: */\n";
    indent(result,2)+=ref_factory.verify_mock_objects(st,opaque_function_returns);
    result+='\n';
  }
  
  if(exists_func_call)
  {

    std::string declared_type;
    std::string declared_name;
    std::string call_expression;
    
    bool is_constructor=func.type.get_bool(ID_constructor);
    std::string retval_symbol=as_string(func.name)+RETURN_VALUE_SUFFIX;
    const auto findit=st.symbols.find(retval_symbol);
    if(is_constructor)
    {
      if(to_code_type(func.type).parameters().size()==0)
      {
        java_call_descriptor desc;
        populate_descriptor_names(func,desc);
        indent(result)+="/* creating instance to execute static initializer */\n";
        declared_type=desc.classname;
        declared_name="constructed";
        call_expression="(" + desc.classname + ") " + force_instantiate(desc.classname) + "; // ";
      }
      else
      {
        const auto& thistype=to_code_type(func.type).parameters()[0].type();
        indent(result) += "/* creating new object to test constructor */\n";
        add_decl_from_type(declared_type,st,thistype);
        declared_name="constructed";
        call_expression="new ";
      }
    }
    else
    {
      indent(result) += "/* call function under test */\n";      
      if(findit!=st.symbols.end())
      {
        add_decl_from_type(declared_type,st,findit->second.type);
        declared_name="retval";
      }
    }

    if((!is_constructor) && is_instance_method(st, func_id))
    {
      for (const irep_idt &param : get_parameters(st.lookup(func_id)))
      {
        const symbolt &symbol=st.lookup(param);
        if (symbol.base_name=="this")
        {
          const inputst::iterator value=inputs.find(param);
          const namespacet ns(st);
          expr2java(call_expression, value->second, ns);
        }
      }
      add_func_call(call_expression,st,func_id,true);
    }
    else
      add_func_call(call_expression,st,func_id);

    if(declared_type.length()!=0)
      indent(result,2)+=(declared_type + ' ' + declared_name + ";\n");

    unsigned indent_call=2u;
    
    if(expect_exception.size()!=0)
    {
      indent(result,2)+="try {\n";
      indent_call=4u;
    }

    indent(result,indent_call);
    if(declared_type.length()!=0)
      result+=(declared_name + " = ");
    result+=(call_expression+'\n');

    if(expect_exception.size()!=0)
    {
      indent(result,2)+="}\n";
      indent(result,2)+=("catch("+expect_exception+" e) {} // Catch expected exception\n");
    }
    
    if(emitAssert || valuesDifference.size() > 0)
    {
      if(emitAssert)
      {
        result+="\n";
        indent(result,2u)+="/* check return value */\n";
        indent(result,2u)+="assertTrue(retval" + assertCompare + ");\n";
      }
      if(valuesDifference.size() > 0)
      {
        result+="\n";
        indent(result,2u)+="/* check detected side effects */\n";
        for(auto &side_effect : valuesDifference)
        {
          auto &objectName = id2string(side_effect.first.first);
          auto &fieldName = id2string(side_effect.first.second);
          auto &value_expr = side_effect.second.second;
          const typet& type = value_expr.type();

          if(type.id()==ID_signedbv)
          {
            indent(result,2u)+="assertTrue("
              + from_expr(ns,"",value_expr)
              + " == (int) Reflector.getInstanceField("
              + objectName + ",\"" + fieldName + "\"));\n";
          }
        }
      }
    }
    else
    {
      result+="\n";
      indent(result,2u)+="/* Method return type is void, or not expected to return */\n";
    }
  }

  result+='\n';
  // closing the method
  indent(result)+="\n}\n";
  return result;

}

std::string func_name(const symbolt &symbol)
{
  return get_escaped_func_name(symbol);
}

void qualified2identifier(std::string &s, const char search, const char replace)
{
  std::replace(s.begin(), s.end(), search, replace);
}

