/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#include "java_entry_point.h"

#include <algorithm>
#include <set>
#include <unordered_set>
#include <iostream>

#include <linking/static_lifetime_init.h>

#include <util/arith_tools.h>
#include <util/prefix.h>
#include <util/std_types.h>
#include <util/std_code.h>
#include <util/std_expr.h>
#include <util/cprover_prefix.h>
#include <util/message.h>
#include <util/config.h>
#include <util/namespace.h>
#include <util/pointer_offset_size.h>
#include <util/suffix.h>

#include <util/c_types.h>
#include <ansi-c/string_constant.h>

#include <goto-programs/remove_exceptions.h>

#include "java_object_factory.h"
#include "java_types.h"
#include "java_utils.h"

static void create_initialize(symbol_tablet &symbol_table)
{
  // If __CPROVER_initialize already exists, replace it. It may already exist
  // if a GOTO binary provided it. This behaviour mirrors the ANSI-C frontend.
  symbol_table.remove(INITIALIZE_FUNCTION);

  symbolt initialize;
  initialize.name=INITIALIZE_FUNCTION;
  initialize.base_name=INITIALIZE_FUNCTION;
  initialize.mode=ID_java;

  code_typet type;
  type.return_type()=empty_typet();
  initialize.type=type;

  code_blockt init_code;

  namespacet ns(symbol_table);

  symbol_exprt rounding_mode=
    ns.lookup(CPROVER_PREFIX "rounding_mode").symbol_expr();

  init_code.add(
    code_assignt(rounding_mode, from_integer(0, rounding_mode.type())));

  initialize.value=init_code;

  symbol_table.add(initialize);
}

static bool should_init_symbol(const symbolt &sym)
{
  if(sym.type.id()!=ID_code &&
     sym.is_lvalue &&
     sym.is_state_var &&
     sym.is_static_lifetime &&
     sym.mode==ID_java)
    return true;

  return is_java_string_literal_id(sym.name);
}

static bool is_non_null_library_global(const irep_idt &symbolid)
{
  static const std::unordered_set<irep_idt, irep_id_hash> non_null_globals=
  {
    "java::java.lang.System.out",
    "java::java.lang.System.err",
    "java::java.lang.System.in"
  };
  return non_null_globals.count(symbolid);
}

static void java_static_lifetime_init(
  symbol_tablet &symbol_table,
  const source_locationt &source_location,
  bool assume_init_pointers_not_null,
  const object_factory_parameterst &object_factory_parameters,
  const select_pointer_typet &pointer_type_selector)
{
  symbolt &initialize_symbol=*symbol_table.get_writeable(INITIALIZE_FUNCTION);
  code_blockt &code_block=to_code_block(to_code(initialize_symbol.value));

  // We need to zero out all static variables, or nondet-initialize if they're
  // external. Iterate over a copy of the symtab, as its iterators are
  // invalidated by object_factory:

  std::list<irep_idt> symbol_names;
  for(const auto &entry : symbol_table.symbols)
    symbol_names.push_back(entry.first);

  for(const auto &symname : symbol_names)
  {
    const symbolt &sym=*symbol_table.lookup(symname);
    if(should_init_symbol(sym))
    {
      if(sym.value.is_nil() && sym.type!=empty_typet())
      {
        bool allow_null=!assume_init_pointers_not_null;
        if(allow_null)
        {
          irep_idt nameid=sym.symbol_expr().get_identifier();
          std::string namestr=id2string(nameid);
          const std::string suffix="@class_model";
          // Static '.class' fields are always non-null.
          if(has_suffix(namestr, suffix))
            allow_null=false;
          if(allow_null && is_java_string_literal_id(nameid))
            allow_null=false;
          if(allow_null && is_non_null_library_global(nameid))
            allow_null=false;
        }
        auto newsym=object_factory(
          sym.type,
          symname,
          code_block,
          allow_null,
          symbol_table,
          object_factory_parameters,
          allocation_typet::GLOBAL,
          source_location,
          pointer_type_selector);
        code_assignt assignment(sym.symbol_expr(), newsym);
        code_block.add(assignment);
      }
      else if(sym.value.is_not_nil())
      {
        code_assignt assignment(sym.symbol_expr(), sym.value);
        assignment.add_source_location()=source_location;
        code_block.add(assignment);
      }
    }
  }
}

///  Extends \p init_code with code that allocates the objects used as test
///  arguments for the function under test (\p function) and
///  non-deterministically initializes them.
///
///  All the code generated by this function goes to __CPROVER__start, just
///  before the call to the method under test.
///
///  \returns A std::vector of symbol_exprt, one per parameter of \p function,
///  containing the objects that can be used as arguments for \p function.
exprt::operandst java_build_arguments(
  const symbolt &function,
  code_blockt &init_code,
  symbol_tablet &symbol_table,
  bool assume_init_pointers_not_null,
  object_factory_parameterst object_factory_parameters,
  const select_pointer_typet &pointer_type_selector)
{
  const code_typet::parameterst &parameters=
    to_code_type(function.type).parameters();

  exprt::operandst main_arguments;
  main_arguments.resize(parameters.size());

  // certain method arguments cannot be allowed to be null, we set the following
  // variable to true iff the method under test is the "main" method, which will
  // be called (by the jvm) with arguments that are never null
  bool is_default_entry_point(config.main.empty());
  bool is_main=is_default_entry_point;

  // if walks like a duck and quacks like a duck, it is a duck!
  if(!is_main)
  {
    bool named_main=has_suffix(config.main, ".main");
    const typet &string_array_type=
      java_type_from_string("[Ljava.lang.String;");
    bool has_correct_type=
      to_code_type(function.type).return_type().id()==ID_empty &&
      (!to_code_type(function.type).has_this()) &&
      parameters.size()==1 &&
      parameters[0].type().full_eq(string_array_type);
    is_main=(named_main && has_correct_type);
  }

  // we iterate through all the parameters of the function under test, allocate
  // an object for that parameter (recursively allocating other objects
  // necessary to initialize it), and declare such object as an ID_input
  for(std::size_t param_number=0;
      param_number<parameters.size();
      param_number++)
  {
    const code_typet::parametert &p=parameters[param_number];
    const irep_idt base_name=p.get_base_name().empty()?
      ("argument#"+std::to_string(param_number)):p.get_base_name();

    // true iff this parameter is the `this` pointer of the method, which cannot
    // be null
    bool is_this=(param_number==0) && parameters[param_number].get_this();

    bool allow_null=
      !assume_init_pointers_not_null && !is_main && !is_this;

    // generate code to allocate and non-deterministicaly initialize the
    // argument
    main_arguments[param_number]=
      object_factory(
        p.type(),
        base_name,
        init_code,
        allow_null,
        symbol_table,
        object_factory_parameters,
        allocation_typet::LOCAL,
        function.location,
        pointer_type_selector);

    // record as an input
    codet input(ID_input);
    input.operands().resize(2);
    input.op0()=
      address_of_exprt(
        index_exprt(
          string_constantt(base_name),
          from_integer(0, index_type())));
    input.op1()=main_arguments[param_number];
    input.add_source_location()=function.location;

    init_code.move_to_operands(input);
  }

  return main_arguments;
}

void java_record_outputs(
  const symbolt &function,
  const exprt::operandst &main_arguments,
  code_blockt &init_code,
  symbol_tablet &symbol_table)
{
  const code_typet::parameterst &parameters=
    to_code_type(function.type).parameters();

  exprt::operandst result;
  result.reserve(parameters.size()+1);

  bool has_return_value=
    to_code_type(function.type).return_type()!=empty_typet();

  if(has_return_value)
  {
    // record return value
    codet output(ID_output);
    output.operands().resize(2);

    const symbolt &return_symbol=
      *symbol_table.lookup(JAVA_ENTRY_POINT_RETURN_SYMBOL);

    output.op0()=
      address_of_exprt(
        index_exprt(
          string_constantt(return_symbol.base_name),
          from_integer(0, index_type())));
    output.op1()=return_symbol.symbol_expr();
    output.add_source_location()=function.location;

    init_code.move_to_operands(output);
  }

  for(std::size_t param_number=0;
      param_number<parameters.size();
      param_number++)
  {
    const symbolt &p_symbol=
      *symbol_table.lookup(parameters[param_number].get_identifier());

    if(p_symbol.type.id()==ID_pointer)
    {
      // record as an output
      codet output(ID_output);
      output.operands().resize(2);
      output.op0()=
        address_of_exprt(
          index_exprt(
            string_constantt(p_symbol.base_name),
            from_integer(0, index_type())));
      output.op1()=main_arguments[param_number];
      output.add_source_location()=function.location;

      init_code.move_to_operands(output);
    }
  }

  // record exceptional return variable as output
  codet output(ID_output);
  output.operands().resize(2);

  // retrieve the exception variable
  const symbolt exc_symbol=*symbol_table.lookup(
    JAVA_ENTRY_POINT_EXCEPTION_SYMBOL);

  output.op0()=address_of_exprt(
    index_exprt(string_constantt(exc_symbol.base_name),
                from_integer(0, index_type())));
  output.op1()=exc_symbol.symbol_expr();
  output.add_source_location()=function.location;

  init_code.move_to_operands(output);
}

main_function_resultt get_main_symbol(
  const symbol_tablet &symbol_table,
  const irep_idt &main_class,
  message_handlert &message_handler,
  bool allow_no_body)
{
  messaget message(message_handler);

  // find main symbol
  if(config.main!="")
  {
    // Add java:: prefix
    std::string main_identifier="java::"+config.main;

    std::string error_message;
    irep_idt main_symbol_id=
      resolve_friendly_method_name(config.main, symbol_table, error_message);

    if(main_symbol_id==irep_idt())
    {
      message.error()
        << "main symbol resolution failed: " << error_message << messaget::eom;
      return main_function_resultt::Error;
    }

    symbol_tablet::opt_const_symbol_reft symbol=
      symbol_table.lookup(main_symbol_id);
    INVARIANT(
      symbol,
      "resolve_friendly_method_name should return a symbol-table identifier");

    // check if it has a body
    if(symbol->get().value.is_nil() && !allow_no_body)
    {
      message.error()
        << "main method `" << main_class << "' has no body" << messaget::eom;
      return main_function_resultt::Error;
    }

    return main_function_resultt(*symbol);   // Return found function
  }
  else
  {
    // no function given, we look for the main class
    assert(config.main=="");

    // are we given a main class?
    if(main_class.empty())
      return main_function_resultt::NotFound;   // silently ignore

    std::string entry_method=id2string(main_class)+".main";

    std::string prefix="java::"+entry_method+":";

    // look it up
    std::set<const symbolt *> matches;

    for(const auto &named_symbol : symbol_table.symbols)
    {
      if(named_symbol.second.type.id()==ID_code
        && has_prefix(id2string(named_symbol.first), prefix))
      {
        matches.insert(&named_symbol.second);
      }
    }

    if(matches.empty())
      // Not found, silently ignore
      return main_function_resultt::NotFound;

    if(matches.size()>1)
    {
      message.error()
        << "main method in `" << main_class
        << "' is ambiguous" << messaget::eom;
      return main_function_resultt::Error;  // give up with error, no main
    }

    // function symbol
    const symbolt &symbol=**matches.begin();

    // check if it has a body
    if(symbol.value.is_nil() && !allow_no_body)
    {
      message.error()
        << "main method `" << main_class << "' has no body" << messaget::eom;
      return main_function_resultt::Error;  // give up with error
    }

    return symbol;  // Return found function
  }
}

/// Given the \p symbol_table and the \p main_class to test, this function
/// generates a new function __CPROVER__start that calls the method under tests.
///
/// If __CPROVER__start is already in the `symbol_table`, it silently returns.
/// Otherwise it finds the method under test using `get_main_symbol` and
/// constructs a body for __CPROVER__start which does as follows:
///
/// 1. Allocates and initializes the parameters of the method under test.
/// 2. Call it and save its return variable in the variable 'return'.
/// 3. Declare variable 'return' as an output variable (codet with id
///    ID_output), together with other objects possibly altered by the execution
///    the method under test (in `java_record_outputs`)
///
/// When \p assume_init_pointers_not_null is false, the generated parameter
/// initialization code will non-deterministically set input parameters to
/// either null or a stack-allocated object. Observe that the null/non-null
/// setting only applies to the parameter itself, and is not propagated to other
/// pointers that it might be necessary to initialize in the object tree rooted
/// at the parameter.
/// Parameter \p max_nondet_array_length provides the maximum length for an
/// array used as part of the input to the method under test, and
/// \p max_nondet_tree_depth defines the maximum depth of the object tree
/// created for such inputs. This maximum depth is used **in conjunction** with
/// the so-called "recursive type set" (see field `recursive_set` in class
/// java_object_factoryt) to bound the depth of the object tree for the
/// parameter. Only when
/// - the depth of the tree is >= max_nondet_tree_depth **AND**
/// - the type of the object under initialization is already found in the
///   recursive set
/// then that object is not initalized and the reference pointing to it is
/// (deterministically) set to null. This is a source of underapproximation in
/// our approach to test generation, and should perhaps be fixed in the future.
///
/// \returns true if error occurred on entry point search
bool java_entry_point(
  symbol_tablet &symbol_table,
  const irep_idt &main_class,
  message_handlert &message_handler,
  bool assume_init_pointers_not_null,
  const object_factory_parameterst &object_factory_parameters,
  const select_pointer_typet &pointer_type_selector)
{
  // check if the entry point is already there
  if(symbol_table.symbols.find(goto_functionst::entry_point())!=
     symbol_table.symbols.end())
    return false; // silently ignore

  messaget message(message_handler);
  main_function_resultt res=
    get_main_symbol(symbol_table, main_class, message_handler);
  if(!res.is_success())
    return true;
  symbolt symbol=res.main_function;

  assert(!symbol.value.is_nil());
  assert(symbol.type.id()==ID_code);

  create_initialize(symbol_table);

  java_static_lifetime_init(
    symbol_table,
    symbol.location,
    assume_init_pointers_not_null,
    object_factory_parameters,
    pointer_type_selector);

  return generate_java_start_function(
    symbol,
    symbol_table,
    message_handler,
    assume_init_pointers_not_null,
    object_factory_parameters,
    pointer_type_selector);
}

bool recreate_initialize(
  symbol_tablet &symbol_table,
  const irep_idt &main_class,
  message_handlert &message_handler,
  bool assume_init_pointers_not_null,
  const object_factory_parameterst &object_factory_parameters,
  const select_pointer_typet &pointer_type_selector)
{
  messaget message(message_handler);
  main_function_resultt res=
    get_main_symbol(symbol_table, main_class, message_handler);
  if(res.status!=main_function_resultt::Success)
  {
    // No initialization was originally created (yikes!) so we can't recreate
    // it now
    return res.status==main_function_resultt::Error;
  }
  symbolt symbol=res.main_function;

  create_initialize(symbol_table);

  java_static_lifetime_init(
    symbol_table,
    symbol.location,
    assume_init_pointers_not_null,
    object_factory_parameters,
    pointer_type_selector);

  return false;
}

/// Generate a _start function for a specific function. See
/// java_entry_point for more details.
/// \param symbol: The symbol representing the function to call
/// \param symbol_table: Global symbol table
/// \param message_handler: Where to write output to
/// \param assume_init_pointers_not_null: When creating pointers, assume they
///   always take a non-null value.
/// \param max_nondet_array_length: The length of the arrays to create when
///   filling them
/// \param max_nondet_tree_depth: defines the maximum depth of the object tree
///   (see java_entry_points documentation for details)
/// \param pointer_type_selector: Logic for substituting types of pointers
/// \returns true if error occurred on entry point search, false otherwise
bool generate_java_start_function(
  const symbolt &symbol,
  symbol_tablet &symbol_table,
  message_handlert &message_handler,
  bool assume_init_pointers_not_null,
  const object_factory_parameterst& object_factory_parameters,
  const select_pointer_typet &pointer_type_selector)
{
  messaget message(message_handler);
  code_blockt init_code;

  // build call to initialization function
  {
    symbol_tablet::symbolst::const_iterator init_it=
      symbol_table.symbols.find(INITIALIZE_FUNCTION);

    if(init_it==symbol_table.symbols.end())
    {
      message.error() << "failed to find " INITIALIZE_FUNCTION " symbol"
                      << messaget::eom;
      return true; // give up with error
    }

    code_function_callt call_init;
    call_init.lhs().make_nil();
    call_init.add_source_location()=symbol.location;
    call_init.function()=init_it->second.symbol_expr();

    init_code.move_to_operands(call_init);
  }

  // build call to the main method, of the form
  // return = main_method(arg1, arg2, ..., argn)
  // where return is a new variable
  // and arg1 ... argn are constructed below as well

  code_function_callt call_main;

  source_locationt loc=symbol.location;
  loc.set_function(symbol.name);
  source_locationt &dloc=loc;

  // function to call
  call_main.add_source_location()=dloc;
  call_main.function()=symbol.symbol_expr();
  call_main.function().add_source_location()=dloc;

  // if the method return type is not void, store return value in a new variable
  // named 'return'
  if(to_code_type(symbol.type).return_type()!=empty_typet())
  {
    auxiliary_symbolt return_symbol;
    return_symbol.mode=ID_java;
    return_symbol.is_static_lifetime=false;
    return_symbol.name=JAVA_ENTRY_POINT_RETURN_SYMBOL;
    return_symbol.base_name="return";
    return_symbol.type=to_code_type(symbol.type).return_type();

    symbol_table.add(return_symbol);
    call_main.lhs()=return_symbol.symbol_expr();
  }

  // add the exceptional return value
  auxiliary_symbolt exc_symbol;
  exc_symbol.mode=ID_java;
  exc_symbol.name=JAVA_ENTRY_POINT_EXCEPTION_SYMBOL;
  exc_symbol.base_name=exc_symbol.name;
  exc_symbol.type=java_reference_type(empty_typet());
  symbol_table.add(exc_symbol);

  // Zero-initialise the top-level exception catch variable:
  init_code.copy_to_operands(
    code_assignt(
      exc_symbol.symbol_expr(),
      null_pointer_exprt(to_pointer_type(exc_symbol.type))));

  // create code that allocates the objects used as test arguments and
  // non-deterministically initializes them
  exprt::operandst main_arguments=
    java_build_arguments(
      symbol,
      init_code,
      symbol_table,
      assume_init_pointers_not_null,
      object_factory_parameters,
      pointer_type_selector);
  call_main.arguments()=main_arguments;

  // Create target labels for the toplevel exception handler:
  code_labelt toplevel_catch("toplevel_catch", code_skipt());
  code_labelt after_catch("after_catch", code_skipt());

  code_blockt call_block;

  // Push a universal exception handler:
  // Catch all exceptions:
  // This is equivalent to catching Throwable, but also works if some of
  // the class hierarchy is missing so that we can't determine that
  // the thrown instance is an indirect child of Throwable
  code_push_catcht push_universal_handler(
    irep_idt(), toplevel_catch.get_label());
  irept catch_type_list(ID_exception_list);
  irept catch_target_list(ID_label);

  call_block.move_to_operands(push_universal_handler);

  // we insert the call to the method AFTER the argument initialization code
  call_block.move_to_operands(call_main);

  // Pop the handler:
  code_pop_catcht pop_handler;
  call_block.move_to_operands(pop_handler);
  init_code.move_to_operands(call_block);

  // Normal return: skip the exception handler:
  init_code.copy_to_operands(code_gotot(after_catch.get_label()));

  // Exceptional return: catch and assign to exc_symbol.
  code_landingpadt landingpad(exc_symbol.symbol_expr());
  init_code.copy_to_operands(toplevel_catch);
  init_code.move_to_operands(landingpad);

  // Converge normal and exceptional return:
  init_code.move_to_operands(after_catch);

  // declare certain (which?) variables as test outputs
  java_record_outputs(symbol, main_arguments, init_code, symbol_table);

  // create a symbol for the __CPROVER__start function, associate the code that
  // we just built and register it in the symbol table
  symbolt new_symbol;

  code_typet main_type;
  main_type.return_type()=empty_typet();

  new_symbol.name=goto_functionst::entry_point();
  new_symbol.type.swap(main_type);
  new_symbol.value.swap(init_code);
  new_symbol.mode=ID_java;

  if(!symbol_table.insert(std::move(new_symbol)).second)
  {
    message.error() << "failed to move main symbol" << messaget::eom;
    return true;
  }

  return false;
}
