#include <iostream>
#include <functional>

#include <util/message.h>
#include <util/substitute.h>
#include <cbmc/bmc.h>
#include <ansi-c/expr2c_class.h>

#include <java_bytecode/java_entry_point.h>
#include <test_gen/java_test_source_factory.h>
#include <test_gen/java_test_case_generator.h>

#include <functional>

bool java_test_case_generatort::contains(const std::string &id, const char * const needle)
{
  return std::string::npos != id.find(needle);
}

bool java_test_case_generatort::is_meta(const irep_idt &id)
{
  const std::string &str=id2string(id);
  return contains(str, "$assertionsDisabled");
}

inputst java_test_case_generatort::generate_inputs(const symbol_tablet &st,
    const goto_functionst &gf, const goto_tracet &trace,
    interpretert::list_input_varst& opaque_function_returns,
    interpretert::input_var_functionst& first_assignments,
    interpretert::dynamic_typest& dynamic_types,
    const optionst &options)
{
  interpretert interpreter(st, gf, this, options);
  inputst res(interpreter.load_counter_example_inputs(trace, opaque_function_returns));
  for (inputst::const_iterator it(res.begin()); it != res.end();)
    if (is_meta(it->first)) it=res.erase(it);
    else ++it;
  first_assignments=interpreter.get_input_first_assignments();
  dynamic_types=interpreter.get_dynamic_types();
  return res;
}

const irep_idt &java_test_case_generatort::get_entry_function_id(const goto_functionst &gf)
{
  typedef goto_functionst::function_mapt function_mapt;
  const function_mapt &fm=gf.function_map;
  const irep_idt start(goto_functionst::entry_point());
  const function_mapt::const_iterator entry_func=fm.find(start);
  assert(fm.end() != entry_func);
  const goto_programt::instructionst &in=entry_func->second.body.instructions;
  typedef goto_programt::instructionst::const_reverse_iterator reverse_target;
  reverse_target codeit=in.rbegin();
  const reverse_target end=in.rend();
  assert(end != codeit);
  // Tolerate 'dead' statements at the end of _start.
  while(end!=codeit && codeit->code.get_statement()!=ID_function_call)
    ++codeit;
  assert(end != codeit);
  const reverse_target call=codeit;
  const code_function_callt &func_call=to_code_function_call(call->code);
  const exprt &func_expr=func_call.function();
  return to_symbol_expr(func_expr).get_identifier();
}

const std::string java_test_case_generatort::get_test_function_name(const symbol_tablet &st, const goto_functionst &gf, size_t test_idx)
{
  const irep_idt &entry_func_id=get_entry_function_id(gf);
    // the key is an arbitrary test name
  std::string entry_func_str=as_string(st.lookup(entry_func_id).pretty_name);
  // remove ., <, > and substitute with _ to create valid Java identifiers
  size_t paren_offset=entry_func_str.find('(');
  if(paren_offset!=std::string::npos)
    entry_func_str=entry_func_str.substr(0,paren_offset);
  substitute(entry_func_str, ".", "_");
  substitute(entry_func_str, "<", "_");
  substitute(entry_func_str, ">", "_");
  std::size_t h = std::hash<std::string>()(as_string(entry_func_id));
  std::ostringstream testname;
  testname << entry_func_str << "_" << std::hex << h << "_"
           << std::setfill('0') << std::setw(3) << test_idx;
  const std::string &unique_name = testname.str();
  return unique_name;
}

const std::string java_test_case_generatort::generate_test_case(
  const optionst &options, const symbol_tablet &st,
  const goto_functionst &gf, const goto_tracet &trace,
  const test_case_generatort generate, size_t test_idx,
  std::vector<std::string> goals_reached)
{

  interpretert::list_input_varst opaque_function_returns;
  interpretert::input_var_functionst input_defn_functions;
  interpretert::dynamic_typest dynamic_types;
  
  const inputst inputs(generate_inputs(st,gf,trace,opaque_function_returns,
                                       input_defn_functions,dynamic_types,
                                       options));
  const irep_idt &entry_func_id=get_entry_function_id(gf);
  bool enters_main=false;
  irep_idt previous_function;
  for(const auto& step : trace.steps)
  {
    if(step.pc->function==irep_idt())
      continue;
    if(step.pc->function==entry_func_id && previous_function=="_start")
    {
      enters_main=true;
      break;
    }
    previous_function=step.pc->function;
  }

  std::string assertCompare;
  /* can we emit an assert, i.e., does the function return a non-void value? */
  bool emitAssert = false;
  /* does the trace cover a complete flow through the function, i.e., not just
     an init block etc. */
  bool coversCompleteFlow = false;

  for(const auto& step : trace.steps)
  {
    if(step.type==goto_trace_stept::ASSIGNMENT)
    {
      irep_idt identifier=step.lhs_object.get_identifier();
      const source_locationt &source_location=step.pc->source_location;

      if(id2string(identifier)=="return'")
      {
        const exprt &expr = step.full_lhs_value;

        // from json_expr.cpp
        if(expr.id()==ID_constant)
        {
          status() << "FUNCTION: " << id2string(source_location.get_function()) << eom;
          status() << "ID      : " << id2string(identifier) << eom;
          status() << "VAL     : " << expr.get_string(ID_value) << eom;


          const namespacet ns(st);
          const typet &type=ns.follow(expr.type());

          // no unsinged ints in Java
          if(// type.id()==ID_unsignedbv ||
             type.id()==ID_signedbv ||
             type.id()==ID_c_bit_field)
          {
            std::size_t width = to_bitvector_type(type).get_width();
            if(width==8 || width==16 || width==32 || width==64)
            {
              mp_integer i;
              to_integer(expr, i);
              assertCompare=(" == " + integer2string(i));
              emitAssert = true;
            }
          }
          else if(type.id()==ID_c_enum)
          {
            assertCompare=(" == " + expr.get_string(ID_value));
            emitAssert = true;
          }
          else if(type.id()==ID_c_enum_tag)
          {
            assertCompare=(" == " + expr.get_string(ID_value));
            emitAssert = true;
          }
          else if(type.id()==ID_floatbv)
          {
            std::size_t width = to_bitvector_type(type).get_width();
            if(width==32 || width==64)
            {
              assertCompare=(" == " + expr.get_string(ID_value));
              emitAssert = true;
            }
          }
          else if(type.id()==ID_bool || type.id()==ID_c_bool)
          {
            if(expr.is_true())
              assertCompare=(" == true");
            else
              assertCompare=(" == false");
            emitAssert = true;
          }
          else if(type.id()==ID_string)
          {
            assertCompare=(".equals(" + expr.get_string(ID_value) +")");
            emitAssert = true;
          }
          else
          {
            assertCompare=" != null";
            emitAssert = true;
          }
        }
      }
    }
    else if(step.type==goto_trace_stept::OUTPUT)
      coversCompleteFlow = true;
  }

  if(goals_reached.size() && !coversCompleteFlow)
    return("/* test cases without return values are not generated in coverage mode */\n");

  std::string expect_exception;
  if(trace.steps.size()!=0)
  {
    const auto& last_step=*trace.steps.rbegin();
    if(last_step.type==goto_trace_stept::ASSERT)
    {
      const auto& prop_class=as_string(last_step.pc->source_location.get_property_class());
      if(prop_class=="assertion")
        expect_exception="java.lang.AssertionError";
      else if(prop_class=="array-index-oob-low" ||
              prop_class=="array-index-oob-high")
        expect_exception="java.lang.IndexOutOfBoundsException";
      else if(prop_class=="bad-dynamic-cast")
        expect_exception="java.lang.ClassCastException";
      else if(prop_class=="array-create-negative-size")
        expect_exception="NegativeArraySizeException";
    }
  }

  const std::string &unique_name = get_test_function_name(st, gf, test_idx);
  const std::string source(generate(st,entry_func_id,enters_main,inputs,opaque_function_returns,
                                    input_defn_functions,dynamic_types,unique_name,
                                    assertCompare, emitAssert,
                                    options.get_bool_option("java-disable-mocks"),
                                    !options.get_bool_option("java-verify-mocks"),
                                    options.get_list_option("java-mock-class"),
                                    options.get_list_option("java-no-mock-class"),
                                    goals_reached,expect_exception));
  const std::string empty("");
  std::string out_file_name=options.get_option("outfile");
  if(out_file_name.empty())
    {
      // if(!test_name.empty())
      //   std::cout << "Test case: " << test_name << std::endl;
      //std::cout << source << std::endl;
      return source;
    }
  else
    {
      out_file_name+=unique_name + ".java";

      std::ofstream(out_file_name.c_str()) << source;
      return empty;
    }
}

java_test_case_generatort::test_case_statust java_test_case_generatort::generate_test_case(optionst &options, const symbol_tablet &st,
                                                   const goto_functionst &gf, bmct &bmc, const test_case_generatort generate)
{
  options.set_option("stop-on-fail", true);
  switch (bmc.run(gf))
    {
    case safety_checkert::SAFE:
      return java_test_case_generatort::FAIL;
    case safety_checkert::ERROR:
      return java_test_case_generatort::ERROR;
    case safety_checkert::UNSAFE:
    default:
      {
        const goto_tracet &trace=bmc.safety_checkert::error_trace;
        status() << generate_test_case(options, st, gf, trace, generate) << eom;
        return java_test_case_generatort::SUCCESS;
      }
    }
}

const std::string  java_test_case_generatort::generate_java_test_case(const optionst &options, const symbol_tablet &st,
                                                                      const goto_functionst &gf, const goto_tracet &trace,
                                                                      const size_t test_idx,
                                                                      const std::vector<std::string> &goals_reached)
{
  const test_case_generatort source_gen=generate_java_test_case_from_inputs;
  return generate_test_case(options, st, gf, trace, source_gen, test_idx, goals_reached);
}

const std::string java_test_case_generatort::generate_test_func_name(const symbol_tablet &st,
                                                                     const goto_functionst &gf,
                                                                     const size_t test_idx)
{
  return get_test_function_name(st, gf, test_idx + 1);
}

java_test_case_generatort::test_case_statust java_test_case_generatort::generate_java_test_case(optionst &o, const symbol_tablet &st,
                                                       const goto_functionst &gf, bmct &bmc)
{
  const test_case_generatort source_gen=generate_java_test_case_from_inputs;
  return generate_test_case(o, st, gf, bmc, source_gen);
}
