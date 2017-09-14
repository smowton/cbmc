/*******************************************************************\

Module: Value-set analysis tests

Author: Chris Smowton, chris@smowton.net

\*******************************************************************/

#include <catch.hpp>

#include <util/config.h>
#include <langapi/mode.h>
#include <goto-programs/initialize_goto_model.h>
#include <goto-programs/goto_inline.h>
#include <java_bytecode/java_bytecode_language.h>
#include <java_bytecode/java_types.h>
#include <pointer-analysis/value_set_analysis.h>

/// An example customised value_sett. It makes a series of small changes
/// to the underlying value_sett logic, which can then be verified by the
/// test below:
/// * Writes to variables with 'ignored' in their name are ignored.
/// * All writes are made weak by forcing `add_to_sets` to true.
/// * Never propagate values via the field "never_read"
/// * Adds an ID_unknown to the value of variable "maybe_unknown", and
///     to the possible referees of fields named unknown_field_ref and
///     variables named unknown_global_ref
class test_value_sett:
  public value_set_opst,
  public custom_value_sett<basic_value_sett>
{
public:
  /// Builds a test_value_set, configuring our underlying_value_set object to
  /// defer to our custom logic
  test_value_sett():
    custom_value_sett<basic_value_sett>(this)
  {
  }

  /// Copies a test_value_set, copying our underlying_value_set object
  /// but setting it to defer to *this* instance's custom logic
  test_value_sett(const test_value_sett &other):
    custom_value_sett<basic_value_sett>(this, other)
  {
  }

  static bool assigns_to_ignored_variable(const code_assignt &assign)
  {
    if(assign.lhs().id()!=ID_symbol)
      return false;
    const irep_idt &id=to_symbol_expr(assign.lhs()).get_identifier();
    return id2string(id).find("ignored")!=std::string::npos;
  }

  void apply_code(const codet &code, const namespacet &ns) override
  {
    // Ignore assignments to the local "ignored"
    if(code.get_statement()==ID_assign &&
       assigns_to_ignored_variable(to_code_assign(code)))
    {
      return;
    }
    else
    {
      underlying_value_set.apply_code(code, ns);
    }
  }

  void assign(
    const exprt &lhs,
    const exprt &rhs,
    const namespacet &ns,
    bool is_simplified,
    bool add_to_sets) override
  {
    // Make writes to 'weak_local' weak by forcing 'add_to_sets':
    if(lhs.id()==ID_symbol)
    {
      const irep_idt &id=to_symbol_expr(lhs).get_identifier();
      if(id2string(id).find("weak_local")!=std::string::npos)
        add_to_sets=true;
    }

    underlying_value_set.assign(lhs, rhs, ns, is_simplified, add_to_sets);
  }

  void assign_rec(
    const exprt &lhs,
    const object_mapt &values_rhs,
    const std::string &suffix,
    const namespacet &ns,
    bool add_to_sets) override
  {
    // Disregard writes against variables containing 'no_write':
    if(lhs.id()==ID_symbol)
    {
      const irep_idt &id=to_symbol_expr(lhs).get_identifier();
      if(id2string(id).find("no_write")!=std::string::npos)
        return;
    }

    underlying_value_set.assign_rec(lhs, values_rhs, suffix, ns, add_to_sets);
  }

  void get_value_set_rec(
    const exprt &expr,
    object_mapt &dest,
    const std::string &suffix,
    const typet &original_type,
    const namespacet &ns) const override
  {
    // Ignore reads from fields named "never_read"
    if(expr.id()==ID_member &&
       to_member_expr(expr).get_component_name()=="never_read")
    {
      return;
    }
    else
    {
      underlying_value_set.get_value_set_rec(
        expr, dest, suffix, original_type, ns);
    }
  }

  void get_value_set(
    const exprt &expr,
    object_mapt &dest,
    const namespacet &ns,
    bool is_simplified) const override
  {
    underlying_value_set.get_value_set(expr, dest, ns, is_simplified);

    // Always add an ID_unknown to variables containing "maybe_unknown":
    if(expr.id()==ID_symbol)
    {
      const irep_idt &id=to_symbol_expr(expr).get_identifier();
      if(id2string(id).find("maybe_unknown")!=std::string::npos)
        underlying_value_set.insert(dest, exprt(ID_unknown, expr.type()));
    }
  }

  void get_reference_set(
    const exprt &expr,
    object_mapt &dest,
    const namespacet &ns) const override
  {
    underlying_value_set.get_reference_set(expr, dest, ns);

    // Add ID_unknown to the possible referees of 'unknown_field_ref'
    if(expr.id()==ID_dereference &&
       expr.op0().id()==ID_member &&
       to_member_expr(expr.op0()).get_component_name()=="unknown_field_ref")
    {
      underlying_value_set.insert(dest, exprt(ID_unknown, expr.type()));
    }
  }

  void get_reference_set_rec(
    const exprt &expr,
    object_mapt &dest,
    const namespacet &ns) const override
  {
    underlying_value_set.get_reference_set_rec(expr, dest, ns);

    // Add ID_unknown to the possible referees of 'unknown_global_ref'
    if(expr.id()==ID_dereference &&
       expr.op0().id()==ID_symbol)
    {
      const irep_idt &id=to_symbol_expr(expr.op0()).get_identifier();
      if(id2string(id).find("unknown_global_ref")!=std::string::npos)
      {
        underlying_value_set.insert(dest, exprt(ID_unknown, expr.type()));
      }
    }
  }
};

typedef value_set_analysis_baset<test_value_sett> test_value_set_analysist;

#define TEST_PREFIX "java::CustomVSATest."
#define TEST_FUNCTION_NAME TEST_PREFIX "test:()V"
#define TEST_LOCAL_PREFIX TEST_FUNCTION_NAME "::"

template<class VST>
static value_setst::valuest
get_values(const VST &value_set, const namespacet &ns, const exprt &expr)
{
  value_setst::valuest vals;
  value_set.read_value_set(expr, vals, ns);
  return vals;
}

static std::size_t exprs_with_id(
  const value_setst::valuest &exprs, const irep_idt &id)
{
  return std::count_if(
    exprs.begin(),
    exprs.end(),
    [&id](const exprt &expr)
    {
      return expr.id()==id ||
        (expr.id()==ID_object_descriptor &&
         to_object_descriptor_expr(expr).object().id()==id);
    });
}

SCENARIO("test_value_set_analysis",
         "[core][pointer-analysis][value_set_analysis]")
{
  GIVEN("Normal and custom value-set analysis of CustomVSATest::test")
  {
    goto_modelt goto_model;
    null_message_handlert null_output;
    cmdlinet command_line;

    // This classpath is the default, but the config object
    // is global and previous unit tests may have altered it
    command_line.set("java-cp-include-files", ".");
    config.java.classpath={"."};
    command_line.args.push_back("CustomVSATest.class");

    register_language(new_java_bytecode_language);

    bool model_init_failed=
      initialize_goto_model(goto_model, command_line, null_output);

    namespacet ns(goto_model.symbol_table);

    // Fully inline the test program, to avoid VSA conflating
    // constructor callsites confusing the results we're trying to check:
    goto_function_inline(goto_model, TEST_FUNCTION_NAME, null_output);

    REQUIRE(!model_init_failed);

    const goto_programt &test_function=
      goto_model.goto_functions.function_map.at(TEST_PREFIX "test:()V").body;

    value_set_analysist::locationt test_function_end=
      std::prev(test_function.instructions.end());

    value_set_analysist normal_analysis(ns);
    normal_analysis(goto_model.goto_functions);
    const auto &normal_function_end_vs=
      normal_analysis[test_function_end].value_set;

    test_value_set_analysist test_analysis(ns);
    test_analysis(goto_model.goto_functions);
    const auto &test_function_end_vs=
      test_analysis[test_function_end].value_set;

    reference_typet jlo_ref_type=java_lang_object_type();

    WHEN("Overwriting a local variable")
    {
      symbol_exprt written_symbol(
        TEST_LOCAL_PREFIX "7::weak_local", jlo_ref_type);
      THEN("The normal analysis should perform a hard write")
      {
        auto normal_exprs=
          get_values(normal_function_end_vs, ns, written_symbol);
        REQUIRE(normal_exprs.size()==1);
      }

      THEN("The custom analysis should perform a soft write")
      {
        auto test_exprs=
          get_values(test_function_end_vs, ns, written_symbol);
        // The three values being maybe-unitialised,
        // maybe-assigned first time and
        // maybe-assigned second time (lines 12 and 15 of CustomVSATest.java)
        REQUIRE(test_exprs.size()==3);
      }
    }

    WHEN("Writing to a local named 'ignored'")
    {
      symbol_exprt written_symbol(
        TEST_LOCAL_PREFIX "23::ignored", jlo_ref_type);
      THEN("The normal analysis should write to it")
      {
        auto normal_exprs=
          get_values(normal_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(normal_exprs, ID_dynamic_object)==1);
        REQUIRE(exprs_with_id(normal_exprs, ID_unknown)==0);
      }
      THEN("The custom analysis should ignore the write to it")
      {
        auto test_exprs=
          get_values(test_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(test_exprs, ID_dynamic_object)==0);
        REQUIRE(exprs_with_id(test_exprs, ID_unknown)==1);
      }
    }

    WHEN("Writing to a local named 'no_write'")
    {
      symbol_exprt written_symbol(
        TEST_LOCAL_PREFIX "31::no_write", jlo_ref_type);
      THEN("The normal analysis should write to it")
      {
        auto normal_exprs=
          get_values(normal_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(normal_exprs, ID_dynamic_object)==1);
        REQUIRE(exprs_with_id(normal_exprs, ID_unknown)==0);
      }
      THEN("The custom analysis should ignore the write to it")
      {
        auto test_exprs=
          get_values(test_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(test_exprs, ID_dynamic_object)==0);
        REQUIRE(exprs_with_id(test_exprs, ID_unknown)==1);
      }
    }

    WHEN("Reading from a field named 'never_read'")
    {
      symbol_exprt written_symbol(
        TEST_LOCAL_PREFIX "55::read", jlo_ref_type);
      THEN("The normal analysis should find a dynamic object")
      {
        auto normal_exprs=
          get_values(normal_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(normal_exprs, ID_dynamic_object)==1);
        REQUIRE(exprs_with_id(normal_exprs, ID_unknown)==0);
      }
      THEN("The custom analysis should have no information about it")
      {
        auto test_exprs=
          get_values(test_function_end_vs, ns, written_symbol);
        REQUIRE(test_exprs.size()==0);
      }
    }

    WHEN("Reading from a variable named 'maybe_unknown'")
    {
      symbol_exprt written_symbol(
        TEST_LOCAL_PREFIX "64::maybe_unknown", jlo_ref_type);
      THEN("The normal analysis should find a dynamic object")
      {
        auto normal_exprs=
          get_values(normal_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(normal_exprs, ID_dynamic_object)==1);
        REQUIRE(exprs_with_id(normal_exprs, ID_unknown)==0);
      }
      THEN("The custom analysis should find a dynamic object "
           "*and* an unknown entry")
      {
        auto test_exprs=
          get_values(test_function_end_vs, ns, written_symbol);
        REQUIRE(test_exprs.size()==2);
        REQUIRE(exprs_with_id(test_exprs, ID_unknown)==1);
        REQUIRE(exprs_with_id(test_exprs, ID_dynamic_object)==1);
      }
    }

    WHEN("Reading through a field named 'unknown_field_ref'")
    {
      symbol_exprt written_symbol(
        TEST_LOCAL_PREFIX "110::get_unknown_field", jlo_ref_type);
      THEN("The normal analysis should find a dynamic object")
      {
        auto normal_exprs=
          get_values(normal_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(normal_exprs, ID_dynamic_object)==1);
        REQUIRE(exprs_with_id(normal_exprs, ID_unknown)==0);
      }
      THEN("The custom analysis should find a dynamic object "
           "*and* an unknown entry")
      {
        auto test_exprs=
          get_values(test_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(test_exprs, ID_unknown)==1);
        REQUIRE(exprs_with_id(test_exprs, ID_dynamic_object)==1);
      }
    }

    WHEN("Reading through a global named 'unknown_global_ref'")
    {
      symbol_exprt written_symbol(
        TEST_LOCAL_PREFIX "141::get_unknown_global", jlo_ref_type);
      THEN("The normal analysis should find a dynamic object")
      {
        auto normal_exprs=
          get_values(normal_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(normal_exprs, ID_dynamic_object)==1);
        REQUIRE(exprs_with_id(normal_exprs, ID_unknown)==0);
      }
      THEN("The custom analysis should find a dynamic object "
           "*and* an unknown entry")
      {
        auto test_exprs=
          get_values(test_function_end_vs, ns, written_symbol);
        REQUIRE(exprs_with_id(test_exprs, ID_unknown)==1);
        REQUIRE(exprs_with_id(test_exprs, ID_dynamic_object)==1);
      }
    }
  }
}
