/*******************************************************************

 Module: Counterexample-Guided Inductive Synthesis

 Author: Daniel Kroening, kroening@kroening.com
         Pascal Kesseli, pascal.kesseil@cs.ox.ac.uk

\*******************************************************************/

#ifndef JAVA_TEST_CASE_GENERATOR_H_
#define JAVA_TEST_CASE_GENERATOR_H_

#include <string>
#include <functional>
#include <cbmc/bmc.h>
#include <util/options.h>

#include <test_gen/java_test_source_factory.h>

#include <util/options.h>

typedef std::function<
  std::string(const symbol_tablet &, const irep_idt &, bool, const inputst &,
              const interpretert::list_input_varst&,
              const interpretert::input_var_functionst&,
              const interpretert::dynamic_typest&,
              const std::string &,
              const std::string &,
              bool,
              bool,
              const optionst::value_listt&,
              const optionst::value_listt&,              
              const std::vector<std::string>&)> test_case_generatort;

class java_test_case_generatort:public messaget
{
 public:
 java_test_case_generatort(message_handlert &_message_handler):
  messaget(_message_handler)
  {
  }

  typedef enum { SUCCESS, FAIL, ERROR } test_case_statust;
  const std::string generate_test_func_name(const symbol_tablet &st,
                                            const goto_functionst &gf,
                                            const size_t test_idx);

  /**
   * @brief
   *
   * @details
   *
   * @param options
   * @param st
   * @param gf
   * @param bmc
   *
   * @return
   */
  test_case_statust generate_java_test_case(class optionst &options,
                              const class symbol_tablet &st,
                              const class goto_functionst &gf,
                              class bmct &bmc);

  /**
   * @brief
   *
   * @details
   *
   * @param options
   * @param st
   * @param gf
   * @param trace
   * @param name
   */
  const std::string generate_java_test_case(const optionst &options,
                                            const symbol_tablet &st,
                                            const goto_functionst &gf,
                                            const class goto_tracet &trace,
                                            const size_t test_idx,
                                            const std::vector<std::string> &goals);

private:
  const std::string generate_test_case(const optionst &, const symbol_tablet &,
                                       const goto_functionst &, const goto_tracet &,
                                       const test_case_generatort, size_t=0,
                                       std::vector<std::string> goals_reached=std::vector<std::string>());
  test_case_statust generate_test_case(optionst &, const symbol_tablet &,
                         const goto_functionst &, bmct &, const test_case_generatort);

  bool contains(const std::string &, const char * const);
  bool is_meta(const irep_idt &);
  inputst generate_inputs(const symbol_tablet &, const goto_functionst &,
                          const goto_tracet &, interpretert::list_input_varst&,
                          interpretert::input_var_functionst&,
                          interpretert::dynamic_typest&,
                          const optionst&,
                          interpretert::side_effects_differencet &);
  const irep_idt &get_entry_function_id(const goto_functionst &gf);
  const std::string get_test_function_name(const symbol_tablet &st, const goto_functionst &gf, size_t test_idx);
};
#endif /* JAVA_TEST_CASE_GENERATOR_H_ */
