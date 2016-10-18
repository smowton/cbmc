#ifndef LOCAL_VALUE_SET_ANALYSIS_H
#define LOCAL_VALUE_SET_ANALYSIS_H

#include "value_set_analysis.h"
#include <summaries/summary.h>

class lvsaa_summaryt : summaryt {
 public:
 lvsaa_summaryt(const value_set_analysist::statet& state) : final_state(state) { }
  std::string kind() const noexcept { return "lvsaa"; }

  value_set_analysist::statet final_state;
};

// Value-set analysis extended to use free variables labelled with access paths
// to talk about external entities, rather than simply declare them unknown.

class local_value_set_analysist : public value_set_analysist {

 public:
  
 local_value_set_analysist(const namespacet& ns,
                           const code_typet& ftype,
                           const std::string& fname,
                           const std::string& dbname,
                           local_value_set_analysis_modet m) :
  value_set_analysist(ns),
    function_type(ftype),
    function_name(fname),
    database_dirname(dbname),
    mode(m) {}

  virtual void initialize(const goto_programt &goto_program);

  // Use summaries for all function calls (TODO: recursion and mutual recursion)
  virtual bool should_enter_function(const irep_idt& f) { return false; }

  void transform_function_stub_single_external_set(
    statet& state, locationt l_call, locationt l_return);
  virtual void transform_function_stub(
    statet& state, locationt l_call, locationt l_return);

  void save_summary(const goto_programt&);

 protected:

  const code_typet& function_type;
  const std::string function_name;
  const std::string database_dirname;
  const local_value_set_analysis_modet mode;

};

#endif
