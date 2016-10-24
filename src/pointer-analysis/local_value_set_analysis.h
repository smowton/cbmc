#ifndef LOCAL_VALUE_SET_ANALYSIS_H
#define LOCAL_VALUE_SET_ANALYSIS_H

#include "value_set_analysis.h"
#include "external_value_set_expr.h"
#include <summaries/summary.h>
#include <util/message.h>

class lvsaa_single_external_set_summaryt : public json_serialisable_summaryt {
 public:
  std::string kind() const noexcept { return "lvsaa"; }

  struct fieldname {
    std::string basename;
    std::string fieldname;
  };
  std::vector<std::pair<fieldname, exprt> > field_assignments;

  void from_json(const json_objectt&);
  json_objectt to_json() const;
  void from_final_state(const value_sett& state, const namespacet&, bool export_return_value);
};

// Value-set analysis extended to use free variables labelled with access paths
// to talk about external entities, rather than simply declare them unknown.

class local_value_set_analysist : public value_set_analysist, public messaget {

 public:

  typedef summary_json_databaset<lvsaa_single_external_set_summaryt> dbt;
  
 local_value_set_analysist(const namespacet& ns,
                           const code_typet& ftype,
                           const std::string& fname,
                           dbt& summarydb,
                           local_value_set_analysis_modet m) :
  value_set_analysist(ns),
    function_type(ftype),
    function_name(fname),
    mode(m),
    summarydb(summarydb)
    { }

  virtual void initialize(const goto_programt &goto_program);

  // Use summaries for all function calls (TODO: recursion and mutual recursion)
  virtual bool should_enter_function(const irep_idt& f) { return false; }

  void transform_function_stub_single_external_set(
    const irep_idt& fname, statet& state, locationt l_call, locationt l_return);
  virtual void transform_function_stub(
    const irep_idt& fname, statet& state, locationt l_call, locationt l_return);

  void load_summaries();
  void save_summary(const goto_programt&);

 protected:

  const code_typet& function_type;
  const std::string function_name;
  const local_value_set_analysis_modet mode;
  summary_json_databaset<lvsaa_single_external_set_summaryt>& summarydb;

  virtual bool get_ignore_recursion() { return false; }

};

#endif
