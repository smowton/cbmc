#ifndef LOCAL_VALUE_SET_ANALYSIS_H
#define LOCAL_VALUE_SET_ANALYSIS_H

#include "value_set_analysis.h"

// Value-set analysis extended to use free variables labelled with access paths
// to talk about external entities, rather than simply declare them unknown.

class local_value_set_analysist : public value_set_analysist {

 public:
  
 local_value_set_analysist(const namespacet& ns, const code_typet& ftype, local_value_set_analysis_modet m) :
  value_set_analysist(ns),
    function_type(ftype),
    mode(m) {}

  virtual void initialize(const goto_programt &goto_program);

 protected:

  const code_typet& function_type;
  const local_value_set_analysis_modet mode;

};

#endif
