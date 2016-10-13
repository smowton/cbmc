#ifndef LOCAL_VALUE_SET_ANALYSIS_H
#define LOCAL_VALUE_SET_ANALYSIS_H

#include "value_set_analysis.h"

// Value-set analysis extended to use free variables labelled with access paths
// to talk about external entities, rather than simply declare them unknown.

class local_value_set_analysist : public value_set_analysist {

 public:
  
 local_value_set_analysist(const namespacet& ns, const code_typet& ftype) :
  value_set_analysist(ns),
    function_type(ftype) {}

  virtual void initialize(const goto_programt &goto_program);

 protected:

  const code_typet& function_type;

};

class external_value_set_exprt : public exprt
{
 public:
  inline external_value_set_exprt():exprt("external-value-set")
  {
    operands().resize(1);
    op0().id(ID_unknown);
  }

  inline explicit external_value_set_exprt(const typet &type, const constant_exprt& label):
    exprt("external-value-set",type)
  {
    operands().push_back(label);
  }

  inline exprt &label() { return op0(); }
  inline const exprt &label() const { return op0(); }
};

#endif
