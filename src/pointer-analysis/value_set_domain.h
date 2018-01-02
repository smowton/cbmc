/*******************************************************************\

Module: Value Set

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

/// \file
/// Value Set

#ifndef CPROVER_POINTER_ANALYSIS_VALUE_SET_DOMAIN_H
#define CPROVER_POINTER_ANALYSIS_VALUE_SET_DOMAIN_H

#define USE_DEPRECATED_STATIC_ANALYSIS_H
#include <analyses/static_analysis.h>

#include "value_set.h"

template<class VST>
class value_set_domain_templatet:public domain_baset
{
public:
  VST value_set;

  // overloading

  bool merge(const value_set_domain_templatet<VST> &other, locationt to)
  {
    return value_set.make_union(other.value_set);
  }

  void output(
    const namespacet &ns,
    std::ostream &out) const override
  {
    value_set.output(ns, out);
  }

  jsont output_json(const namespacet &ns) const override
  {
    return value_set.output_json(ns);
  }

  void initialize(
    const namespacet &ns,
    locationt l) override
  {
    value_set.clear();
    value_set.location_number=l->location_number;
    value_set.function=l->function;
  }

  void transform(
    const namespacet &ns,
    locationt from_l,
    locationt to_l) override;

  void get_reference_set(
    const namespacet &ns,
    const exprt &expr,
    value_setst::valuest &dest) override
  {
    value_set.get_reference_set(expr, dest, ns);
  }
};

typedef value_set_domain_templatet<value_sett> value_set_domaint;

#include "value_set_domain_transform.inc"

#endif // CPROVER_POINTER_ANALYSIS_VALUE_SET_DOMAIN_H
