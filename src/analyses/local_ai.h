/*******************************************************************\

Module: Local Abstract Interpretation (summarizing functions)

Author: Anna Trostanetski

\*******************************************************************/

#ifndef CPROVER_LOCAL_ANALYSES_AI_H
#define CPROVER_LOCAL_ANALYSES_AI_H

#include <map>
#include <iosfwd>
#include <iostream>
#include <goto-programs/goto_model.h>
#include <cassert>
#include <memory>

#include <util/std_expr.h>
#include <util/std_code.h>
#include <util/expr_util.h>

#include <util/time_stopping.h>

#include "is_threaded.h"

// forward reference
class local_ai_baset;


class local_ai_summary_baset
{
public:
  local_ai_summary_baset()
  {
  }
  virtual ~local_ai_summary_baset()
  {
  }
};

// don't use me -- I am just a base class
// please derive from me
class local_ai_domain_baset
{
public:
  typedef local_ai_summary_baset summaryt;
  // The constructor is expected to produce 'false'
  // or 'bottom'
  local_ai_domain_baset()
  {
  }

  virtual ~local_ai_domain_baset()
  {
  }

  typedef goto_programt::const_targett locationt;

  virtual void transform(
    locationt from,
    locationt to,
    local_ai_baset &ai,
    const namespacet &ns)=0;

  virtual void transform(
      locationt call_loc,
      summaryt &summary,
      local_ai_baset &ai,
      const namespacet &ns)=0;

  virtual void output(
    std::ostream &out,
    const local_ai_baset &ai,
    const namespacet &ns) const
  {
  }

  // no states
  virtual void make_bottom()
  {
  }

  // all states
  virtual void make_top()
  {
  }

  // a reasonable entry-point state
  virtual void make_entry()
  {
  }

  // also add
  //
  //   bool merge(const T &b, locationt from, locationt to);
  //
  // This computes the join between "this" and "b".
  // Return true if "this" has changed.
  //
  // and
  //  virtual summaryt get_summary(
  //      locationt end_loc,
  //      local_ai_baset &ai,
  //      const namespacet &ns);
  // This computes a function summary out of the domain of the exit point
};

// don't use me -- I am just a base class
// use ait instead
class local_ai_baset
{
public:
  typedef local_ai_domain_baset statet;
  typedef local_ai_summary_baset summaryt;
  typedef goto_programt::const_targett locationt;

  local_ai_baset()
  {
  }
  
  virtual ~local_ai_baset()
  {
  }

  inline void operator()(
    const goto_programt &goto_program,
    const namespacet &ns)
  {
    goto_functionst goto_functions;
    initialize(goto_program);
    entry_state(goto_program);
    fixedpoint(goto_program, goto_functions, ns);
  }
    
  inline void operator()(
    const goto_functionst &goto_functions,
    const namespacet &ns)
  {
    initialize(goto_functions);
    entry_state(goto_functions);
    fixedpoint(goto_functions, ns);
  }

  inline void operator()(const goto_modelt &goto_model)
  {
    const namespacet ns(goto_model.symbol_table);
    initialize(goto_model.goto_functions);
    entry_state(goto_model.goto_functions);
    fixedpoint(goto_model.goto_functions, ns);
  }

  inline void operator()(
    const goto_functionst::goto_functiont &goto_function,
    const namespacet &ns)
  {
    goto_functionst goto_functions;
    initialize(goto_function);
    entry_state(goto_function.body);
    fixedpoint(goto_function.body, goto_functions, ns);
  }

  virtual void clear()
  {
  }
  
  virtual void output(
    const namespacet &ns,
    const goto_functionst &goto_functions,
    std::ostream &out) const;

  inline void output(
    const goto_modelt &goto_model,
    std::ostream &out) const
  {
    const namespacet ns(goto_model.symbol_table);
    output(ns, goto_model.goto_functions, out);
  }

  inline void output(
    const namespacet &ns,
    const goto_programt &goto_program,
    std::ostream &out) const
  {
    output(ns, goto_program, "", out);
  }

  inline void output(
    const namespacet &ns,
    const goto_functionst::goto_functiont &goto_function,
    std::ostream &out) const
  {
    output(ns, goto_function.body, "", out);
  }

protected:
  // overload to add a factory
  virtual void initialize(const goto_programt &);
  virtual void initialize(const goto_functionst::goto_functiont &);
  virtual void initialize(const goto_functionst &);

  void entry_state(const goto_programt &);
  void entry_state(const goto_functionst &);

  virtual void output(
    const namespacet &ns,
    const goto_programt &goto_program,
    const irep_idt &identifier,
    std::ostream &out) const;

  // the work-queue is sorted by location number
  typedef std::map<unsigned, locationt> working_sett;
  
  locationt get_next(working_sett &working_set);
  
  void put_in_working_set(
    working_sett &working_set,
    locationt l)
  {
    working_set.insert(
      std::pair<unsigned, locationt>(l->location_number, l));
  }
  
  // true = found s.th. new
  bool fixedpoint(
    const goto_programt &goto_program,
    const goto_functionst &goto_functions,
    const namespacet &ns);
    
  virtual void fixedpoint(
    const goto_functionst &goto_functions,
    const namespacet &ns)=0;

  void sequential_fixedpoint(
    const goto_functionst &goto_functions,
    const namespacet &ns);

  // true = found s.th. new
  bool visit(
    locationt l,
    working_sett &working_set,
    const goto_programt &goto_program,
    const goto_functionst &goto_functions,
    const namespacet &ns);
  
  typedef std::set<irep_idt> recursion_sett;
  recursion_sett recursion_set;
    
  // function calls
  bool do_function_call_rec(
    locationt l_call, locationt l_return,
    const exprt &function,
    const exprt::operandst &arguments,
    const goto_functionst &goto_functions,
    const namespacet &ns);

  bool do_function_call(
    locationt l_call, locationt l_return,
    const goto_functionst &goto_functions,
    const goto_functionst::function_mapt::const_iterator f_it,
    const exprt::operandst &arguments,
    const namespacet &ns);

  // abstract methods
    
  virtual bool merge(const statet &src, locationt from, locationt to)=0;
  // for concurrent fixedpoint
  virtual bool merge_shared(
    const statet &src,
    locationt from,
    locationt to,
    const namespacet &ns)=0;
  virtual void remove_function(irep_idt function)=0;
  virtual statet &get_state(locationt l)=0;
  virtual const statet &find_state(locationt l) const=0;
  virtual statet* make_temporary_state(const statet &s)=0;
  virtual bool is_function_analysed(irep_idt function)=0;
  virtual void add_function_summary(irep_idt function, const locationt &l_end, const namespacet &ns)=0;
  virtual summaryt& get_function_summary(irep_idt function)=0;
};

// domainT is expected to be derived from ai_domain_baseT
// summaryT is expected to be derived from ai_summary_baset
template<typename domainT, typename summaryT>
class local_ait:public local_ai_baset
{
public:
  typedef local_ai_summary_baset summaryt;
  // constructor
  local_ait():local_ai_baset()
  {
  }

  virtual ~local_ait() {}

  typedef goto_programt::const_targett locationt;

  inline domainT &operator[](locationt l)
  {
    typename func_states_mapt::iterator f_it=func_states_map.find(l->function);
    if(f_it==func_states_map.end()) throw "failed to find state1";
    typename state_mapt::iterator it=f_it->second.find(l);
    if(it==f_it->second.end()) throw "failed to find state";
    return it->second;
  }
    
  inline const domainT &operator[](locationt l) const
  {
    typename func_states_mapt::const_iterator f_it=func_states_map.find(l->function);
    if(f_it==func_states_map.end()) throw "failed to find state";
    typename state_mapt::const_iterator it=f_it->second.find(l);
    if(it==f_it->second.end()) throw "failed to find state";
    return it->second;
  }

  summaryt& get_function_summary(irep_idt function)
  {
    return function_summaries[function];
  }

  virtual void clear()
  {
    func_states_map.clear();
    local_ai_baset::clear();
  }

protected:
  typedef hash_map_cont<locationt, domainT, const_target_hash> state_mapt;
  typedef hash_map_cont<irep_idt, state_mapt, irep_id_hash> func_states_mapt;
  func_states_mapt func_states_map;

  typedef hash_map_cont<irep_idt, summaryT, irep_id_hash> function_end_statest;
  function_end_statest function_summaries;

  virtual bool is_function_analysed(irep_idt function)
  {
    return function_summaries.find(function)!=function_summaries.end();
  }

  virtual void add_function_summary(irep_idt function, const locationt &l_end,const namespacet &ns)
  {
    function_summaries[function]=func_states_map[function][l_end].get_summary(l_end,*this,ns);
  }

  virtual void remove_function(irep_idt function)
  {
    func_states_map.erase(function);
  }
  // this one creates states, if need be
  virtual statet &get_state(locationt l)
  {
    return func_states_map[l->function][l]; // calls default constructor
  }

  // this one just finds states
  virtual const statet &find_state(locationt l) const
  {
    typename func_states_mapt::const_iterator f_it=func_states_map.find(l->function);
    if(f_it==func_states_map.end()) throw "failed to find state5";
    typename state_mapt::const_iterator it=f_it->second.find(l);
    if(it==f_it->second.end()) throw "failed to find state6";
    return it->second;
  }

  virtual bool merge(const statet &src, locationt from, locationt to)
  {
    statet &dest=get_state(to);
    return static_cast<domainT&>(dest).merge(static_cast<const domainT&>(src), from, to);
  }
  
  virtual statet *make_temporary_state(const statet &s)
  {
    return new domainT(static_cast<const domainT&>(s));
  }

  virtual void fixedpoint(
    const goto_functionst &goto_functions,
    const namespacet &ns)
  {
    sequential_fixedpoint(goto_functions, ns);
  }

private:  
  // to enforce that domainT is derived from ai_domain_baset
  void dummy(const domainT &s) { const statet &x=s; (void)x; }

  // not implemented in sequential analyses
  virtual bool merge_shared(
    const statet &src,
    goto_programt::const_targett from,
    goto_programt::const_targett to,
    const namespacet &ns)
  {
    throw "not implemented";
  }
};

#endif
