/*******************************************************************\

Module: Range-based reaching definitions analysis (following Field-
        Sensitive Program Dependence Analysis, Litvak et al., FSE 2010),
        local version

Author: Michael Tautschnig, Anna Trostanetski

\*******************************************************************/

#ifndef CPROVER_LOCAL_REACHING_DEFINITIONS_H
#define CPROVER_LOCAL_REACHING_DEFINITIONS_H

#include "local_ai.h"
#include "goto_rw.h"
#include "reaching_definitions.h"

class value_setst;
class is_threadedt;
class dirtyt;
class local_reaching_definitions_analysist;


class local_rd_range_summaryt:public local_ai_summary_baset
{
public:
  local_rd_range_summaryt()
  {
  }

  ~local_rd_range_summaryt()
  {
  }

  typedef std::vector<std::size_t> values_innert;
//  typedef hash_set_cont<std::size_t> values_innert;
  #ifdef USE_DSTRING
  typedef std::map<irep_idt, values_innert> valuest;
//  typedef hash_map_cont<irep_idt, values_innert, irep_id_hash> valuest;
  #else
  typedef hash_map_cont<irep_idt, values_innert, irep_id_hash> valuest;
  #endif
  valuest values;
};

class local_rd_range_domaint:public local_ai_domain_baset
{
public:
  local_rd_range_domaint():
    local_ai_domain_baset(),
    bv_container(0)
  {
  }

  inline void set_bitvector_container(
    sparse_bitvector_analysist<reaching_definitiont> &_bv_container)
  {
    bv_container=&_bv_container;
  }

  virtual void transform(
      locationt from,
      locationt to,
      local_ai_baset &ai,
      const namespacet &ns);

  virtual local_rd_range_summaryt get_summary(
      locationt end_loc,
      local_ai_baset &ai,
      const namespacet &ns);

  virtual void transform(
      locationt call_loc,
      summaryt &summary,
      local_ai_baset &ai,
      const namespacet &ns);

  virtual void output(
      std::ostream &out,
      const local_ai_baset &ai,
      const namespacet &ns) const
  {
    output(out);
  }

  // returns true iff there is s.th. new
  bool merge(
    const local_rd_range_domaint &other,
    locationt from,
    locationt to);
  bool merge_shared(
    const local_rd_range_domaint &other,
    locationt from,
    locationt to,
    const namespacet &ns);

  // each element x represents a range of bits [x.first, x.second)
  typedef std::multimap<range_spect, range_spect> rangest;
  typedef std::map<locationt, rangest> ranges_at_loct;

  const ranges_at_loct& get(const irep_idt &identifier) const;
  inline const void clear_cache(const irep_idt &identifier) const
  {
    export_cache[identifier].clear();
  }

protected:
  sparse_bitvector_analysist<reaching_definitiont> *bv_container;

  typedef std::vector<std::size_t> values_innert;
//  typedef hash_set_cont<std::size_t> values_innert;
  #ifdef USE_DSTRING
  typedef std::map<irep_idt, values_innert> valuest;
//  typedef hash_map_cont<irep_idt, values_innert, irep_id_hash> valuest;
  #else
  typedef hash_map_cont<irep_idt, values_innert, irep_id_hash> valuest;
  #endif
  valuest values;

  #ifdef USE_DSTRING
  typedef std::map<irep_idt, ranges_at_loct> export_cachet;
//  typedef hash_map_cont<irep_idt, ranges_at_loct, irep_id_hash>
//    export_cachet;
  #else
  typedef hash_map_cont<irep_idt, ranges_at_loct, irep_id_hash>
    export_cachet;
  #endif
  mutable export_cachet export_cache;

  void populate_cache(const irep_idt &identifier) const;

  void transform_dead(
    const namespacet &ns,
    locationt from);
  void transform_start_thread(
    const namespacet &ns,
    local_reaching_definitions_analysist &rd);
  void transform_function_call(
    const namespacet &ns,
    locationt from,
    locationt to,
    local_reaching_definitions_analysist &rd);
  void transform_assign(
    const namespacet &ns,
    locationt from,
    locationt to,
    local_reaching_definitions_analysist &rd);

   void kill(
    const irep_idt &identifier,
    const range_spect &range_start,
    const range_spect &range_end);
  void kill_inf(
    const irep_idt &identifier,
    const range_spect &range_start);
  bool gen(
    locationt from,
    const irep_idt &identifier,
    const range_spect &range_start,
    const range_spect &range_end);

  void output(std::ostream &out) const;

  bool merge_inner(
    values_innert &dest,
    const values_innert &other);
};


class local_reaching_definitions_analysist :
  public local_ait<local_rd_range_domaint, local_rd_range_summaryt>,
  public sparse_bitvector_analysist<reaching_definitiont>
{
public:
  // constructor
  explicit local_reaching_definitions_analysist(const namespacet &_ns):
  local_ait<local_rd_range_domaint, local_rd_range_summaryt>(),
    ns(_ns),
    value_sets(0),
    is_threaded(0),
    is_dirty(0)
  {
  }

  virtual ~local_reaching_definitions_analysist();

  virtual void initialize(
    const goto_functionst &goto_functions);

  virtual statet &get_state(goto_programt::const_targett l)
  {
    statet &s=local_ait<local_rd_range_domaint, local_rd_range_summaryt>::get_state(l);

    local_rd_range_domaint *rd_state=dynamic_cast<local_rd_range_domaint*>(&s);
    assert(rd_state!=0);

    rd_state->set_bitvector_container(*this);

    return s;
  }

  value_setst &get_value_sets() const
  {
    assert(value_sets);
    return *value_sets;
  }

  const is_threadedt &get_is_threaded() const
  {
    assert(is_threaded);
    return *is_threaded;
  }

  const dirtyt &get_is_dirty() const
  {
    assert(is_dirty);
    return *is_dirty;
  }

protected:
  const namespacet &ns;
  value_setst * value_sets;
  is_threadedt * is_threaded;
  dirtyt * is_dirty;
};

#endif

