/*******************************************************************\

Module: Range-based reaching definitions analysis (following Field-
        Sensitive Program Dependence Analysis, Litvak et al., FSE 2010),
        local version

Author: Michael Tautschnig, Anna Trostanetski

\*******************************************************************/

#include <util/pointer_offset_size.h>
#include <util/prefix.h>

#include <pointer-analysis/value_set_analysis_fi.h>

#include "is_threaded.h"
#include "dirty.h"

#include "local_reaching_definitions.h"
#include <algorithm>


/*******************************************************************\

Function: local_rd_range_domaint::populate_cache

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_rd_range_domaint::populate_cache(const irep_idt &identifier) const
{
  assert(bv_container);

  valuest::const_iterator v_entry=values.find(identifier);
  if(v_entry==values.end() ||
     v_entry->second.empty())
    return;

  ranges_at_loct &export_entry=export_cache[identifier];

  for(values_innert::const_iterator
      it=v_entry->second.begin();
      it!=v_entry->second.end();
      ++it)
  {
    const reaching_definitiont &v=bv_container->get(*it);

    export_entry[v.definition_at].insert(
      std::make_pair(v.bit_begin, v.bit_end));
  }
}

/*******************************************************************\

Function: local_rd_range_domaint::transform

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_rd_range_domaint::transform(
  locationt from,
  locationt to,
  local_ai_baset &ai,
  const namespacet &ns)
{
  local_reaching_definitions_analysist *rd=
    dynamic_cast<local_reaching_definitions_analysist*>(&ai);
  assert(rd!=0);

  assert(bv_container);

  // kill values
  if(from->is_dead())
    transform_dead(ns, from);
  // kill thread-local values
  else if(from->is_start_thread())
    transform_start_thread(ns, *rd);
  // do argument-to-parameter assignments
  else if(from->is_function_call())
    transform_function_call(ns, from, to, *rd);
  // cleanup parameters
  else if(from->is_end_function())
    assert(false);
  // lhs assignements
  else if(from->is_assign())
    transform_assign(ns, from, from, *rd);
  // initial (non-deterministic) value
  else if(from->is_decl())
    transform_assign(ns, from, from, *rd);

#if 0
  // handle return values
  if(to->is_function_call())
  {
    const code_function_callt &code=to_code_function_call(to->code);

    if(code.lhs().is_not_nil())
    {
      rw_range_set_value_sett rw_set(ns, rd->get_value_sets());
      goto_rw(to, rw_set);
      const bool is_must_alias=rw_set.get_w_set().size()==1;

      forall_rw_range_set_w_objects(it, rw_set)
      {
        const irep_idt &identifier=it->first;
        // ignore symex::invalid_object
        const symbolt *symbol_ptr;
        if(ns.lookup(identifier, symbol_ptr))
          continue;
        assert(symbol_ptr!=0);

        const range_domaint &ranges=rw_set.get_ranges(it);

        if(is_must_alias &&
           (!rd->get_is_threaded()(from) ||
            (!symbol_ptr->is_shared() &&
             !rd->get_is_dirty()(identifier))))
          for(range_domaint::const_iterator
              r_it=ranges.begin();
              r_it!=ranges.end();
              ++r_it)
            kill(identifier, r_it->first, r_it->second);
      }
    }
  }
#endif
}

/*******************************************************************\

Function: local_rd_range_domaint::transform_dead

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_rd_range_domaint::transform_dead(
  const namespacet &ns,
  locationt from)
{
  const irep_idt& identifier=
    to_symbol_expr(to_code_dead(from->code).symbol()).get_identifier();

  valuest::iterator entry=values.find(identifier);

  if(entry!=values.end())
  {
    values.erase(entry);
    export_cache.erase(identifier);
  }
}

/*******************************************************************\

Function: local_rd_range_domaint::transform_start_thread

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_rd_range_domaint::transform_start_thread(
  const namespacet &ns,
  local_reaching_definitions_analysist &rd)
{
  for(valuest::iterator it=values.begin();
      it!=values.end();
      ) // no ++it
  {
    const irep_idt &identifier=it->first;

    if(!ns.lookup(identifier).is_shared() &&
       !rd.get_is_dirty()(identifier))
    {
      export_cache.erase(identifier);

      valuest::iterator next=it;
      ++next;
      values.erase(it);
      it=next;
    }
    else
      ++it;
  }
}

/*******************************************************************\

Function: local_rd_range_domaint::transform_function_call

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_rd_range_domaint::transform_function_call(
  const namespacet &ns,
  locationt from,
  locationt to,
  local_reaching_definitions_analysist &rd)
{
  const code_function_callt &code=to_code_function_call(from->code);

  goto_programt::const_targett next=from;
  ++next;

  // only if there is an actual call, i.e., we have a body
  if(next!=to)
  {
    export_cache.clear();
    values.clear();
  }
  else
  {
    // handle return values of undefined functions
    const code_function_callt &code=to_code_function_call(from->code);

    if(code.lhs().is_not_nil())
      transform_assign(ns, from, from, rd);
  }
}

/*******************************************************************\

Function: local_rd_range_domaint::transform

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

//transform for end function
void local_rd_range_domaint::transform(
      locationt call,
      local_rd_range_domaint::summaryt &summary,
      local_ai_baset &ai,
      const namespacet &ns)
{
  local_reaching_definitions_analysist *rdp=
    dynamic_cast<local_reaching_definitions_analysist*>(&ai);
  assert(rdp!=0);

  local_reaching_definitions_analysist& rd=*rdp;

  local_rd_range_summaryt *rd_summary=
      dynamic_cast<local_rd_range_summaryt*>(&summary);
  assert(rd_summary!=0);

  const code_function_callt &code=to_code_function_call(call->code);

  valuest new_values = rd_summary->values;
  values=rd[call].values;

  for(valuest::const_iterator
      it=new_values.begin();
      it!=new_values.end();
      ++it)
  {
    const irep_idt &identifier=it->first;

    if(!rd.get_is_threaded()(call) ||
       (!ns.lookup(identifier).is_shared() &&
        !rd.get_is_dirty()(identifier)))
      for(values_innert::const_iterator
          i_it=it->second.begin();
          i_it!=it->second.end();
          ++i_it)
      {
        const reaching_definitiont &v=bv_container->get(*i_it);
        kill(v.identifier, v.bit_begin, v.bit_end);
      }

    const symbolt *sym;
    if(!ns.lookup(identifier, sym) && !sym->is_procedure_local())
    {
      for(values_innert::const_iterator i_it=it->second.begin();
          i_it!=it->second.end(); ++i_it)
      {
        const reaching_definitiont &v=bv_container->get(*i_it);
        gen(call, v.identifier, v.bit_begin, v.bit_end);
      }
    }
  }
}

local_rd_range_summaryt local_rd_range_domaint::get_summary(
      locationt end_loc,
      local_ai_baset &ai,
      const namespacet &ns)
{
  local_rd_range_summaryt sum;
  sum.values=values;
  return sum;
}
/*******************************************************************\

Function: local_rd_range_domaint::transform_assign

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_rd_range_domaint::transform_assign(
  const namespacet &ns,
  locationt from,
  locationt to,
  local_reaching_definitions_analysist &rd)
{
  rw_range_set_value_sett rw_set(ns, rd.get_value_sets());
  goto_rw(to, rw_set);
  const bool is_must_alias=rw_set.get_w_set().size()==1;

  forall_rw_range_set_w_objects(it, rw_set)
  {
    const irep_idt &identifier=it->first;
    // ignore symex::invalid_object
    const symbolt *symbol_ptr;
    if(ns.lookup(identifier, symbol_ptr))
      continue;
    assert(symbol_ptr!=0);

    const range_domaint &ranges=rw_set.get_ranges(it);

    if(is_must_alias &&
       (!rd.get_is_threaded()(from) ||
        (!symbol_ptr->is_shared() &&
         !rd.get_is_dirty()(identifier))))
      for(range_domaint::const_iterator
          r_it=ranges.begin();
          r_it!=ranges.end();
          ++r_it)
        kill(identifier, r_it->first, r_it->second);

    for(range_domaint::const_iterator
        r_it=ranges.begin();
        r_it!=ranges.end();
        ++r_it)
      gen(from, identifier, r_it->first, r_it->second);
  }
}

/*******************************************************************\

Function: local_rd_range_domaint::kill

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_rd_range_domaint::kill(
  const irep_idt &identifier,
  const range_spect &range_start,
  const range_spect &range_end)
{
  assert(range_start>=0);
  // -1 for objects of infinite/unknown size
  if(range_end==-1)
  {
    kill_inf(identifier, range_start);
    return;
  }

  assert(range_end>range_start);

  valuest::iterator entry=values.find(identifier);
  if(entry==values.end())
    return;

  bool clear_export_cache=false;
  values_innert new_values;

  for(values_innert::iterator
      it=entry->second.begin();
      it!=entry->second.end();
     ) // no ++it
  {
    const reaching_definitiont &v=bv_container->get(*it);

    if(v.bit_begin>=range_end)
    {
      ++it;
    }
    else if(v.bit_end!=-1&&v.bit_end<=range_start)
    {
      ++it;
    }
    else if(v.bit_begin >= range_start &&
            v.bit_end!=-1 &&
            v.bit_end <= range_end) // rs <= a < b <= re
    {
      clear_export_cache=true;

      entry->second.erase(it);
    }
    else if(v.bit_begin >= range_start) // rs <= a <= re < b
    {
      clear_export_cache=true;

      reaching_definitiont v_new=v;
      v_new.bit_begin=range_end;
      new_values.push_back(bv_container->add(v_new));

      entry->second.erase(it);
    }
    else if(v.bit_end==-1 ||
            v.bit_end > range_end) // a <= rs < re < b
    {
      clear_export_cache=true;

      reaching_definitiont v_new=v;
      v_new.bit_end=range_start;

      reaching_definitiont v_new2=v;
      v_new2.bit_begin=range_end;

      new_values.push_back(bv_container->add(v_new));
      new_values.push_back(bv_container->add(v_new2));

      entry->second.erase(it);
    }
    else // a <= rs < b <= re
    {
      clear_export_cache=true;

      reaching_definitiont v_new=v;
      v_new.bit_end=range_start;
      new_values.push_back(bv_container->add(v_new));

      entry->second.erase(it);
    }
  }

  if(clear_export_cache)
    export_cache.erase(identifier);

  values_innert::iterator it=entry->second.begin();
  for(values_innert::const_iterator
      itn=new_values.begin();
      itn!=new_values.end();
      ++itn)
  {
    while(it!=entry->second.end() && *it<*itn)
      ++it;
    if(it==entry->second.end() || *itn<*it)
    {
      entry->second.insert(it, *itn);
    }
    else if(it!=entry->second.end())
    {
      assert(*it==*itn);
      ++it;
    }
  }
}

/*******************************************************************\

Function: local_rd_range_domaint::kill_inf

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_rd_range_domaint::kill_inf(
  const irep_idt &identifier,
  const range_spect &range_start)
{
  assert(range_start>=0);

#if 0
  valuest::iterator entry=values.find(identifier);
  if(entry==values.end())
    return;

  XXX export_cache_available=false;

  // makes the analysis underapproximating
  rangest &ranges=entry->second;

  for(rangest::iterator it=ranges.begin();
      it!=ranges.end();
     ) // no ++it
    if(it->second.first!=-1 &&
       it->second.first <= range_start)
      ++it;
    else if(it->first >= range_start) // rs <= a < b <= re
    {
      ranges.erase(it++);
    }
    else // a <= rs < b < re
    {
      it->second.first=range_start;
      ++it;
    }
#endif
}

/*******************************************************************\

Function: local_rd_range_domaint::gen

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool local_rd_range_domaint::gen(
  locationt from,
  const irep_idt &identifier,
  const range_spect &range_start,
  const range_spect &range_end)
{
  // objects of size 0 like union U { signed : 0; };
  if(range_start==0 && range_end==0)
    return false;

  assert(range_start>=0);

  // -1 for objects of infinite/unknown size
  assert(range_end>range_start || range_end==-1);

  reaching_definitiont v;
  v.identifier=identifier;
  v.definition_at=from;
  v.bit_begin=range_start;
  v.bit_end=range_end;

  std::size_t loc=bv_container->add(v);
  values_innert &entry=values[identifier];
  if(std::find(entry.begin(),entry.end(),loc)!= entry.end())
    return false;

  entry.push_back(loc);
  export_cache.erase(identifier);

#if 0
  range_spect merged_range_end=range_end;

  std::pair<valuest::iterator, bool> entry=
    values.insert(std::make_pair(identifier, rangest()));
  rangest &ranges=entry.first->second;

  if(!entry.second)
  {
    for(rangest::iterator it=ranges.begin();
        it!=ranges.end();
        ) // no ++it
    {
      if(it->second.second!=from ||
         (it->second.first!=-1 && it->second.first <= range_start) ||
         (range_end!=-1 && it->first >= range_end))
        ++it;
      else if(it->first > range_start) // rs < a < b,re
      {
        if(range_end!=-1)
          merged_range_end=std::max(range_end, it->second.first);
        ranges.erase(it++);
      }
      else if(it->second.first==-1 ||
              (range_end!=-1 &&
               it->second.first >= range_end)) // a <= rs < re <= b
      {
        // nothing to do
        return false;
      }
      else // a <= rs < b < re
      {
        it->second.first=range_end;
        return true;
      }
    }
  }

  ranges.insert(std::make_pair(
      range_start,
      std::make_pair(merged_range_end, from)));
#endif

  return true;
}

/*******************************************************************\

Function: local_rd_range_domaint::output

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_rd_range_domaint::output(std::ostream &out) const
{
  out << "Reaching definitions:" << std::endl;
  for(valuest::const_iterator
      it=values.begin();
      it!=values.end();
      ++it)
  {
    const irep_idt &identifier=it->first;

    const ranges_at_loct &ranges=get(identifier);

    out << "  " << identifier << "[";

    for(ranges_at_loct::const_iterator itl=ranges.begin();
        itl!=ranges.end();
        ++itl)
      for(rangest::const_iterator itr=itl->second.begin();
          itr!=itl->second.end();
          ++itr)
      {
        if(itr!=itl->second.begin() ||
           itl!=ranges.begin())
          out << ";";

        out << itr->first << ":" << itr->second;
        out << "@" << itl->first->location_number;
      }

    out << "]" << std::endl;

    clear_cache(identifier);
  }
}

/*******************************************************************\

Function: local_rd_range_domaint::merge_inner

  Inputs:

 Outputs: returns true iff there is s.th. new

 Purpose:

\*******************************************************************/

bool local_rd_range_domaint::merge_inner(
  values_innert &dest,
  const values_innert &other)
{
  bool more=false;

#if 0
  ranges_at_loct::iterator itr=it->second.begin();
  for(ranges_at_loct::const_iterator itro=ito->second.begin();
      itro!=ito->second.end();
      ++itro)
  {
    while(itr!=it->second.end() && itr->first<itro->first)
      ++itr;
    if(itr==it->second.end() || itro->first<itr->first)
    {
      it->second.insert(*itro);
      more=true;
    }
    else if(itr!=it->second.end())
    {
      assert(itr->first==itro->first);

      for(rangest::const_iterator itrro=itro->second.begin();
          itrro!=itro->second.end();
          ++itrro)
        more=gen(itr->second, itrro->first, itrro->second) ||
          more;

      ++itr;
    }
  }
#else
  values_innert::iterator itr=dest.begin();
  for(values_innert::const_iterator
      itro=other.begin();
      itro!=other.end();
      ++itro)
  {
    while(itr!=dest.end() && *itr<*itro)
      ++itr;
    if(itr==dest.end() || *itro<*itr)
    {
      dest.insert(itr, *itro);
      more=true;
    }
    else if(itr!=dest.end())
    {
      assert(*itr==*itro);
      ++itr;
    }
  }
#endif

  return more;
}

/*******************************************************************\

Function: local_rd_range_domaint::merge

  Inputs:

 Outputs: returns true iff there is s.th. new

 Purpose:

\*******************************************************************/

bool local_rd_range_domaint::merge(
  const local_rd_range_domaint &other,
  locationt from,
  locationt to)
{
  bool more=false;

  valuest::iterator it=values.begin();
  for(valuest::const_iterator ito=other.values.begin();
      ito!=other.values.end();
      ++ito)
  {
    while(it!=values.end() && it->first<ito->first)
      ++it;
    if(it==values.end() || ito->first<it->first)
    {
      values.insert(*ito);
      more=true;
    }
    else if(it!=values.end())
    {
      assert(it->first==ito->first);

      if(merge_inner(it->second, ito->second))
      {
        more=true;
        export_cache.erase(it->first);
      }

      ++it;
    }
  }

  return more;
}

/*******************************************************************\

Function: local_rd_range_domaint::merge_shared

  Inputs:

 Outputs: returns true iff there is s.th. new

 Purpose:

\*******************************************************************/

bool local_rd_range_domaint::merge_shared(
  const local_rd_range_domaint &other,
  goto_programt::const_targett from,
  goto_programt::const_targett to,
  const namespacet &ns)
{
  // TODO: dirty vars
#if 0
  local_reaching_definitions_analysist *rd=
    dynamic_cast<local_reaching_definitions_analysist*>(&ai);
  assert(rd!=0);
#endif

  bool more=false;

  valuest::iterator it=values.begin();
  for(valuest::const_iterator ito=other.values.begin();
      ito!=other.values.end();
      ++ito)
  {
    const irep_idt &identifier=ito->first;

    if(!ns.lookup(identifier).is_shared() /*&&
       !rd.get_is_dirty()(identifier)*/)
      continue;

    while(it!=values.end() && it->first<ito->first)
      ++it;
    if(it==values.end() || ito->first<it->first)
    {
      values.insert(*ito);
      more=true;
    }
    else if(it!=values.end())
    {
      assert(it->first==ito->first);

      if(merge_inner(it->second, ito->second))
      {
        more=true;
        export_cache.erase(it->first);
      }

      ++it;
    }
  }

  return more;
}

/*******************************************************************\

Function: local_rd_range_domaint::get

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

const local_rd_range_domaint::ranges_at_loct& local_rd_range_domaint::get(
  const irep_idt &identifier) const
{
  populate_cache(identifier);

  static ranges_at_loct empty;

  export_cachet::const_iterator entry=export_cache.find(identifier);

  if(entry==export_cache.end())
    return empty;
  else
    return entry->second;
}

/*******************************************************************\

Function: local_reaching_definitions_analysist::~local_reaching_definitions_analysist

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

local_reaching_definitions_analysist::~local_reaching_definitions_analysist()
{
  if(is_dirty) delete is_dirty;
  if(is_threaded) delete is_threaded;
  if(value_sets) delete value_sets;
}

/*******************************************************************\

Function: local_reaching_definitions_analysist::initialize

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void local_reaching_definitions_analysist::initialize(
  const goto_functionst &goto_functions)
{
  value_set_analysis_fit *value_sets_=new value_set_analysis_fit(ns);
  (*value_sets_)(goto_functions);
  value_sets=value_sets_;

  is_threaded=new is_threadedt(goto_functions);
  is_dirty=new dirtyt(goto_functions);
  local_ait<local_rd_range_domaint, local_rd_range_summaryt>::initialize(goto_functions);
}

