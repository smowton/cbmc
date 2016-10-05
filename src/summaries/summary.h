/*******************************************************************\

Module: summary

Author: Marek Trtik

Date: September 2016

This module defines interfaces and functionality for all kinds of summaries.
It in particular comprises loop, function, and module summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_SUMMARIES_SUMMARY_H
#define CPROVER_SUMMARIES_SUMMARY_H

#include <goto-programs/goto_model.h>
#include <util/irep.h>
#include <string>
#include <unordered_map>
#include <memory>
#include <tuple>

/*******************************************************************\

   Class: summaryt

 Purpose:

This is a base class of summaries of any kind. It defines a mandatory
interface for any summary. It can be used for summarisation of loops,
functions, modules, etc. But of course, each kind of summary is supposed
to have a different (dedicated) implementation.

When you creating your summaries, you should subclass this summaryt type
and also provide a function object which is responsible for computation
of summaries.

\*******************************************************************/
class  summaryt
{
public:

  virtual ~summaryt() {}

  /*******************************************************************\
   It should return globally unique identifier of a 'kind' of the
   summaries. For example, it can be a unique name of an analysis which has
   computed them.
  \*******************************************************************/
  virtual std::string  kind() const = 0;

  /*******************************************************************\
   A textual human-readable description of the summaries.
  \*******************************************************************/
  virtual std::string  description() const noexcept { return ""; }

  // TODO: define other interface functions!!
};


/*******************************************************************\
 We represent a summary of an object (loop, function, etc.) as a pair:
    [object-unique-identifier,summary-ptr].
 This is defined in the following three 'typedef' statements.
\*******************************************************************/
typedef std::string  summarised_object_idt;
typedef std::shared_ptr<summaryt const>  summary_ptrt;
typedef std::pair<summarised_object_idt,summary_ptrt>  object_summaryt;


/*******************************************************************\

   Class: summaryt

 Purpose:

It holds and caches all computed summaries of the same kind (i.e. those
whose method 'summaryt::kind()' returns the same string). The goal is to
provide fast access to computed summaries. The implementation provides
fast caching of frequently used summaries, streaming summaries to/from
the disc (to minimise memory occupation), and thread-safety of all accesses.

For each kind of summaries one should use a separate instance of this
database.

If you want to permanently store the content of the cache to the disc,
you have to do that manually (yourself) by enumerating all elements.

\*******************************************************************/
class  database_of_summariest
{
public:

  typedef std::unordered_map<summarised_object_idt,summary_ptrt>  cachet;
  typedef cachet  databaset;

  virtual ~database_of_summariest() {}

  template<typename  summary_typet>
  std::shared_ptr<summary_typet const>  find(
      summarised_object_idt const&  object_id
      ) const;

  void  insert(object_summaryt const&  object_and_summary);

  databaset::const_iterator  cbegin() const;
  databaset::const_iterator  begin() const { return cbegin(); }  
  databaset::const_iterator  cend() const;
  databaset::const_iterator  end() const { return cend(); }

  std::size_t  count(const summarised_object_idt& id) const
  { return m_cache.count(id); }

  const summary_ptrt& operator[](const summarised_object_idt& id) const
  { return m_cache.at(id); }

private:
  cachet  m_cache;
};


template<typename  summary_typet>
std::shared_ptr<summary_typet const>  database_of_summariest::find(
    summarised_object_idt const&  object_id
    ) const
{
  auto const  it = m_cache.find(object_id);
  return it == m_cache.cend() ?
            std::shared_ptr<summary_typet const>() :
            std::dynamic_pointer_cast<summary_typet const>(it->second)
            ;
}


typedef std::shared_ptr<database_of_summariest>  database_of_summaries_ptrt;


#endif
