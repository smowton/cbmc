/////////////////////////////////////////////////////////////////////////////
//
// Module: summary
// Author: Marek Trtik
//
// This module defines interfaces and functionality for all kinds of summaries.
// It in particular comprises loop, function, and module summaries.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef CPROVER_SUMMARY_H
#define CPROVER_SUMMARY_H

#include <goto-programs/goto_model.h>
#include <util/irep.h>
#include <string>
#include <unordered_map>
#include <memory>
#include <tuple>

namespace sumfn {


/**
 * This is a base class of summaries of any kind. It defines a mandatory
 * interface for any summary. It can be used for summarisation of loops,
 * functions, modules, etc. But of course, each kind of summary is supposed
 * to have a different (dedicated) implementation.
 *
 * When you creating your summaries, you should subclass this summaryt type
 * and also provide a function object which is responsible for computation
 * of summaries.
 */
struct  summaryt
{
  virtual ~summaryt() {}

  /**
   * It should return globally unique identifier of a 'kind' of the
   * summaries. For example, it can be a unique name of an analysis which has
   * computed them.
   */
  virtual std::string  kind() const = 0;

  /**
   * A textual human-readable description of the summaries.
   */
  virtual std::string  description() const noexcept { return ""; }

  // TODO: define other interface functions!!
};


/**
 * We represent a summary of an object (loop, function, etc.) as a pair:
 *    [object-unique-identifier,summary-ptr].
 * This is defined in the following three 'using' statements.
 */
typedef std::string  summarised_object_idt;
typedef std::shared_ptr<summaryt const>  summary_ptrt;
typedef std::pair<summarised_object_idt,summary_ptrt>  object_summaryt;


/**
 * It holds and caches all computed summaries of the same kind (i.e. those
 * whose method 'summaryt::kind()' returns the same string). The goal is to
 * provide fast access to computed summaries. The implementation provides
 * fast caching of frequently used summaries, streaming summaries to/from
 * the disc (to minimise memory occupation), and thread-safety of all accesses.
 *
 * For each kind of summaries one should use a separate instance of this
 * database.
 *
 * If you want to permanently store the content of the cache to the disc,
 * you have to do that manually (yourself) by enumerating all elements.
 */
struct  database_of_summariest
{
  typedef std::unordered_map<summarised_object_idt,summary_ptrt>  cachet;
  typedef cachet  databaset;

  virtual ~database_of_summariest() {}

  void  insert(object_summaryt const&  object_and_summary);

  databaset::const_iterator  cbegin() const;
  databaset::const_iterator  begin() const { return cbegin(); }  
  databaset::const_iterator  cend() const;
  databaset::const_iterator  end() const { return cend(); }  

  // TODO: add interface for searching and iteration in the database.

private:
  cachet  m_cache;
};


typedef std::shared_ptr<database_of_summariest>  database_of_summaries_ptrt;


}

#endif
