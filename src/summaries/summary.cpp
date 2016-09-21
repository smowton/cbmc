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


#include <summaries/summary.h>

namespace sumfn {


void  database_of_summaries_t::insert(
    object_summary_t const&  object_and_summary
    )
{
  m_cache.insert(object_and_summary);
}

database_of_summaries_t::database_t::const_iterator
database_of_summaries_t::cbegin() const
{
  return m_cache.cbegin();
}

database_of_summaries_t::database_t::const_iterator
database_of_summaries_t::cend() const
{
  return m_cache.cend();
}

}
