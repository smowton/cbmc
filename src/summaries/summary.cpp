/*******************************************************************\

Module: summary

Author: Marek Trtik

Date: September 2016

This module defines interfaces and functionality for all kinds of summaries.
It in particular comprises loop, function, and module summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <summaries/summary.h>
#include <util/file_util.h>

void  database_of_summariest::insert(
    object_summaryt const&  object_and_summary
    )
{
  m_cache.insert(object_and_summary);
}

database_of_summariest::databaset::const_iterator
database_of_summariest::cbegin() const
{
  return m_cache.cbegin();
}

database_of_summariest::databaset::const_iterator
database_of_summariest::cend() const
{
  return m_cache.cend();
}


