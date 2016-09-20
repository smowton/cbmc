/////////////////////////////////////////////////////////////////////////////
//
// Module: summary
// Author: Marek Trtik
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////


#include <summaries/summary.h>
#include <util/msgstream.h>

namespace sumfn {


void  database_of_summaries_t::insert(
    object_summary_t const&  object_and_summary
    )
{
  m_cache.insert(object_and_summary);
}


}
