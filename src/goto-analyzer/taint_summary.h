/////////////////////////////////////////////////////////////////////////////
//
// Module: taint_summary
// Author: Marek Trtik
//
// This module defines interfaces and functionality for tint summaries.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef CPROVER_TAINT_SUMMARY_H
#define CPROVER_TAINT_SUMMARY_H

#include <summaries/summary.h>
#include <goto-programs/goto_model.h>
#include <goto-programs/goto_functions.h>
#include <util/irep.h>
#include <string>

namespace sumfn { namespace taint {


struct  summary_t : public sumfn::summary_t
{
  std::string  kind() const;
  std::string  description() const noexcept;
};


void  summarise_all_functions(
    goto_modelt const&  instrumented_program,
    database_of_summaries_t&  summaries_to_compute
    );


summary_ptr_t  summarise_function(
    irep_idt const&  function_id,
    goto_functionst::function_mapt const&  functions
    );


}}

#endif
