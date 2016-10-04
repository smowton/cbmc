/////////////////////////////////////////////////////////////////////////////
//
// Module: taint_summary_json
// Author: Chris Smowton
//
// Reads and writes taint summaries as JSON.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef CPROVER_TAINT_SUMMARY_JSON_H
#define CPROVER_TAINT_SUMMARY_JSON_H

#include <util/json.h>
#include <summaries/summary.h>
#include "taint_summary.h"


json_objectt summary_to_json(const object_summaryt&);
object_summaryt summary_from_json(const json_objectt&,
                                  const taint_summary_domain_ptrt);


#endif
