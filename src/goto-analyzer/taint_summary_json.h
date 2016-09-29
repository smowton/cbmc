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

namespace sumfn { namespace taint {

 json_objectt summary_to_json(const object_summaryt&);
 object_summaryt summary_from_json(const json_objectt&, const domain_ptrt);

}} // Close namespaces

#endif
