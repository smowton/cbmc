/////////////////////////////////////////////////////////////////////////////
//
// Module: utility
// Author: Marek Trtik
//
// This module defines utility functions which can be useful when implementing
// summaries of any kinds.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef CPROVER_SUMMARIES_UTILITY_H
#define CPROVER_SUMMARIES_UTILITY_H

#include <util/expr.h>
#include <util/namespace.h>
#include <string>

namespace sumfn {


/**
 *
 *
 *
 */
typedef  exprt  access_path_to_memoryt;



/**
 *
 *
 *
 */
bool  is_identifier(access_path_to_memoryt const&  lvalue);


/**
 *
 *
 *
 */
std::string  name_of_symbol_access_path(access_path_to_memoryt const&  lvalue);


/**
 *
 *
 *
 */
bool  is_parameter(access_path_to_memoryt const&  lvalue,
                   namespacet const&  ns);


/**
 *
 *
 *
 */
bool  is_static(access_path_to_memoryt const&  lvalue, namespacet const&  ns);


/**
 *
 *
 *
 */
bool  is_return_value_auxiliary(access_path_to_memoryt const&  lvalue,
                                namespacet const&  ns);


/**
 *
 *
 *
 */
bool  is_pure_local(access_path_to_memoryt const&  lvalue,
                    namespacet const&  ns);


/**
 *
 *
 *
 */
access_path_to_memoryt  scope_translation(
    access_path_to_memoryt const&  source_path,
    irep_idt const&  source_scope_id,
    irep_idt const&  target_scope_id
    //,     goto_modelt const&  program
    );


}

#endif
