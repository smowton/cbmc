/*******************************************************************\

Module: utility

Author: Marek Trtik

Date: September 2016

This module defines utility functions which can be useful when implementing
summaries of any kinds.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_SUMMARIES_UTILITY_H
#define CPROVER_SUMMARIES_UTILITY_H

#include <util/expr.h>
#include <util/namespace.h>
#include <util/std_code.h>
#include <util/std_types.h>
#include <string>

namespace sumfn {


/*******************************************************************\
\*******************************************************************/
typedef  exprt  access_path_to_memoryt;


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
access_path_to_memoryt const&  empty_access_path();


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  is_empty(access_path_to_memoryt const&  path);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  is_identifier(access_path_to_memoryt const&  lvalue);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
std::string  name_of_symbol_access_path(access_path_to_memoryt const&  lvalue);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  is_parameter(access_path_to_memoryt const&  lvalue,
                   namespacet const&  ns);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  is_static(access_path_to_memoryt const&  lvalue, namespacet const&  ns);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  is_return_value_auxiliary(access_path_to_memoryt const&  lvalue,
                                namespacet const&  ns);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  is_pure_local(access_path_to_memoryt const&  lvalue,
                    namespacet const&  ns);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool  is_this(access_path_to_memoryt const&  lvalue, namespacet const&  ns);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
access_path_to_memoryt  normalise(
    access_path_to_memoryt const&  access_path,
    namespacet const&  ns
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
access_path_to_memoryt  scope_translation(
    access_path_to_memoryt const&  source_path,
    irep_idt const&  source_scope_id,
    irep_idt const&  target_scope_id,
    code_function_callt const&  source_scope_call_expr,
    code_typet const&  source_scope_type,
    namespacet const&  ns
    );


}

#endif
