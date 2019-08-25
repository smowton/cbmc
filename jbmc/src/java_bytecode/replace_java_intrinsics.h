/*******************************************************************\

Module: Replace Java intrinsics

Author: Diffblue Ltd.

\*******************************************************************/

/// \file
/// Replace Java intrinsics

#ifndef CPROVER_JAVA_BYTECODE_REPLACE_JAVA_INTRINSICS_H
#define CPROVER_JAVA_BYTECODE_REPLACE_JAVA_INTRINSICS_H

class goto_modelt;
class goto_model_functiont;
class message_handlert;

void replace_java_intrinsics(goto_model_functiont &, message_handlert &);
void replace_java_intrinsics(goto_modelt &, message_handlert &);

#endif
