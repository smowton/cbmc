/*******************************************************************\
 Module: Goto Programs
 Author: Thomas Kiley, thomas@diffblue.com
\*******************************************************************/

/// \file
/// Goto Programs Author: Thomas Kiley, thomas@diffblue.com

#ifndef CPROVER_GOTO_PROGRAMS_REBUILD_GOTO_START_FUNCTION_H
#define CPROVER_GOTO_PROGRAMS_REBUILD_GOTO_START_FUNCTION_H

#include <util/message.h>

#include "lazy_goto_model.h"


class symbol_tablet;
class goto_functionst;

#define OPT_FUNCTIONS \
  "(function):"

#define HELP_FUNCTIONS \
  " --function name              set main function name\n"

class rebuild_goto_start_functiont: public messaget
{
public:
  rebuild_goto_start_functiont(
    lazy_goto_modelt &goto_model,
    message_handlert &message_handler);

  bool operator()();

private:
  irep_idt get_entry_point_mode() const;

  void remove_existing_entry_point();

  lazy_goto_modelt &goto_model;
};

#endif // CPROVER_GOTO_PROGRAMS_REBUILD_GOTO_START_FUNCTION_H
