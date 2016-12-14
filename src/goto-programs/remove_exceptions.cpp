/*******************************************************************\

Module: Remove exception handling 

Author: Cristina David

Date:   December 2016

\*******************************************************************/
#include<iostream>
#include <stack>

#include <util/std_expr.h>
#include <util/symbol_table.h>

#include "remove_exceptions.h"

class remove_exceptionst
{
public:
  explicit remove_exceptionst(symbol_tablet &_symbol_table):
    symbol_table(_symbol_table)
  {
  }

  void operator()(
    goto_functionst &goto_functions);

protected:
  symbol_tablet &symbol_table;

  void add_exceptional_returns(
    goto_functionst::function_mapt::iterator f_it);

  void replace_throws(
    goto_functionst::function_mapt::iterator f_it);

  void instrument_function_calls(
    goto_functionst::function_mapt::iterator f_it);

  void instrument_exception_handlers(
    goto_functionst::function_mapt::iterator f_it);
  void add_gotos(
    goto_functionst::function_mapt::iterator f_it);

  void add_throw_gotos(
    goto_functionst::function_mapt::iterator f_it,
    goto_programt::instructionst::iterator i_it,
    stack_catcht stack_catch);

  void add_function_call_gotos(
    goto_functionst::function_mapt::iterator f_it,
    goto_programt::instructionst::iterator i_it,
    stack_catcht stack_catch);
};

void remove_exceptionst::add_exceptional_returns(
  goto_functionst::function_mapt::iterator f_it)
{
  const irep_idt function_id=f_it->first;
  goto_programt &goto_program=f_it->second.body;

  if(goto_program.empty())
    return;

  bool change=true;

  // we recursively add all the functions that may throw an exception
  while(change)
  {
    change=false;
    Forall_goto_program_instructions(i_it, goto_program)
    {
      irep_idt function_call_id;
      if(i_it->is_function_call())
        function_call_id=to_symbol_expr(to_code_function_call(i_it->code).
          function()).get_identifier();

      if(i_it->is_throw() ||
        (i_it->is_function_call() &&
         symbol_table.has_symbol(id2string(function_call_id)+EXC_SUFFIX)))
      {
        change=true;
        // look up the function symbol
        symbol_tablet::symbolst::iterator s_it=
          symbol_table.symbols.find(function_id);

        assert(s_it!=symbol_table.symbols.end());
        symbolt &function_symbol=s_it->second;

        auxiliary_symbolt new_symbol;
        new_symbol.is_static_lifetime=true;
        new_symbol.module=function_symbol.module;
        new_symbol.base_name=id2string(function_symbol.base_name)+EXC_SUFFIX;
        new_symbol.name=id2string(function_symbol.name)+EXC_SUFFIX;
        new_symbol.mode=function_symbol.mode;
        // initialize with NULL
        new_symbol.type=typet(ID_pointer, empty_typet());
        new_symbol.value=null_pointer_exprt(pointer_typet());
        symbol_table.add(new_symbol);
        return;
      }
    }
  }
}

/*******************************************************************\

Function: remove_exceptionst::replace_throws

Inputs:

Outputs:

Purpose: turns 'throw x' in function f into an assignment to f#exc_value

\*******************************************************************/

void remove_exceptionst::replace_throws(
  goto_functionst::function_mapt::iterator f_it)
{
  const irep_idt function_id=f_it->first;
  goto_programt &goto_program=f_it->second.body;

  if(goto_program.empty())
    return;

  Forall_goto_program_instructions(i_it, goto_program)
  {
    if(i_it->is_throw() &&
       symbol_table.has_symbol(id2string(function_id)+EXC_SUFFIX))
    {
      assert(i_it->code.operands().size()==1);
      symbolt &function_symbol=symbol_table.lookup(id2string(function_id)+
                                                  EXC_SUFFIX);

      // replace "throw x;" by "f#exception_value=x;"
      symbol_exprt lhs_expr;
      lhs_expr.set_identifier(id2string(function_id)+EXC_SUFFIX);
      lhs_expr.type()=function_symbol.type;

      // find the symbol corresponding to the thrown exceptions
      exprt exc_symbol=i_it->code;
      while(exc_symbol.id()!=ID_symbol)
        exc_symbol=exc_symbol.op0();

      // add the assignment with the appropriate cast
      code_assignt assignment(typecast_exprt(lhs_expr, exc_symbol.type()),
                              exc_symbol);

      // now turn the `throw' into `assignment'
      i_it->type=ASSIGN;
      i_it->code=assignment;
    }
  }
}

/*******************************************************************\

Function: remove_exceptionst::instrument_function_calls

Inputs:

Outputs:

Purpose: after each function call g() in function f 
         adds f#exception_value=g#exception_value;

\*******************************************************************/

void remove_exceptionst::instrument_function_calls(
  goto_functionst::function_mapt::iterator f_it)
{
  const irep_idt &caller_id=f_it->first;
  goto_programt &goto_program=f_it->second.body;

  if(goto_program.empty())
    return;

  Forall_goto_program_instructions(i_it, goto_program)
  {
    if(i_it->is_function_call())
    {
      code_function_callt &function_call=to_code_function_call(i_it->code);
      const irep_idt &callee_id=
        to_symbol_expr(function_call.function()).get_identifier();

      // can exceptions escape?
      if(symbol_table.has_symbol(id2string(callee_id)+EXC_SUFFIX) &&
        symbol_table.has_symbol(id2string(caller_id)+EXC_SUFFIX))
      {
        symbolt &callee=symbol_table.lookup(id2string(callee_id)+EXC_SUFFIX);
        symbolt &caller=symbol_table.lookup(id2string(caller_id)+EXC_SUFFIX);

        symbol_exprt rhs_expr;
        rhs_expr.set_identifier(id2string(callee_id)+EXC_SUFFIX);
        rhs_expr.type()=callee.type;

        symbol_exprt lhs_expr;
        lhs_expr.set_identifier(id2string(caller_id)+EXC_SUFFIX);
        lhs_expr.type()=caller.type;

        goto_programt::targett t=goto_program.insert_after(i_it);
        t->make_assignment();
        t->source_location=i_it->source_location;
        t->code=code_assignt(lhs_expr, rhs_expr);
        t->function=i_it->function;
      }
    }
  }
}

/*******************************************************************\

Function: remove_exceptionst::instrument_exception_handlers

Inputs:

Outputs:

Purpose: at the beginning of each handler in function f 
         adds exc=f#exception_value; f#exception_value=NULL;

\*******************************************************************/

void remove_exceptionst::instrument_exception_handlers(
  goto_functionst::function_mapt::iterator f_it)
{
  const irep_idt &function_id=f_it->first;
  goto_programt &goto_program=f_it->second.body;

  if(goto_program.empty())
    return;

  Forall_goto_program_instructions(i_it, goto_program)
  {
    // is this a handler
    if(i_it->type==CATCH && i_it->code.find(ID_handler)!=get_nil_irep())
    {
      // retrieve the exception variable
      const irept &exception=i_it->code.find(ID_handler);

      if(symbol_table.has_symbol(id2string(function_id)+EXC_SUFFIX))
      {
        symbolt &function_symbol=symbol_table.lookup(id2string(function_id)+
                                                    EXC_SUFFIX);
        // next we reset the exceptional return to NULL
        symbol_exprt lhs_expr_null;
        lhs_expr_null.set_identifier(id2string(function_id)+EXC_SUFFIX);
        lhs_expr_null.type()=function_symbol.type;
        exprt rhs_expr_null;
        rhs_expr_null=null_pointer_exprt(pointer_typet());

        // add the assignment
        goto_programt::targett t_null=goto_program.insert_after(i_it);
        t_null->make_assignment();
        t_null->source_location=i_it->source_location;
        t_null->code=code_assignt(
          lhs_expr_null,
          typecast_exprt(rhs_expr_null, lhs_expr_null.type()));
        t_null->function=i_it->function;

        // add the assignment exc=f#exception_value
        symbol_exprt rhs_expr_exc;
        rhs_expr_exc.set_identifier(id2string(function_id)+EXC_SUFFIX);
        rhs_expr_exc.type()=function_symbol.type;

        const exprt &lhs_expr_exc=static_cast<const exprt &>(exception);
        goto_programt::targett t_exc=goto_program.insert_after(i_it);
        t_exc->make_assignment();
        t_exc->source_location=i_it->source_location;
        t_exc->code=code_assignt(
          typecast_exprt(lhs_expr_exc, rhs_expr_exc.type()),
          rhs_expr_exc);
        t_exc->function=i_it->function;
      }

      i_it->make_skip();
    }
  }
}

/*******************************************************************\

Function: remove_exceptionst::add_gotos_throw

Inputs:

Outputs:

Purpose: instruments each throw with conditional GOTOS to the 
         corresponding exception handlers

\*******************************************************************/
void remove_exceptionst::add_throw_gotos(
  goto_functionst::function_mapt::iterator f_it,
  goto_programt::instructionst::iterator i_it,
  stack_catcht stack_catch)
{
  assert(i_it->type==THROW);

  goto_programt &goto_program=f_it->second.body;

  assert(i_it->code.operands().size()==1);

  // make sure that these are always forward gotos
  assert(!i_it->is_backwards_goto());

  // jump to the end of the function
  // this will appear after the GOTO-based dynamic dispatch below
  goto_programt::targett t_end=goto_program.insert_after(i_it);
  goto_programt::targett new_state;
  // find the end of the function
  for(goto_programt::instructionst::iterator inner_it=i_it;
      inner_it!=goto_program.instructions.end();
      inner_it++)
  {
    if(inner_it->is_end_function())
      new_state=inner_it;
  }
  t_end->make_goto(new_state);
  t_end->source_location=i_it->source_location;
  t_end->function=i_it->function;

  // add GOTOs implementing the dynamic dispatch of the
  // exception handlers
  for(std::size_t i=stack_catch.size(); i-->0;)
  {
    for(std::size_t j=stack_catch[i].catch_handlers.size(); j-->0;)
    {
      goto_programt::targett new_state_pc;
      new_state_pc=stack_catch[i].catch_handlers[j].second;

      // find handler
      goto_programt::targett t_exc=goto_program.insert_after(i_it);
      t_exc->make_goto(new_state_pc);
      t_exc->source_location=i_it->source_location;
      t_exc->function=i_it->function;

      // use instanceof to check that this is the correct handler
      symbol_typet type(stack_catch[i].catch_handlers[j].first);
      type_exprt expr(type);
      // find the symbol corresponding to the caught exceptions
      exprt exc_symbol=i_it->code;
      while(exc_symbol.id()!=ID_symbol)
        exc_symbol=exc_symbol.op0();

      binary_predicate_exprt check(exc_symbol, ID_java_instanceof, expr);
      t_exc->guard=check;
    }
  }
}

/*******************************************************************\

Function: remove_exceptionst::add_function_call_gotos

Inputs:

Outputs:

Purpose: instruments each function call that may escape exceptions
          with conditional GOTOS to the corresponding exception handlers

\*******************************************************************/
void remove_exceptionst::add_function_call_gotos(
  goto_functionst::function_mapt::iterator f_it,
  goto_programt::instructionst::iterator i_it,
  stack_catcht stack_catch)
{
  assert(i_it->type==FUNCTION_CALL);

  goto_programt &goto_program=f_it->second.body;


  code_function_callt &function_call=to_code_function_call(i_it->code);
  assert(function_call.function().id()==ID_symbol);
  const irep_idt &callee_id=
    to_symbol_expr(function_call.function()).get_identifier();

  if(symbol_table.has_symbol(id2string(callee_id)+EXC_SUFFIX))
  {
    // jump to the end of the function
    goto_programt::targett t_end=goto_program.insert_after(i_it);
    goto_programt::targett new_state;
    // find the end of the function
    for(goto_programt::instructionst::iterator inner_it=i_it;
        inner_it!=goto_program.instructions.end();
        inner_it++)
    {
      if(inner_it->is_end_function())
        new_state=inner_it;
    }
    t_end->make_goto(new_state);
    t_end->source_location=i_it->source_location;
    t_end->function=i_it->function;

    // dynamic dispatch of the escaped exception
    for(std::size_t i=stack_catch.size(); i-->0;)
    {
      for(std::size_t j=stack_catch[i].catch_handlers.size(); j-->0;)
      {
        symbolt &callee_exc_symbol=symbol_table.lookup(id2string(callee_id)+
                                                       EXC_SUFFIX);
        symbol_exprt callee_exc;
        callee_exc.set_identifier(id2string(callee_id)+EXC_SUFFIX);
        callee_exc.type()=callee_exc_symbol.type;

        goto_programt::targett new_state_pc;
        new_state_pc=stack_catch[i].catch_handlers[j].second;
        goto_programt::targett t_exc=goto_program.insert_after(i_it);
        t_exc->make_goto(new_state_pc);
        t_exc->source_location=i_it->source_location;
        t_exc->function=i_it->function;
        // use instanceof to check that this is the correct handler
        symbol_typet type(stack_catch[i].catch_handlers[j].first);
        type_exprt expr(type);
        binary_predicate_exprt check_instanceof(
          callee_exc,
          ID_java_instanceof,
          expr);
        t_exc->guard=check_instanceof;

        // add a null check (so that instanceof can ba applied)
        equal_exprt eq_null(typecast_exprt(callee_exc, pointer_typet()),
                            null_pointer_exprt(pointer_typet()));
        // jump to the end of the function
        goto_programt::targett t_null=goto_program.insert_after(i_it);
        t_null->make_goto(new_state);
        t_null->source_location=i_it->source_location;
        t_null->function=i_it->function;
        t_null->guard=eq_null;
      }
    }
  }
}

/*******************************************************************\

Function: remove_exceptionst::add_gotos

Inputs:

Outputs:

Purpose: instruments each throw and function calls that may escape exceptions
         with conditional GOTOS to the corresponding exception handlers

\*******************************************************************/
void remove_exceptionst::add_gotos(
  goto_functionst::function_mapt::iterator f_it)
{
  // Stack of try-catch blocks
  stack_catcht stack_catch;

  const irep_idt &function_id=f_it->first;
  goto_programt &goto_program=f_it->second.body;

  if(goto_program.empty())
    return;
  Forall_goto_program_instructions(i_it, goto_program)
  {
    // it's a CATCH but not a handler
    if(i_it->type==CATCH && i_it->code.find(ID_handler)==get_nil_irep())
    {
      if(i_it->targets.empty()) // pop
      {
#if 0
        if(stack_catch.empty())
          throw "catch-pop on empty call stack";
#endif
        // pop from the stack if possible
        if(!stack_catch.empty())
        {
          stack_catch.pop_back();
        }
        else
        {
          std::cout << "Remove exceptions: empty stack" << std::endl;
        }
      }
      else // push
      {
        std::cout << "(push) add_gotos for fct " <<
          id2string(function_id) << std::endl;
        exceptiont exception;
        // copy targets
        const irept::subt &exception_list=
          i_it->code.find(ID_exception_list).get_sub();
        assert(exception_list.size()==i_it->targets.size());

        // Fill the map with the catch type and the target
        unsigned i=0;
        for(goto_programt::targetst::const_iterator
              it=i_it->targets.begin();
            it!=i_it->targets.end();
            it++, i++)
        {
          exception.catch_handlers.push_back(
            std::make_pair(exception_list[i].id(), *it));
        }

        // Stack it
        stack_catch.push_back(exception);
      }

      i_it->make_skip();
    }
    else if(i_it->type==THROW)
    {
      add_throw_gotos(f_it, i_it, stack_catch);
    }
    else if(i_it->type==FUNCTION_CALL)
    {
      add_function_call_gotos(f_it, i_it, stack_catch);
    }
  }
}


/*******************************************************************\

Function: remove_exceptionst::operator()

Inputs:

Outputs:

Purpose:

\*******************************************************************/

void remove_exceptionst::operator()(goto_functionst &goto_functions)
{
  Forall_goto_functions(it, goto_functions)
  {
    add_exceptional_returns(it);
    instrument_exception_handlers(it);
    add_gotos(it);
    instrument_function_calls(it);
    replace_throws(it);
  }
}

/*******************************************************************\

Function: remove_exceptions

Inputs:

Outputs:

Purpose: removes throws/CATCH-POP/CATCH-PUSH

\*******************************************************************/

void remove_exceptions(
  symbol_tablet &symbol_table,
  goto_functionst &goto_functions)
{
  remove_exceptionst rr(symbol_table);
  rr(goto_functions);
}

/*******************************************************************\

Function: remove_exceptions

Inputs:

Outputs:

Purpose: removes throws/CATCH-POP/CATCH-PUSH

\*******************************************************************/

void remove_exceptions(goto_modelt &goto_model)
{
  remove_exceptionst rr(goto_model.symbol_table);
  rr(goto_model.goto_functions);
}



