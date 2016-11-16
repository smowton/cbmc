/*******************************************************************\

Module: taint_summary

Author: Marek Trtik

Date: September 2016

This module defines interfaces and functionality for taint summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_SUMMARY_H
#define CPROVER_TAINT_SUMMARY_H

#include "taint_summary_json.h"

#include <summaries/summary.h>
#include <summaries/utility.h>
#include <goto-programs/goto_model.h>
#include <goto-programs/goto_functions.h>
#include <analyses/call_graph.h>
#include <pointer-analysis/local_value_set_analysis.h>
#include <pointer-analysis/object_numbering.h>
#include <util/irep.h>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <functional>
#include <string>
#include <iosfwd>


/*******************************************************************\

   Class:

 Purpose:

\*******************************************************************/
class  taint_svaluet
{
public:

  typedef unsigned long  taint_symbolt;
  typedef std::set<taint_symbolt>  expressiont;

  taint_svaluet(
      expressiont const&  expression,
      bool  is_bottom,
      bool  is_top
      );

  taint_svaluet(
      expressiont const&  expression,
      expressiont const&  suppression,
      bool  is_bottom,
      bool  is_top
      );

  taint_svaluet(taint_svaluet const&  other);
  taint_svaluet(taint_svaluet&&  other);

  taint_svaluet&  operator=(taint_svaluet const&  other);
  taint_svaluet&  operator=(taint_svaluet&&  other);

  bool  is_top() const noexcept { return m_is_top; }
  bool  is_bottom() const noexcept { return m_is_bottom; }
  expressiont const&  expression() const noexcept { return m_expression; }
  expressiont const&  suppression() const noexcept { return m_suppression; }

  bool  is_symbol() const noexcept
  { return !is_top() && !is_bottom() && expression().size() == 1UL; }

private:
  expressiont  m_expression;
  expressiont  m_suppression;
  bool  m_is_bottom;
  bool  m_is_top;
};

/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_svaluet  taint_make_symbol();


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_svaluet  taint_make_bottom();


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_svaluet  taint_make_top();


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
bool operator==(taint_svaluet const& a, taint_svaluet const& b);
inline bool operator!=(taint_svaluet const& a, taint_svaluet const& b)
{
  return !(a==b);
}

/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_svaluet  join(taint_svaluet const&  a, taint_svaluet const&  b);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_svaluet  suppression(
    taint_svaluet const&  a,
    taint_svaluet::expressiont const&  sub
    );


/*******************************************************************\
\*******************************************************************/
typedef access_path_to_memoryt  taint_lvaluet;

typedef std::unordered_map<taint_lvaluet,taint_svaluet,irep_hash,irep_full_eq>
        taint_map_from_lvalues_to_svaluest;
typedef std::unordered_set<taint_lvaluet,irep_hash,irep_full_eq>
        taint_lvalues_sett;


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_svaluet::taint_symbolt find_taint_value(const exprt &expr);


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
exprt find_taint_expression(const exprt &expr);



typedef std::map<unsigned int,taint_svaluet> taint_numbered_lvalue_svalue_mapt;
typedef goto_programt::instructiont::const_targett  instruction_iteratort;
typedef std::unordered_map<instruction_iteratort,
                           taint_numbered_lvalue_svalue_mapt,
                           instruction_iterator_hashert>
        taint_numbered_domaint;



/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_numbered_lvalue_svalue_mapt  join(
    taint_numbered_lvalue_svalue_mapt const&  a,
    taint_numbered_lvalue_svalue_mapt const&  b
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_numbered_lvalue_svalue_mapt  assign(
    taint_numbered_lvalue_svalue_mapt const&  a,
    taint_numbered_lvalue_svalue_mapt const&  b
    );


/*******************************************************************\
\*******************************************************************/

/*******************************************************************\
\*******************************************************************/
typedef std::unordered_map<instruction_iteratort,
                           taint_map_from_lvalues_to_svaluest,
                           instruction_iterator_hashert>
        taint_symmary_domaint;

typedef std::shared_ptr<taint_symmary_domaint>  taint_summary_domain_ptrt;


/*******************************************************************\

   Class:

 Purpose:

\*******************************************************************/
class  taint_summaryt : public json_serialisable_summaryt
{
public:

  taint_summaryt(taint_map_from_lvalues_to_svaluest const&  input,
                 taint_map_from_lvalues_to_svaluest const&  output,
                 const taint_numbered_domaint& domain,
		 const object_numberingt& numbering);

  taint_summaryt() {}

  std::string  kind() const noexcept;
  std::string  description() const noexcept;

  taint_map_from_lvalues_to_svaluest const&  input() const noexcept
  { return m_input; }
  taint_map_from_lvalues_to_svaluest const&  output() const noexcept
  { return m_output; }

  const taint_numbered_domaint&  domain() const noexcept { return m_domain; }
  const object_numberingt& domain_numbering() const noexcept { return numbering; }

  json_objectt to_json() const;
  void from_json(const json_objectt&);

private:
  taint_map_from_lvalues_to_svaluest  m_input;
  taint_map_from_lvalues_to_svaluest  m_output;
  taint_numbered_domaint  m_domain;
  object_numberingt numbering;
};

typedef std::shared_ptr<taint_summaryt const>  taint_summary_ptrt;


typedef std::unordered_map<std::string,taint_svaluet::taint_symbolt>
        taint_specification_symbol_names_to_svalue_symbols_mapt;

typedef std::unordered_map<taint_svaluet::taint_symbolt,std::string>
        taint_svalue_symbols_to_specification_symbols_mapt;


typedef std::unordered_map<std::string,object_numberingt>
        taint_object_numbering_per_functiont;

typedef std::map<irep_idt,std::set<unsigned> > object_numbers_by_fieldnamet;
typedef std::unordered_map<std::string,object_numbers_by_fieldnamet>
        object_numbers_by_field_per_functiont;


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
void  taint_summarise_all_functions(
    goto_modelt const&  instrumented_program,
    database_of_summariest&  summaries_to_compute,
    call_grapht const&  call_graph,
    local_value_set_analysist::dbt* lvsa_db,
    taint_specification_symbol_names_to_svalue_symbols_mapt const&
        taint_spec_names,
    taint_object_numbering_per_functiont&  taint_object_numbering,
    object_numbers_by_field_per_functiont&  object_numbers_by_field,
    message_handlert&  msg,
    double  timeout = 60.0,
    std::ostream* const  log = nullptr
    );


/*******************************************************************\

Function:

  Inputs: See purpose

 Outputs: See purpose

 Purpose:


\*******************************************************************/
taint_summary_ptrt  taint_summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    database_of_summariest const&  database,
    local_value_set_analysist::dbt* lvsa_db,
    taint_specification_symbol_names_to_svalue_symbols_mapt const&
        taint_spec_names,
    object_numberingt&  taint_object_numbering,
    object_numbers_by_fieldnamet&  object_numbers_by_field,
    message_handlert&  msg,
    std::ostream* const  log = nullptr
    );


typedef std::set<unsigned int> taint_numbered_lvalues_sett;
void expand_external_objects(taint_numbered_lvalues_sett& lvalue_set,
                             const object_numbers_by_fieldnamet& by_fieldname,
                             const object_numberingt& taint_object_numbering);


#endif
