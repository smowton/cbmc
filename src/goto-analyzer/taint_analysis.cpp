/*******************************************************************\

Module: Taint Analysis

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#include <iostream>
#include <fstream>

#include <util/prefix.h>
#include <util/simplify_expr.h>
#include <util/json.h>
#include <util/file_util.h>
#include <util/suffix.h>
#include <json/json_parser.h>

#include <ansi-c/string_constant.h>

#include <goto-programs/class_hierarchy.h>

#include <analyses/custom_bitvector_analysis.h>

#include <summaries/summary.h>

#include "taint_analysis.h"
#include "taint_parser.h"
#include "taint_summary.h"
#include "taint_summary_json.h"

/*******************************************************************\

   Class: taint_analysist

 Purpose:

\*******************************************************************/

class taint_analysist:public messaget
{
public:
  taint_analysist()
  {
  }

  bool operator()(
    const std::string &taint_file_name,
    const symbol_tablet &,
    goto_functionst &,
    bool show_full,
    const std::string &json_file_name,
    const std::string &summaries_directory);

protected:
  taint_parse_treet taint;
  class_hierarchyt class_hierarchy;
  
  void instrument(const namespacet &, goto_functionst &);
  void instrument(const namespacet &, goto_functionst::goto_functiont &);

  void read_summaries(const std::string&, database_of_summariest&);
};

class bitvector_analysis_with_summariest:public custom_bitvector_analysist
{
public:
  bitvector_analysis_with_summariest(const database_of_summaries_ptrt _db)
    : summarydb(_db)
  {}

protected:
  database_of_summaries_ptrt summarydb;

  virtual bool should_enter_function(const irep_idt& id)
  { return summarydb->count(id2string(id)) == 0UL; }

  virtual void transform_function_call_stub(
      locationt,
      custom_bitvector_domaint&, const namespacet&
      );

  taint_summary_ptrt get_summary(const irep_idt& identifier);
};

/*******************************************************************\

Function: taint_analysist::instrument

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void taint_analysist::instrument(
  const namespacet &ns,
  goto_functionst &goto_functions)
{
  for(auto & function : goto_functions.function_map)
    instrument(ns, function.second);
}

/*******************************************************************\

Function: taint_analysist::instrument

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void taint_analysist::instrument(
  const namespacet &ns,
  goto_functionst::goto_functiont &goto_function)
{
  for(goto_programt::instructionst::iterator
      it=goto_function.body.instructions.begin();
      it!=goto_function.body.instructions.end();
      it++)
  {
    const goto_programt::instructiont &instruction=*it;
    
    goto_programt tmp;
  
    switch(instruction.type)
    {
    case FUNCTION_CALL:
      {
        const code_function_callt &function_call=
          to_code_function_call(instruction.code);
        const exprt &function=function_call.function();
        
        if(function.id()==ID_symbol)
        {
          const irep_idt &identifier=
            to_symbol_expr(function).get_identifier();
            
          std::set<irep_idt> identifiers;
          
          identifiers.insert(identifier);

          irep_idt class_id=function.get(ID_C_class);
          if(class_id.empty())
          {
            
          }
          else
          {
            std::string suffix=
              std::string(id2string(identifier), class_id.size(), std::string::npos);
            
            class_hierarchyt::idst parents=
              class_hierarchy.get_parents_trans(class_id);
            for(const auto & p : parents)
              identifiers.insert(id2string(p)+suffix);
          }
          
          for(const auto & rule : taint.rules)
          {
            bool match=false;
            for(const auto & i : identifiers)
              if(i==rule.function_identifier ||
                 has_prefix(id2string(i), "java::"+id2string(rule.function_identifier)+":"))
              {
                match=true;
                break;
              }
              
            if(match)
            {
              debug() << "MATCH " << rule.id << " on " << identifier << eom;
              
              exprt where=nil_exprt();
              
              const code_typet &code_type=to_code_type(function.type());
              
              bool have_this=
                !code_type.parameters().empty() &&
                code_type.parameters().front().get_bool(ID_C_this);
              
              switch(rule.where)
              {
              case taint_parse_treet::rulet::RETURN_VALUE:
                {
                  const symbolt &return_value_symbol=
                    ns.lookup(id2string(identifier)+"#return_value");
                  where=return_value_symbol.symbol_expr();
                }
                break;

              case taint_parse_treet::rulet::PARAMETER:
                {
                  unsigned nr=have_this?rule.parameter_number:rule.parameter_number-1;
                  if(function_call.arguments().size()>nr)
                    where=function_call.arguments()[nr];
                }
                break;

              case taint_parse_treet::rulet::THIS:
                if(have_this)
                {
                  assert(!function_call.arguments().empty());
                  where=function_call.arguments()[0];
                }
                break;
              }
              
              switch(rule.kind)
              {
              case taint_parse_treet::rulet::SOURCE:
                {
                  codet code_set_may("set_may");
                  code_set_may.operands().resize(2);
                  code_set_may.op0()=where;
                  code_set_may.op1()=address_of_exprt(string_constantt(rule.taint));
                  goto_programt::targett t=tmp.add_instruction();
                  t->make_other(code_set_may);
                  t->source_location=instruction.source_location;
                }
                break;
              
              case taint_parse_treet::rulet::SINK:
                {
                  goto_programt::targett t=tmp.add_instruction();
                  binary_predicate_exprt get_may("get_may");
                  get_may.op0()=where;
                  get_may.op1()=address_of_exprt(string_constantt(rule.taint));
                  t->make_assertion(not_exprt(get_may));
                  t->source_location=instruction.source_location;
                  t->source_location.set_property_class("taint rule "+id2string(rule.id));
                  t->source_location.set_comment(rule.message);
                }
                break;
              
              case taint_parse_treet::rulet::SANITIZER:
                {
                  codet code_clear_may("clear_may");
                  code_clear_may.operands().resize(2);
                  code_clear_may.op0()=where;
                  code_clear_may.op1()=address_of_exprt(string_constantt(rule.taint));
                  goto_programt::targett t=tmp.add_instruction();
                  t->make_other(code_clear_may);
                  t->source_location=instruction.source_location;
                }
                break;
              }
              
            }
          }
        }
      }
      break;
    
    default:;
    }
    
    if(!tmp.empty())
    {
      goto_programt::targett next=it;
      next++;
      goto_function.body.destructive_insert(next, tmp);
    }
  }
}

taint_summary_ptrt bitvector_analysis_with_summariest::get_summary(
    const irep_idt& identifier
    )
{
  return summarydb->find<taint_summaryt>(id2string(identifier));
}

namespace {

typedef custom_bitvector_domaint::vectorst vectorst;
typedef custom_bitvector_domaint::bit_vectort bit_vectort;

vectorst substitute_taint(
  const taint_svaluet& in,
  const std::map<std::string,vectorst>& subs)
{
  if(in.is_top())
    return vectorst();

  if(in.is_bottom())
  {
    vectorst ret;
    // Set 'may' for all possible taints.
    ret.may_bits=(bit_vectort)-1;
    return ret;
  }

  // Otherwise merge all taint sources given:
  vectorst ret;
  for(const auto& taint : in.expression())
  {
    const auto& vec=subs.at(taint);
    ret=custom_bitvector_domaint::merge(vec,ret);
  }
  return ret;  
}

}

void bitvector_analysis_with_summariest::transform_function_call_stub(
  locationt loc, custom_bitvector_domaint& domain, const namespacet& ns)
{
 
  const goto_programt::instructiont &instruction=*loc;
  const code_function_callt &code_function_call=to_code_function_call(instruction.code);
  const exprt &function=code_function_call.function();
  if(function.id()!=ID_symbol)
    throw "transform_function_call_stub with non-symbol argument";
  
  const irep_idt &identifier=to_symbol_expr(function).get_identifier();
  const auto summary=get_summary(identifier);

  // The summary should declare a symbol like "Tn" giving a symbolic taint name for each param.
  // Build a map from such symbolic names to actual taint vectors:
  
  std::map<std::string,vectorst> actual_input_taint;
  const auto& ftype=to_code_type(function.type());
  for(const auto& param : ftype.parameters())
  {
    symbol_exprt param_symbol(param.get_identifier(),param.type());
    auto param_taints=domain.get_rhs(param_symbol);
    auto findit=summary->input().find(param_symbol);
    if(findit==summary->input().end())
      continue;
    auto param_taint_object=findit->second;
    assert(param_taint_object.expression().size()==1);
    actual_input_taint[*(param_taint_object.expression().begin())]=param_taints;
  }

  // Now the summary maps symbolic taints onto actual expressions. Assign actual
  // taint to each given target.
  for(const auto& output : summary->output())
  {
    auto actual_output_taint=substitute_taint(output.second,actual_input_taint);
    if(output.first.id()==ID_symbol &&
       has_suffix(id2string(to_symbol_expr(output.first).get_identifier()),"#return_value"))
    {
      // Overwritten for certain:
      domain.assign_lhs(output.first,actual_output_taint);
    }
    else
    {
      // May be tainted:
      auto existing_taint=domain.get_rhs(output.first);
      auto merged_taint=custom_bitvector_domaint::merge(existing_taint,actual_output_taint);
      domain.assign_lhs(output.first,merged_taint);
    }
  }
  
}

void taint_analysist::read_summaries(
  const std::string& dir,
  database_of_summariest& summarydb)
{
  std::string index_filename=dir+"/"+"__index.json";
  if(!fileutl_file_exists(index_filename))
    throw "Summaries: __index.json not found";
  jsont index;
  {
    std::ifstream index_stream(index_filename);
    if(parse_json(index_stream,index_filename,get_message_handler(),index))
      throw "Failed to parse summaries index";
  }
  // In future, we'll load summaries on demand. For now, load everything in the index:
  assert(index.is_object() && "Summaries: expected __index to contain an object");
  for(const auto& entry : index.object)
  {
    assert(entry.second.is_string() && "Summaries: expected __index value to be a string");
    std::string entry_filename=dir+"/"+entry.second.value;
    if(!fileutl_file_exists(entry_filename))
      throw "Summaries: function json not found";

    jsont entry_json;
    {
      std::ifstream entry_stream(entry_filename);
      if(parse_json(entry_stream,entry_filename,get_message_handler(),entry_json))
	throw "Failed to parse entry json";
    }
    if(!entry_json.is_object())
      throw "Summaries: expected entry json to contain an object";

    const auto& entry_obj=static_cast<const json_objectt&>(entry_json);
    auto deserialised_entry=
        summary_from_json(entry_obj,taint_summary_domain_ptrt());
    summarydb.insert(deserialised_entry);
  }
}
   

/*******************************************************************\

Function: taint_analysist::operator()

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool taint_analysist::operator()(
  const std::string &taint_file_name,
  const symbol_tablet &symbol_table,
  goto_functionst &goto_functions,
  bool show_full,
  const std::string &json_file_name,
  const std::string &summaries_directory)
{
  try
  {
    json_arrayt json_result;
    bool use_json=!json_file_name.empty();
  
    status() << "Reading taint file `" << taint_file_name
             << "'" << eom;

    if(taint_parser(taint_file_name, taint, get_message_handler()))
    {
      error() << "Failed to read taint definition file" << eom;
      return true;
    }

    status() << "Got " << taint.rules.size()
             << " taint definitions" << eom;

    taint.output(debug());
    debug() << eom;

    status() << "Instrumenting taint" << eom;

    class_hierarchy(symbol_table);

    const namespacet ns(symbol_table);
    instrument(ns, goto_functions);
    goto_functions.update();
    
    bool have_entry_point=
      goto_functions.function_map.find(goto_functionst::entry_point())!=
      goto_functions.function_map.end();

    // do we have an entry point?
    if(have_entry_point)
    {
      status() << "Working from entry point" << eom;
    }
    else
    {
      status() << "No entry point found; "
                  "we will consider the heads of all functions as reachable" << eom;

      goto_programt end, gotos, calls;
      
      end.add_instruction(END_FUNCTION);

      forall_goto_functions(f_it, goto_functions)
        if(f_it->second.body_available() &&
           f_it->first!=goto_functionst::entry_point())
        {
          goto_programt::targett t=calls.add_instruction();
          code_function_callt call;
          call.function()=ns.lookup(f_it->first).symbol_expr();
          t->make_function_call(call);
          calls.add_instruction()->make_goto(end.instructions.begin());
          goto_programt::targett g=gotos.add_instruction();
          g->make_goto(t, side_effect_expr_nondett(bool_typet()));
        }
        
      goto_functionst::goto_functiont &entry=
        goto_functions.function_map[goto_functionst::entry_point()];

      goto_programt &body=entry.body;

      body.destructive_append(gotos);
      body.destructive_append(calls);
      body.destructive_append(end);
      
      goto_functions.update();
    }

    status() << "Data-flow analysis" << eom;

    database_of_summaries_ptrt summarydb =
        std::make_shared<database_of_summariest>();
    if(summaries_directory!="")
      read_summaries(summaries_directory,*summarydb);
    
    bitvector_analysis_with_summariest custom_bitvector_analysis(summarydb);
    custom_bitvector_analysis(goto_functions, ns);
    
    if(show_full)
    {
      custom_bitvector_analysis.output(ns, goto_functions, std::cout);
      return false;
    }
    
    forall_goto_functions(f_it, goto_functions)
    {
      if(!f_it->second.body.has_assertion()) continue;
      
      const symbolt &symbol=ns.lookup(f_it->first);

      if(f_it->first=="__actual_thread_spawn")
        continue;
        
      bool first=true;
        
      forall_goto_program_instructions(i_it, f_it->second.body)
      {
        if(!i_it->is_assert()) continue;
        if(!custom_bitvector_domaint::has_get_must_or_may(i_it->guard))
          continue;

        if(custom_bitvector_analysis[i_it].is_bottom) continue;

        exprt result=custom_bitvector_analysis.eval(i_it->guard, i_it);
        exprt result2=simplify_expr(result, ns);

        if(result2.is_true()) continue;

        if(first)
        {
          first=false;
          if(!use_json)
            std::cout << "\n"
                         "******** Function " << symbol.display_name() << '\n';
        }

        if(use_json)
        {
          json_objectt json;
          json["bug_class"]=json_stringt(id2string(i_it->source_location.get_property_class()));
          json["file"]=json_stringt(id2string(i_it->source_location.get_file()));
          json["line"]=json_numbert(id2string(i_it->source_location.get_line()));
          json_result.array.push_back(json);
        }
        else
        {
          std::cout << i_it->source_location;
          if(!i_it->source_location.get_comment().empty())
            std::cout << ": " << i_it->source_location.get_comment();
            
          if(!i_it->source_location.get_property_class().empty())
            std::cout << " (" << i_it->source_location.get_property_class() << ")";

          std::cout << '\n';
        }
      }
    }
    
    if(use_json)
    {
      std::ofstream json_out(json_file_name);

      if(!json_out)
      {
        error() << "Failed to open json output `"
                << json_file_name << "'" << eom;
        return true;
      }
      
      status() << "Analysis result is written to `"
               << json_file_name << "'" << eom;
      
      json_out << json_result << '\n';
    }
  
    return false;
  }
  catch(const char *error_msg)
  {
    error() << error_msg << eom;
    return true;
  }
  catch(const std::string &error_msg)
  {
    error() << error_msg << eom;
    return true;
  }
  catch(...)
  {
    return true;
  }
}

/*******************************************************************\

Function: taint_analysis

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool taint_analysis(
  goto_modelt &goto_model,
  const std::string &taint_file_name,
  message_handlert &message_handler,
  bool show_full,
  const std::string &json_file_name,
  const std::string &summaries_directory)
{
  taint_analysist taint_analysis;
  taint_analysis.set_message_handler(message_handler);
  return taint_analysis(
    taint_file_name, goto_model.symbol_table, goto_model.goto_functions,
    show_full, json_file_name, summaries_directory);
}

std::string  taint_analysis_instrument_knowledge(
  goto_modelt&  model,
  std::string const&  taint_file_name,
  message_handlert&  logger
  )
{
  struct taint_analysis_accessor_t : public taint_analysist {
    taint_parse_treet& get_taint() { return taint; }
    class_hierarchyt& get_class_hierarchy() { return class_hierarchy; }
    void instrument(namespacet const&  ns, goto_functionst& fns) {
      taint_analysist::instrument(ns,fns);
    }
  };
  taint_analysis_accessor_t  analysis;
  analysis.set_message_handler(logger);
  if (taint_parser(taint_file_name, analysis.get_taint(), logger) == true)
    return "Failed to read taint definition file";
  analysis.get_class_hierarchy()(model.symbol_table);
  analysis.instrument(namespacet(model.symbol_table), model.goto_functions);
  model.goto_functions.update();
  return ""; // Success
}
