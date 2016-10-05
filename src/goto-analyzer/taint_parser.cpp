/*******************************************************************\

Module: Taint Parser

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#include <ostream>

#include <util/string2int.h>

#include <json/json_parser.h>

#include "taint_parser.h"

/*******************************************************************\

Function: taint_parser

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool taint_parser(
  const std::string &file_name,
  taint_parse_treet &dest,
  message_handlert &message_handler)
{
  jsont json;
  messaget message(message_handler);

  if(parse_json(file_name, message_handler, json))
  {
    message.error() << "taint file is not a valid json file"
                    << messaget::eom;
    return true;
  }

  if(!json.is_array())
  {
    message.error() << "expecting an array in the taint file, but got "
                    << json << messaget::eom;
    return true;
  }
  
  for(jsont::arrayt::const_iterator
      it=json.array.begin();
      it!=json.array.end();
      it++)
  {
    if(!it->is_object())
    {
      message.error() << "expecting an array of objects in the taint file, but got "
                      << *it << messaget::eom;
      return true;
    }
    
    taint_parse_treet::rulet rule;
    
    const std::string kind=(*it)["kind"].value;
    const std::string function=(*it)["function"].value;
    const std::string where=(*it)["where"].value;
    const std::string taint=(*it)["taint"].value;
    const std::string taint_message=(*it)["message"].value;
    const std::string id=(*it)["id"].value;
    const auto& immediate=(*it)["immediate"];
    
    if(kind=="source")
      rule.kind=taint_parse_treet::rulet::SOURCE;
    else if(kind=="sink")
      rule.kind=taint_parse_treet::rulet::SINK;
    else if(kind=="sanitizer")
      rule.kind=taint_parse_treet::rulet::SANITIZER;
    else
    {
      message.error() << "taint rule must have \"kind\" which is "
                         "\"source\" or \"sink\" or \"sanitizer\""
                      << messaget::eom;
      return true;
    }
    
    if(function.empty())
    {
      message.error() << "taint rule must have \"function\""
                      << messaget::eom;
      return true;
    }
    else
      rule.function_identifier=function;

    if(where=="return_value")
    {
      rule.where=taint_parse_treet::rulet::RETURN_VALUE;
    }
    else if(where=="this")
    {
      rule.where=taint_parse_treet::rulet::THIS;
    }
    else if(std::string(where, 0, 9)=="parameter")
    {
      rule.where=taint_parse_treet::rulet::PARAMETER;
      rule.parameter_number=
        safe_string2unsigned(std::string(where, 9, std::string::npos));
    }
    else
    {
      message.error() << "taint rule must have \"where\""
                      << " which is \"return_value\" or \"this\" or \"parameter1\"..."
                      << messaget::eom;
      return true;
    }

    if(immediate.is_null() || immediate.is_false())
      rule.immediate=false;
    else if(immediate.is_true())
      rule.immediate=true;
    else
    {
      message.error() << "\"immediate\" must be a boolean" << messaget::eom;
      return true;
    }
    
    rule.taint=taint;
    rule.message=taint_message;
    rule.id=id;
    
    dest.rules.push_back(rule);
  }
  
  return false;
}

/*******************************************************************\

Function: taint_parse_treet::rulet::output

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void taint_parse_treet::rulet::output(std::ostream &out) const
{
  if(!id.empty()) out << id << ": ";

  switch(kind)
  {
  case SOURCE: out << "SOURCE "; break;
  case SINK: out << "SINK "; break;
  case SANITIZER: out << "SANITIZER "; break;
  }
  
  out << taint << " on ";
  
  switch(where)
  {
  case THIS: out << "this in " << function_identifier; break;
  case PARAMETER: out << "parameter " << parameter_number << " of " << function_identifier; break;
  case RETURN_VALUE: out << "return value of " << function_identifier; break;
  }
  
  out << '\n';
}

/*******************************************************************\

Function: taint_parse_treet::output

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void taint_parse_treet::output(std::ostream &out) const
{
  for(const auto & rule : rules)
    rule.output(out);
}

