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

#include <summaries/utility.h>
#include <util/symbol.h>
#include <util/std_expr.h>

namespace sumfn {


bool  is_identifier(access_path_to_memoryt const&  lvalue)
{
  return lvalue.id() == ID_symbol;
}


std::string  name_of_symbol_access_path(access_path_to_memoryt const&  lvalue)
{
  return is_identifier(lvalue) ?
              as_string(to_symbol_expr(lvalue).get_identifier()) :
              "";
}


bool  is_parameter(access_path_to_memoryt const&  lvalue, namespacet const&  ns)
{
  if (is_identifier(lvalue))
  {
    symbolt const*  symbol = nullptr;
    ns.lookup(name_of_symbol_access_path(lvalue),symbol);
    return symbol != nullptr && symbol->is_parameter;
  }
  return false;
}

bool  is_static(access_path_to_memoryt const&  lvalue, namespacet const&  ns)
{
  if (is_identifier(lvalue))
  {
    symbolt const*  symbol = nullptr;
    ns.lookup(name_of_symbol_access_path(lvalue),symbol);
    return symbol != nullptr && symbol->is_static_lifetime;
  }
  else if (lvalue.id() == ID_member)
  {
  }
  return false;
}

bool  is_return_value_auxiliary(access_path_to_memoryt const&  lvalue,
                                namespacet const&  ns)
{
  if (is_identifier(lvalue))
  {
    irep_idt const&  name = name_of_symbol_access_path(lvalue);
    symbolt const*  symbol = nullptr;
    ns.lookup(name,symbol);
    return symbol != nullptr &&
           symbol->is_static_lifetime &&
           symbol->is_auxiliary &&
           symbol->is_file_local &&
           symbol->is_thread_local &&
           as_string(name).find("#return_value") != std::string::npos
           ;
  }
  return false;
}

bool  is_pure_local(access_path_to_memoryt const&  lvalue,
                    namespacet const&  ns)
{
  return lvalue.id() != ID_member &&
         !is_parameter(lvalue,ns) &&
         !is_static(lvalue,ns)
         ;
}


access_path_to_memoryt  scope_translation(
    access_path_to_memoryt const&  source_path,
    irep_idt const&  source_scope_id,
    irep_idt const&  target_scope_id
    //,    goto_modelt const&  program
    )
{
  ////std::string const  key = "((struct Sum01 *)(void *)this)->L";
  ////auto const  xxit = a.find(lvalue_svalue.first);
  //std::cout << "*****************************************************\n";
  //std::cout << "lvalue_svalue.first = ";
  //dump_lvalue_in_html(lvalue_svalue.first,ns,std::cout);
  //std::cout << "\n";
  //sumfn::detail::dump_irept(lvalue_svalue.first,std::cout);
  //std::cout << "\n";
  //for (auto  it = a.cbegin(); it != a.cend(); ++it)
  //{
  //std::cout << "it->first = ";
  //dump_lvalue_in_html(it->first,ns,std::cout);
  //std::cout << "\n";
  //sumfn::detail::dump_irept(it->first,std::cout);
  //std::cout << "\n";
  //std::cout.flush();
  ////  std::cout << (irep_full_eq()(lvalue_svalue.first,it->first)) << "\n";
  ////  std::cout << (irep_eq()(lvalue_svalue.first,it->first)) << "\n";
  ////  std::cout << (lvalue_svalue.first == it->first) << "\n";
  //}
  ////std::cout << (lvalue_svalue.first.compare(it->second)) << "\n";
  ////std::cout << "lvalue1 = " << lvalue_svalue.first << "\n";
  ////std::cout << "lvalue2 = " << it->second << "\n";
  //std::cout.flush();

  return source_path;
}




}
