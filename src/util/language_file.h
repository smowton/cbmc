/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/


#ifndef CPROVER_UTIL_LANGUAGE_FILE_H
#define CPROVER_UTIL_LANGUAGE_FILE_H

#include <iosfwd>
#include <set>
#include <map>
#include <string>
#include <memory> // unique_ptr

#include "message.h"
#include "symbol_table.h"

class language_filet;
class languaget;

class language_modulet final
{
public:
  std::string name;
  bool type_checked, in_progress;
  language_filet *file;

  language_modulet():
    type_checked(false),
    in_progress(false),
    file(nullptr)
  {}
};

class language_filet final
{
public:
  typedef std::set<std::string> modulest;
  modulest modules;

  std::unique_ptr<languaget> language;
  std::string filename;

  void get_modules();

  void convert_lazy_method(
    const irep_idt &id,
    symbol_tablet &symbol_table);

  language_filet();
  language_filet(const language_filet &rhs);

  ~language_filet();
};

class language_filest:public messaget
{
public:
  typedef std::map<std::string, language_filet> file_mapt;
  file_mapt file_map;

  // Contains pointers into file_mapt!
  typedef std::map<std::string, language_modulet> module_mapt;
  module_mapt module_map;

  // Contains pointers into filemapt!
  // This is safe-ish as long as this is std::map.
  typedef std::map<irep_idt, language_filet *> lazy_method_mapt;
  lazy_method_mapt lazy_method_map;

  void clear_files()
  {
    file_map.clear();
  }

  void set_should_generate_opaque_method_stubs(bool stubs_enabled);

  bool parse();

  void show_parse(std::ostream &out);

  bool generate_support_functions(symbol_tablet &symbol_table);

  bool typecheck(symbol_tablet &symbol_table);

  bool final(symbol_table_baset &symbol_table);

  bool interfaces(symbol_tablet &symbol_table);

  // The method must have been added to the symbol table and registered
  // in lazy_method_map (currently always in language_filest::typecheck)
  // for this to be legal.
  void convert_lazy_method(
    const irep_idt &id,
    symbol_tablet &symbol_table)
  {
    PRECONDITION(symbol_table.symbols.count(id) != 0);
    lazy_method_mapt::iterator it=lazy_method_map.find(id);
    if(it!=lazy_method_map.end())
      it->second->convert_lazy_method(id, symbol_table);
  }

  void clear()
  {
    file_map.clear();
    module_map.clear();
    lazy_method_map.clear();
  }

protected:
  bool typecheck_module(
    symbol_tablet &symbol_table,
    language_modulet &module);

  bool typecheck_module(
    symbol_tablet &symbol_table,
    const std::string &module);
};

#endif // CPROVER_UTIL_LANGUAGE_FILE_H
