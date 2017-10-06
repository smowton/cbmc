// Copyright 2016-2017 Diffblue Limited. All Rights Reserved.

#include "symbol_table.h"

#include <ostream>
#include <algorithm>
#include <util/invariant.h>


/// Find a symbol in the symbol table.
/// \param identifier: The name of the symbol to look for
/// \return Returns an optional reference to the found symbol, without a value
///   if a symbol with the given name does not exist in the symbol table
symbol_tablet::opt_const_symbol_reft symbol_tablet::lookup(
  const irep_idt &identifier) const
{
  symbolst::const_iterator it=symbols.find(identifier);
  if(it==symbols.end())
    return opt_const_symbol_reft();
  return std::cref(it->second);
}

/// Add a new symbol to the symbol table
/// \param symbol: The symbol to be added to the symbol table
/// \return Returns true if the process failed, which should only happen if
///   there is a symbol with the same name already in the symbol table.
bool symbol_tablet::add(const symbolt &symbol)
{
  return !insert(symbol).second;
}

/// Move a symbol into the symbol table. If there is already a symbol with the
/// same name then symbol is unchanged, new_symbol points to the symbol with the
/// same name and true is returned. Otherwise, the symbol is moved into the
/// symbol table, symbol is destroyed, new_symbol points to its new
/// location in the symbol table and false is returned
/// \param symbol: The symbol to be added to the symbol table
/// \param new_symbol: Pointer which the function will set to either point to
///   the symbol in the symbol table with the same name or to the symbol that
///   has been successfully moved into the symbol table
/// \return Returns a boolean indicating whether the process failed, which
///   should only happen if there is a symbol with the same name already in the
///   symbol table. If the process failed then symbol is unchanged and
///   new_symbol points to the symbol with the same name. If the process
///   succeeded symbol is set to be empty and new_symbol points to its new
///   location in the symbol table
bool symbol_tablet::move(symbolt &symbol, symbolt *&new_symbol)
{
  // Add an empty symbol to the table or retrieve existing symbol with same name
  symbolt temp_symbol;
  // This is not copying the symbol, this is passing the three required
  // parameters to insert (just in the symbol)
  temp_symbol.name=symbol.name;
  temp_symbol.base_name=symbol.base_name;
  temp_symbol.module=symbol.module;
  std::pair<symbolt &, bool> result=insert(std::move(temp_symbol));
  if(result.second)
  {
    // Move the provided symbol into the symbol table, this can't be done
    // earlier
    result.first.swap(symbol);
  }
  // Return the address of the symbol in the table
  new_symbol=&result.first;
  return !result.second;
}

/// Remove a symbol from the symbol table
/// \param name: The name of the symbol to remove
/// \return Returns a boolean indicating whether the process failed
bool symbol_tablet::remove(const irep_idt &name)
{
  symbolst::const_iterator entry=symbols.find(name);
  if(entry==symbols.end())
    return true;
  erase(entry);
  return false;
}

/// Print the contents of the symbol table
/// \param out: The ostream to direct output to
void symbol_tablet::show(std::ostream &out) const
{
  std::vector<irep_idt> sorted_names;
  sorted_names.reserve(symbols.size());
  for(const auto &elem : symbols)
    sorted_names.push_back(elem.first);
  std::sort(
    sorted_names.begin(),
    sorted_names.end(),
    [](const irep_idt &a, const irep_idt &b)
    { return as_string(a)<as_string(b); });
  out << "\n" << "Symbols:" << "\n";
  for(const auto &name : sorted_names)
    out << symbols.at(name);
}

/// Print the contents of the symbol table
/// \param out: The ostream to direct output to
/// \param symbol_table: The symbol table to print out
std::ostream &operator<<(std::ostream &out, const symbol_tablet &symbol_table)
{
  symbol_table.show(out);
  return out;
}


/// Find a symbol in the symbol table.
/// \param identifier: The name of the symbol to look for
/// \return Returns an optional reference to the found symbol, without a value
///   if a symbol with the given name does not exist in the symbol table
symbol_tablet::opt_symbol_reft concrete_symbol_tablet::get_writeable(
  const irep_idt &identifier)
{
  symbolst::iterator it=internal_symbols.find(identifier);
  if(it==symbols.end())
    return opt_symbol_reft();
  return std::ref(it->second);
}

std::pair<symbolt &, bool> concrete_symbol_tablet::insert(symbolt symbol)
{
  // Add the symbol to the table or retrieve existing symbol with the same name
  std::pair<symbolst::iterator, bool> result=
    internal_symbols.emplace(symbol.name, std::move(symbol));
  symbolt &new_symbol=result.first->second;
  if(result.second)
  {
    try
    {
      symbol_base_mapt::iterator base_result=
        internal_symbol_base_map.emplace(new_symbol.base_name, new_symbol.name);
      try
      {
        internal_symbol_module_map.emplace(new_symbol.module, new_symbol.name);
      }
      catch(...)
      {
        internal_symbol_base_map.erase(base_result);
        throw;
      }
    }
    catch(...)
    {
      internal_symbols.erase(result.first);
      throw;
    }
  }
  return std::make_pair(std::ref(new_symbol), result.second);
}

void concrete_symbol_tablet::erase(const symbolst::const_iterator &entry)
{
  const symbolt &symbol=entry->second;

  symbol_base_mapt::const_iterator
    base_it=symbol_base_map.lower_bound(entry->second.base_name);
  symbol_base_mapt::const_iterator
    base_it_end=symbol_base_map.upper_bound(entry->second.base_name);
  while(base_it!=base_it_end && base_it->second!=symbol.name)
    ++base_it;
  INVARIANT(
    base_it!=base_it_end,
    "symbolt::base_name should not be changed "
    "after it is added to the symbol_table "
    "(name: "+id2string(symbol.name)+", "
    "current base_name: "+id2string(symbol.base_name)+")");
  internal_symbol_base_map.erase(base_it);

  symbol_module_mapt::const_iterator
    module_it=symbol_module_map.lower_bound(entry->second.module),
    module_it_end=symbol_module_map.upper_bound(entry->second.module);
  while(module_it!=module_it_end && module_it->second!=symbol.name)
    ++module_it;
  INVARIANT(
    module_it!=module_it_end,
    "symbolt::module should not be changed "
    "after it is added to the symbol_table "
    "(name: "+id2string(symbol.name)+", "
    "current module: "+id2string(symbol.module)+")");
  internal_symbol_module_map.erase(module_it);

  internal_symbols.erase(entry);
}
