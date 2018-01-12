/*******************************************************************\

 Module: Unit test utilities

 Author: DiffBlue Limited. All rights reserved.

\*******************************************************************/

#include "load_java_class.h"
#include <testing-utils/catch.hpp>
#include <iostream>

#include <util/config.h>
#include <util/language.h>
#include <util/options.h>
#include <util/suffix.h>

#include <goto-programs/lazy_goto_model.h>

#include <java_bytecode/java_bytecode_language.h>

/// Go through the process of loading, type-checking and finalising loading a
/// specific class file to build the symbol table.
/// \param java_class_name: The name of the class file to load. It should not
///   include the .class extension.
/// \param class_path: The path to load the class from. Should be relative to
///   the unit directory.
/// \param main: The name of the main function or "" to use the default
///   behaviour to find a main function.
/// \return The symbol table that is generated by parsing this file.
symbol_tablet load_java_class(
  const std::string &java_class_name,
  const std::string &class_path,
  const std::string &main)
{
  return load_java_class(
    java_class_name, class_path, main, new_java_bytecode_language());
}

/// Go through the process of loading, type-checking and finalising loading a
/// specific class file to build the symbol table.
/// \param java_class_name: The name of the class file to load. It should not
///   include the .class extension.
/// \param class_path: The path to load the class from. Should be relative to
///   the unit directory.
/// \param main: The name of the main function or "" to use the default
///   behaviour to find a main function.
/// \param java_lang: The language implementation to use for the loading,
///   which will be destroyed by this function.
/// \return The symbol table that is generated by parsing this file.
symbol_tablet load_java_class(
  const std::string &java_class_name,
  const std::string &class_path,
  const std::string &main,
  std::unique_ptr<languaget> &&java_lang)
{
  // We expect the name of the class without the .class suffix to allow us to
  // check it
  PRECONDITION(!has_suffix(java_class_name, ".class"));
  std::string filename=java_class_name + ".class";

  // Construct a lazy_goto_modelt
  null_message_handlert message_handler;
  lazy_goto_modelt lazy_goto_model(
    [] (goto_model_functiont &function)
    { },
    [] (goto_modelt &goto_model)
    { return false; },
    message_handler);

  // Configure the path loading
  cmdlinet command_line;
  command_line.set("java-cp-include-files", class_path);
  config.java.classpath.clear();
  config.java.classpath.push_back(class_path);
  config.main = main;

  // Add the language to the model
  language_filet &lf=lazy_goto_model.add_language_file(filename);
  lf.language=std::move(java_lang);
  languaget &language=*lf.language;

  std::istringstream java_code_stream("ignored");

  // Configure the language, load the class files
  language.set_message_handler(message_handler);
  language.get_language_options(command_line);
  language.parse(java_code_stream, filename);
  language.typecheck(lazy_goto_model.symbol_table, "");
  language.generate_support_functions(lazy_goto_model.symbol_table);
  language.final(lazy_goto_model.symbol_table);

  lazy_goto_model.load_all_functions();

  std::unique_ptr<goto_modelt> maybe_goto_model=
    lazy_goto_modelt::process_whole_model_and_freeze(
      std::move(lazy_goto_model));
  INVARIANT(maybe_goto_model, "Freezing lazy_goto_model failed");

  // Verify that the class was loaded
  const std::string class_symbol_name="java::"+java_class_name;
  REQUIRE(maybe_goto_model->symbol_table.has_symbol(class_symbol_name));
  const symbolt &class_symbol=
    *maybe_goto_model->symbol_table.lookup(class_symbol_name);
  REQUIRE(class_symbol.is_type);
  const typet &class_type=class_symbol.type;
  REQUIRE(class_type.id()==ID_struct);

  // if this fails it indicates the class was not loaded
  // Check your working directory and the class path is correctly configured
  // as this often indicates that one of these is wrong.
  REQUIRE_FALSE(class_type.get_bool(ID_incomplete_class));
  return std::move(maybe_goto_model->symbol_table);
}
