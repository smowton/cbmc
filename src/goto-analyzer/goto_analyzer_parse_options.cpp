/*******************************************************************\

Module: Goto-Analyser Command Line Option Processing

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#include <cstdlib> // exit()
#include <iostream>
#include <fstream>
#include <memory>

#include <ansi-c/ansi_c_language.h>
#include <cpp/cpp_language.h>
#include <java_bytecode/java_bytecode_language.h>
#include <jsil/jsil_language.h>

#include <json/json_parser.h>

#include <goto-programs/set_properties.h>
#include <goto-programs/remove_function_pointers.h>
#include <goto-programs/remove_virtual_functions.h>
#include <goto-programs/remove_instanceof.h>
#include <goto-programs/remove_returns.h>
#include <goto-programs/remove_vector.h>
#include <goto-programs/remove_complex.h>
#include <goto-programs/remove_asm.h>
#include <goto-programs/goto_convert_functions.h>
#include <goto-programs/show_properties.h>
#include <goto-programs/show_symbol_table.h>
#include <goto-programs/read_goto_binary.h>
#include <goto-programs/goto_inline.h>
#include <goto-programs/link_to_library.h>

#include <analyses/goto_check.h>
#include <analyses/local_may_alias.h>

#include <pointer-analysis/show_value_sets.h>

#include <langapi/mode.h>

#include <util/language.h>
#include <util/options.h>
#include <util/config.h>
#include <util/string2int.h>
#include <util/unicode.h>
#include <util/file_util.h>
#include <util/msgstream.h>
#include <util/prefix.h>

#include <cbmc/version.h>

#include <summaries/summary.h>
#include <goto-analyzer/pointsto_temp_analyser.h>
#include <goto-analyzer/pointsto_temp_summary_dump.h>
#include <goto-analyzer/taint_summary.h>
#include <goto-analyzer/taint_summary_dump.h>
#include <goto-analyzer/taint_summary_json.h>
#include <goto-analyzer/taint_planner.h>
#include <goto-analyzer/taint_planner_dump.h>
#include <goto-analyzer/taint_trace_recogniser.h>
#include <goto-analyzer/taint_trace_dump.h>

#include "goto_analyzer_parse_options.h"
#include "taint_analysis.h"
#include "unreachable_instructions.h"
#include "static_analyzer.h"

/*******************************************************************\

Function: goto_analyzer_parse_optionst::goto_analyzer_parse_optionst

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

goto_analyzer_parse_optionst::goto_analyzer_parse_optionst(int argc, const char **argv):
  parse_options_baset(GOTO_ANALYSER_OPTIONS, argc, argv),
  language_uit(cmdline, ui_message_handler),
  ui_message_handler(cmdline, "GOTO-ANALYZER " CBMC_VERSION)
{
}
  
/*******************************************************************\

Function: goto_analyzer_parse_optionst::register_languages

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void goto_analyzer_parse_optionst::register_languages()
{
  register_language(new_ansi_c_language);
  register_language(new_cpp_language);
  register_language(new_java_bytecode_language);
  register_language(new_jsil_language);
}

/*******************************************************************\

Function: goto_analyzer_parse_optionst::eval_verbosity

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void goto_analyzer_parse_optionst::eval_verbosity()
{
  // this is our default verbosity
  unsigned int v=messaget::M_STATISTICS;
  
  if(cmdline.isset("verbosity"))
  {
    v=unsafe_string2unsigned(cmdline.get_value("verbosity"));
    if(v>10) v=10;
  }
  
  ui_message_handler.set_verbosity(v);
}

/*******************************************************************\

Function: goto_analyzer_parse_optionst::get_command_line_options

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void goto_analyzer_parse_optionst::get_command_line_options(optionst &options)
{
  if(config.set(cmdline))
  {
    usage_error();
    exit(1);
  }

  #if 0
  if(cmdline.isset("c89"))
    config.ansi_c.set_c89();

  if(cmdline.isset("c99"))
    config.ansi_c.set_c99();

  if(cmdline.isset("c11"))
    config.ansi_c.set_c11();

  if(cmdline.isset("cpp98"))
    config.cpp.set_cpp98();

  if(cmdline.isset("cpp03"))
    config.cpp.set_cpp03();

  if(cmdline.isset("cpp11"))
    config.cpp.set_cpp11();
  #endif

  #if 0
  // check array bounds
  if(cmdline.isset("bounds-check"))
    options.set_option("bounds-check", true);
  else
    options.set_option("bounds-check", false);

  // check division by zero
  if(cmdline.isset("div-by-zero-check"))
    options.set_option("div-by-zero-check", true);
  else
    options.set_option("div-by-zero-check", false);

  // check overflow/underflow
  if(cmdline.isset("signed-overflow-check"))
    options.set_option("signed-overflow-check", true);
  else
    options.set_option("signed-overflow-check", false);

  // check overflow/underflow
  if(cmdline.isset("unsigned-overflow-check"))
    options.set_option("unsigned-overflow-check", true);
  else
    options.set_option("unsigned-overflow-check", false);

  // check overflow/underflow
  if(cmdline.isset("float-overflow-check"))
    options.set_option("float-overflow-check", true);
  else
    options.set_option("float-overflow-check", false);

  // check for NaN (not a number)
  if(cmdline.isset("nan-check"))
    options.set_option("nan-check", true);
  else
    options.set_option("nan-check", false);

  // check pointers
  if(cmdline.isset("pointer-check"))
    options.set_option("pointer-check", true);
  else
    options.set_option("pointer-check", false);

  // check for memory leaks
  if(cmdline.isset("memory-leak-check"))
    options.set_option("memory-leak-check", true);
  else
    options.set_option("memory-leak-check", false);

  // check assertions
  if(cmdline.isset("no-assertions"))
    options.set_option("assertions", false);
  else
    options.set_option("assertions", true);

  // use assumptions
  if(cmdline.isset("no-assumptions"))
    options.set_option("assumptions", false);
  else
    options.set_option("assumptions", true);

  // magic error label
  if(cmdline.isset("error-label"))
    options.set_option("error-label", cmdline.get_values("error-label"));
  #endif
}


int  run_pointsto_temp_analyser(
  goto_modelt&  program,
  cmdlinet const&  cmdline,
  message_handlert&  message_handler)
{
  try
  {
    std::stringstream  log;
    const call_grapht call_graph(program.goto_functions);
    database_of_summariest  summaries;

    pointsto_temp_summarise_all_functions(
          program,
          summaries,
          call_graph,
          &log
          );

    dump_in_html(
          summaries,
          &pointsto_temp_summary_dump_in_html,
          program,
          call_graph,
          "./dump_pointsto_temp_summaries",
          cmdline.isset("taint-dump-program"),
          cmdline.isset("taint-dump-log") ? &log : nullptr
          );
  }
  catch (const std::exception& e)
  {
    message_handler.print(message_clientt::M_ERROR,
          msgstream() << "EXCEPTION: " << e.what()
          );
    return 0;
  }

  return 1;
}


/*******************************************************************\

Function: do_taint_analysis

  Inputs: The program to be analysed and the command line options.

 Outputs: Status value of the result (1 success, 0 fail).

 Purpose:

It performs the whole taint analysis. The planner has already read the initial plan.

\*******************************************************************/
int  do_taint_analysis(
  goto_modelt&  program,
  jsont& plan,
  cmdlinet const&  cmdline,
  message_handlert&  message_handler)
{
  try
  {
    taint_plannert planner(program,plan,message_handler);
    
    std::stringstream  log;
    const call_grapht call_graph(program.goto_functions);

    while (true)
    {
      auto const  old_num_precision_levels =
          planner.get_precision_levels().size();

      const std::string error_message =
        planner.solve_top_precision_level(program,call_graph,&log);
      if (!error_message.empty())
      {
        message_handler.print(message_clientt::M_ERROR,
              msgstream() << "ERROR: " << error_message
              );
        return 0;
      }

      if (old_num_precision_levels == planner.get_precision_levels().size())
        break;
    }

    taint_dump_taint_planner_in_html(
          planner,
          program,
          namespacet(program.symbol_table),
          "./dump_taint_planner"
          );

    dump_in_html(
          *planner.get_top_precision_level()->get_summary_database(),
          &taint_dump_in_html,
          program,
          call_graph,
          "./dump_top_taint_summaries",
          cmdline.isset("taint-dump-program"),
          cmdline.isset("taint-dump-log") ? &log : nullptr
          );

  }
  catch (const std::exception& e)
  {
    message_handler.print(message_clientt::M_ERROR,
          msgstream() << "EXCEPTION: " << e.what()
          );
    return 0;
  }

  return 1;
}

/*******************************************************************\

Function: goto_analyzer_parse_optionst::doit

  Inputs:

 Outputs:

 Purpose: invoke main modules

\*******************************************************************/

int goto_analyzer_parse_optionst::doit()
{
  if(cmdline.isset("version"))
  {
    std::cout << CBMC_VERSION << std::endl;
    return 0;
  }

  //
  // command line options
  //

  optionst options;
  get_command_line_options(options);
  eval_verbosity();

  //
  // Print a banner
  //
  status() << "GOTO-ANALYSER version " CBMC_VERSION " "
           << sizeof(void *)*8 << "-bit "
           << config.this_architecture() << " "
           << config.this_operating_system() << eom;

  register_languages();
  
  goto_model.set_message_handler(get_message_handler());

  // Hack for entry point set in a taint-analysis plan (must set 'main' before
  // main frontend parsers are run)
  jsont taint_analysis_plan;
  if(cmdline.isset("taint-analysis"))
  {
    parse_json(cmdline.get_value("taint-analysis"), get_message_handler(), taint_analysis_plan);
    auto entry_point=taint_plannert::get_unique_entry_point(taint_analysis_plan);
    const std::string java_prefix="java::";
    if(has_prefix(entry_point,java_prefix))
      entry_point=entry_point.substr(java_prefix.size());
    cmdline.set("function",entry_point);
    config.main=entry_point;
  }

  if(goto_model(cmdline.args))
    return 6;
    
  if(process_goto_program(options))
    return 6;

  if (cmdline.isset("run-pointsto-temp-analyser"))
    return run_pointsto_temp_analyser(goto_model,cmdline,get_message_handler());
  else if (cmdline.isset("taint-analysis"))
    return do_taint_analysis(goto_model,taint_analysis_plan,cmdline,
                             get_message_handler());
  else if(cmdline.isset("taint"))
  {
    std::string taint_file=cmdline.get_value("taint");
    std::string summary_directory=cmdline.get_value("taint-use-summaries");

    if(cmdline.isset("show-taint"))
    {
      taint_analysis(goto_model, taint_file, get_message_handler(), true, "", summary_directory);
      return 0;
    }
    else if (cmdline.isset("summary-only"))
    {
      taint_sources_mapt  taint_sources;
      taint_sinks_mapt  taint_sinks;

      taint_analysis_instrument_knowledge(
          goto_model,
          taint_file,
          get_message_handler(),
          taint_sources,
          taint_sinks
          );
      std::stringstream  log;
      std::string json_directory=cmdline.get_value("json");
      std::string lvsa_json_directory=cmdline.get_value("lvsa-summary-directory");
      local_value_set_analysist::dbt lvsa_database(lvsa_json_directory);
      summary_json_databaset<taint_summaryt> summaries(json_directory);
      std::string fname=cmdline.get_value("function");
      call_grapht const  call_graph(goto_model.goto_functions);

      local_value_set_analysist::dbt* lvsa_database_ptr = 
          cmdline.isset("taint-no-aa") ? nullptr : &lvsa_database;

      if(fname=="")
      {
        taint_summarise_all_functions(
              goto_model,
              summaries,
              call_graph,
              cmdline.isset("taint-dump-log") ? &log : nullptr,
              lvsa_database_ptr,
              get_message_handler()
              );
      }
      else
      {
        auto ret=taint_summarise_function(
              fname,
              goto_model,
              summaries,
              cmdline.isset("taint-dump-log") ? &log : nullptr,
              lvsa_database_ptr,
              get_message_handler()
              );
        summaries.insert(std::make_pair(fname,ret));
      }

      std::vector<taint_tracet>  error_traces;
      taint_recognise_error_traces(
            error_traces,
            goto_model,
            call_graph,
            summaries,
            taint_sources,
            taint_sinks,
            cmdline.isset("taint-dump-log") ? &log : nullptr
            );

      if(json_directory=="")
      {
        if (cmdline.isset("taint-dump-html-summaries"))
          dump_in_html(
              summaries,
              &taint_dump_in_html,
              static_cast<goto_modelt const&>(goto_model),
              call_graph,
              "./dump_taint_summaries",
              cmdline.isset("taint-dump-program"),
              cmdline.isset("taint-dump-log") ? &log : nullptr
              );

        if (cmdline.isset("taint-dump-html-traces"))
          taint_dump_traces_in_html(
              error_traces,
              static_cast<goto_modelt const&>(goto_model),
              "./dump_taint_traces_html"
              );

        taint_dump_traces_in_json(
            error_traces,
            static_cast<goto_modelt const&>(goto_model),
            "./dump_taint_traces_json"
            );
      }
      else
      {
        summaries.save_all();
      }
    }
    else
    {
      std::string json_file=cmdline.get_value("json");
      bool result=
        taint_analysis(goto_model, taint_file, get_message_handler(), false, json_file, summary_directory);
      return result?10:0;
    }
  }

  if(cmdline.isset("local-value-set-analysis"))
  {
    const auto& dbpath=cmdline.get_value("lvsa-summary-directory");
    if(dbpath=="")
    {
      error() << "Must specify lvsa-summary-directory";
      abort();
    }
    
    local_value_set_analysist::dbt summarydb(dbpath);
    namespacet ns(goto_model.symbol_table);
    if(cmdline.isset("lvsa-function"))
    {
      const auto& fname=cmdline.get_value("lvsa-function");
      const auto& gf=goto_model.goto_functions.function_map.at(fname);
      local_value_set_analysist value_set_analysis(
        ns,gf.type,fname,summarydb,LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET);
      value_set_analysis.set_message_handler(get_message_handler());
      value_set_analysis(gf.body);
      show_value_sets(get_ui(), gf.body, value_set_analysis);
      if(dbpath.size()!=0)
        value_set_analysis.save_summary(gf.body);
    }
    else {
      call_grapht const call_graph(goto_model.goto_functions);
      std::vector<irep_idt> process_order;
      get_inverted_topological_order(call_graph,goto_model.goto_functions,process_order);
      size_t total_funcs=process_order.size();
      size_t processed=0;
      for(const auto& fname : process_order)
      {
	++processed;
	if(fname=="_start")
	  continue;
        debug() << "LVSA: analysing " << fname << eom;
        const auto& gf=goto_model.goto_functions.function_map.at(fname);
        if(!gf.body_available())
          continue;
        local_value_set_analysist value_set_analysis(
          ns,gf.type,id2string(fname),summarydb,LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET);
        value_set_analysis.set_message_handler(get_message_handler());
        value_set_analysis(gf.body);
	if(ui_message_handler.get_verbosity()>=message_clientt::M_DEBUG)
	  show_value_sets(get_ui(), gf.body, value_set_analysis);
	else
	  progress() << processed << "/" << total_funcs << " functions analysed" << eom;
        if(dbpath.size()!=0)
          value_set_analysis.save_summary(gf.body);
      }
    }
    return 0;
  }

  if(cmdline.isset("unreachable-instructions"))
  {
    const std::string json_file=cmdline.get_value("json");

    if(json_file.empty())
      unreachable_instructions(goto_model, false, std::cout);
    else if(json_file=="-")
      unreachable_instructions(goto_model, true, std::cout);
    else
    {
      std::ofstream ofs(json_file);
      if(!ofs)
      {
        error() << "Failed to open json output `"
                << json_file << "'" << eom;
        return 6;
      }

      unreachable_instructions(goto_model, true, ofs);
    }

    return 0;
  }

  if(cmdline.isset("show-local-may-alias"))
  {
    namespacet ns(goto_model.symbol_table);
  
    forall_goto_functions(it, goto_model.goto_functions)
    {
      std::cout << ">>>>\n";
      std::cout << ">>>> " << it->first << '\n';
      std::cout << ">>>>\n";
      local_may_aliast local_may_alias(it->second);
      local_may_alias.output(std::cout, it->second, ns);
      std::cout << '\n';
    }

    return 0;
  }

  label_properties(goto_model);

  if(cmdline.isset("show-properties"))
  {
    show_properties(goto_model, get_ui());
    return 0;
  }

  if(set_properties())
    return 7;
  
  if(cmdline.isset("show-intervals"))
  {
    show_intervals(goto_model, std::cout);
    return 0;
  }

  if(cmdline.isset("non-null") ||
     cmdline.isset("intervals"))
  {
    optionst options;
    options.set_option("json", cmdline.get_value("json"));
    options.set_option("xml", cmdline.get_value("xml"));
    bool result=
      static_analyzer(goto_model, options, get_message_handler());
    return result?10:0;
  }

  error() << "no analysis option given -- consider reading --help"
          << eom;
  return 6;
}

/*******************************************************************\

Function: goto_analyzer_parse_optionst::set_properties

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool goto_analyzer_parse_optionst::set_properties()
{
  try
  {
    if(cmdline.isset("property"))
      ::set_properties(goto_model, cmdline.get_values("property"));
  }

  catch(const char *e)
  {
    error() << e << eom;
    return true;
  }

  catch(const std::string e)
  {
    error() << e << eom;
    return true;
  }
  
  catch(int)
  {
    return true;
  }
  
  return false;
}

/*******************************************************************\

Function: goto_analyzer_parse_optionst::process_goto_program

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/
  
bool goto_analyzer_parse_optionst::process_goto_program(
  const optionst &options)
{
  try
  {
    #if 0
    // Remove inline assembler; this needs to happen before
    // adding the library.
    remove_asm(goto_model);

    // add the library
    status() << "Adding CPROVER library (" 
             << config.ansi_c.arch << ")" << eom;
    link_to_library(goto_model, ui_message_handler);
    #endif

    // remove function pointers
    status() << "Removing function pointers and virtual functions" << eom;
    remove_function_pointers(goto_model, cmdline.isset("pointer-check"));
    remove_virtual_functions(goto_model);
    // remove rtti
    remove_instanceof(goto_model);

    // do partial inlining
    status() << "Partial Inlining" << eom;
    goto_partial_inline(goto_model, ui_message_handler);
    
    // remove returns, gcc vectors, complex
    remove_returns(goto_model);
    remove_vector(goto_model);
    remove_complex(goto_model);

    #if 0
    // add generic checks
    status() << "Generic Property Instrumentation" << eom;
    goto_check(options, goto_model);
    #endif
    
    // recalculate numbers, etc.
    goto_model.goto_functions.update();

    // add loop ids
    goto_model.goto_functions.compute_loop_numbers();
    
    // show it?
    if(cmdline.isset("show-goto-functions"))
    {
      namespacet ns(goto_model.symbol_table);

      goto_model.goto_functions.output(ns, std::cout);
      return true;
    }

    // show it?
    if(cmdline.isset("show-symbol-table"))
    {
      ::show_symbol_table(goto_model, get_ui());
      return true;
    }
  }

  catch(const char *e)
  {
    error() << e << eom;
    return true;
  }

  catch(const std::string e)
  {
    error() << e << eom;
    return true;
  }
  
  catch(int)
  {
    return true;
  }
  
  catch(std::bad_alloc)
  {
    error() << "Out of memory" << eom;
    return true;
  }
  
  return false;
}

/*******************************************************************\

Function: goto_analyzer_parse_optionst::help

  Inputs:

 Outputs:

 Purpose: display command line help

\*******************************************************************/

void goto_analyzer_parse_optionst::help()
{
  std::cout <<
    "\n"
    "* * GOTO-ANALYSER " CBMC_VERSION " - Copyright (C) 2016 ";
    
  std::cout << "(" << (sizeof(void *)*8) << "-bit version)";
    
  std::cout << " * *\n";
    
  std::cout <<
    "* *                Daniel Kroening, DiffBlue                * *\n"
    "* *                 kroening@kroening.com                   * *\n"
    "\n"
    "Usage:                       Purpose:\n"
    "\n"
    " goto-analyzer [-h] [--help]  show help\n"
    " goto-analyzer file.c ...     source file names\n"
    "\n"
    "Analyses:\n"
    "\n"
    " --taint file_name            perform taint analysis using rules in given file\n"
    " --unreachable-instructions   list dead code\n"
    " --intervals                  interval analysis\n"
    " --non-null                   non-null analysis\n"
    "\n"
    "Analysis options:\n"
    " --json file_name             output results in JSON format to given file\n"
    " --xml file_name              output results in XML format to given file\n"
    "\n"
    "C/C++ frontend options:\n"
    " -I path                      set include path (C/C++)\n"
    " -D macro                     define preprocessor macro (C/C++)\n"
    " --arch X                     set architecture (default: "
                                   << configt::this_architecture() << ")\n"
    " --os                         set operating system (default: "
                                   << configt::this_operating_system() << ")\n"
    " --c89/99/11                  set C language standard (default: "
                                   << (configt::ansi_ct::default_c_standard()==
                                       configt::ansi_ct::c_standardt::C89?"c89":
                                       configt::ansi_ct::default_c_standard()==
                                       configt::ansi_ct::c_standardt::C99?"c99":
                                       configt::ansi_ct::default_c_standard()==
                                       configt::ansi_ct::c_standardt::C11?"c11":"") << ")\n"
    " --cpp98/03/11                set C++ language standard (default: "
                                   << (configt::cppt::default_cpp_standard()==
                                       configt::cppt::cpp_standardt::CPP98?"cpp98":
                                       configt::cppt::default_cpp_standard()==
                                       configt::cppt::cpp_standardt::CPP03?"cpp03":
                                       configt::cppt::default_cpp_standard()==
                                       configt::cppt::cpp_standardt::CPP11?"cpp11":"") << ")\n"
    #ifdef _WIN32
    " --gcc                        use GCC as preprocessor\n"
    #endif
    " --no-library                 disable built-in abstract C library\n"
    "\n"
    "Java Bytecode frontend options:\n"
    " --classpath dir/jar          set the classpath\n"
    " --main-class class-name      set the name of the main class\n"
    "\n"
    "Program representations:\n"
    " --show-parse-tree            show parse tree\n"
    " --show-symbol-table          show symbol table\n"
    " --show-goto-functions        show goto program\n"
    " --show-properties            show the properties, but don't run analysis\n"
    "\n"
    "Other options:\n"
    " --version                    show version and exit\n"
    "\n";
}
