/////////////////////////////////////////////////////////////////////////////
//
// Module: summary_dump
// Author: Marek Trtik
//
// It provides dump of computed summaries in human readable form.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////

#include <summaries/summary_dump.h>
#include <util/file_util.h>
#include <util/msgstream.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>


namespace sumfn { namespace detail { namespace {


std::string  dump_function_body_in_html(
    irep_idt const  raw_fn_name,
    goto_programt  const&  fn_body,
    goto_modelt const&  program,
    std::string const&  dump_root_directory
    )
{
  fileutl::create_directory(dump_root_directory);

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
      return msgstream() << "ERROR: sumfn::dump_function_body_in_html() : "
                            "Cannot open the log file '" << log_filename << "'."
                         ;
  dump_html_prefix(ostr);
  ostr << "<h1>Code of function '" << to_html_text(as_string(raw_fn_name))
                                   << "'</h1>\n"
          "<p>\n"
          "All numbers are decimal. The symbol 'N/A' stands for 'not\n"
          "available'. Column 'Loc' shows program locations.\n"
          "</p>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>Loc</th>\n"
          "    <th>Targets</th>\n"
          "    <th>Instruction</th>\n"
          "    <th>Labels</th>\n"
          "    <th>File</th>\n"
          "    <th>Line</th>\n"
          "    <th>Column</th>\n"
          "    <th>Comment</th>\n"
          "  </tr>\n"
          ;
  for (auto  it = fn_body.instructions.cbegin();
      it != fn_body.instructions.cend();
      ++it)
  {
    ostr << "  <tr>\n";

    // Dumping program location
    ostr << "    <td>"
         << it->location_number
         << "</td>\n"
         ;

    // Dumping targets
    if (it->is_target())
      ostr << "    <td>" << it->target_number << "</td>\n";
    else
      ostr << "    <td>    </td>\n";

    // Dumping instruction
    ostr << "    <td>\n";
    dump_instruction_code_in_html(*it,program,ostr);
    ostr << "</td>\n";

    // Dumping labels
    {
      bool  first = true;
      msgstream  labels;
      for (auto label_it = it->labels.cbegin();
           label_it != it->labels.end();
           label_it++)
      {
        std::string const  label = as_string(*label_it);
        if (!label.empty())
        {
          labels  << (first ? "" : ", ") << label;
          first = false;
        }
      }
      std::string const  result = labels.get();
      ostr << "    <td>" << (result.empty() ? "    " : result) << "</td>\n";
    }

    // Dumping source file, line, and column
    if (it->source_location.is_nil())
      ostr << "    <td>N/A</td>\n"
           << "    <td>N/A</td>\n"
           << "    <td>N/A</td>\n"
           ;
    else
    {
      std::string const  name = as_string(it->source_location.get_file());
      std::string const  line = as_string(it->source_location.get_line());
      std::string const  column = as_string(it->source_location.get_column());
      ostr << "    <td>"
           << (name.empty() ? "N/A" : name)
           << "</td>\n"
           << "    <td>"
           << (line.empty() ? "N/A" : line)
           << "</td>\n"
           << "    <td>"
           << (column.empty() ? "N/A" : column)
           << "</td>\n"
           ;
    }

    //Dumping comment
    ostr << "    <td>"
         << as_string(it->source_location.get_comment())
         << "</td>\n"
         ;

    ostr << "  </tr>\n";
  }
  ostr << "</table>\n";

  ostr << "<h2>Plain text code listing</h3>\n";
  ostr << "<pre>\n";
  {
    namespacet ns(program.symbol_table);
    for (auto  it = fn_body.instructions.cbegin();
        it != fn_body.instructions.cend();
        ++it)
    {
      std::stringstream  buffer;
      fn_body.output_instruction(ns,raw_fn_name,buffer,it);
      ostr << to_html_text(buffer.str());
    }
  }
  ostr << "</pre>\n";

  dump_html_suffix(ostr);
  return ""; // no error.
}


std::string  dump_goto_program_in_html(
    goto_modelt const&  program,
    std::string const&  dump_root_directory
    )
{
  fileutl::create_directory(dump_root_directory);

  namespacet const  ns(program.symbol_table);
  goto_functionst::function_mapt const&  functions =
      program.goto_functions.function_map;
  for(auto  it = functions.cbegin(); it != functions.cend(); it++)
    if(it->second.body_available())
    {
      std::string const  err_message =
          detail::dump_function_body_in_html(
              it->first,
              it->second.body,
              program,
              msgstream() << dump_root_directory << "/"
                          << to_file_name(as_string(it->first))
              );
      if (!err_message.empty())
        return err_message;
    }

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
      return msgstream() << "ERROR: sumfn::dump_goto_program_in_html() : "
                            "Cannot open the log file '" << log_filename << "'."
                         ;
  dump_html_prefix(ostr);
  ostr << "<h1>Dump of analysed program</h1>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>Function name</th>\n"
          "    <th>Code</th>\n"
          "  </tr>\n"
          ;
  for(auto  it = functions.cbegin(); it != functions.cend(); it++)
    if(it->second.body_available())
      ostr << "  <tr>\n"
              "    <td>" << to_html_text(as_string(it->first)) << "</td>\n"
              "    <td><a href=\"./" << to_file_name(as_string(it->first))
                                     << "/index.html\">here</a></td>\n"
              "  </tr>\n"
              ;
  ostr << "</table>\n";
  dump_html_suffix(ostr);
  return ""; // no error.
}

std::string  dump_log_in_html(
    std::ostream const&  source,
    std::string const&  dump_root_directory
    )
{
  fileutl::create_directory(dump_root_directory);

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
      return msgstream() << "ERROR: sumfn::dump_log_in_html() : "
                            "Cannot open the log file '" << log_filename << "'."
                         ;
  dump_html_prefix(ostr);
  ostr << "<h1>Log of taint summary computation</h1>\n";
  ostr << source.rdbuf();
  dump_html_suffix(ostr);
  return ""; // no error.
}


void  replace(
    std::string&  str,
    std::string const&  what,
    std::string const&  replacement
    )
{
  size_t  pos = 0;
  while ((pos = str.find(what, pos)) != std::string::npos)
  {
    str.replace(pos, what.length(), replacement);
    pos += replacement.length();
  }
}


}}}

namespace sumfn {


std::string  dump_in_html(
    database_of_summariest const&  computed_summaries,
    callback_dump_derived_summary_in_htmlt const&  summary_dump_callback,
    goto_modelt const&  program,
    std::string const&  dump_root_directory,
    std::ostream* const  log
    )
{
  fileutl::create_directory(dump_root_directory);

  std::string  err_message =
      detail::dump_goto_program_in_html(
          program,
          msgstream() << dump_root_directory << "/goto_model"
          );
  if (!err_message.empty())
    return err_message;

  for (auto  it = computed_summaries.cbegin();
       it != computed_summaries.cend();
       ++it)
  {
    err_message = dump_in_html(
        *it,
        summary_dump_callback,
        program,
        msgstream() << dump_root_directory << "/" << to_file_name(it->first)
        );
    if (!err_message.empty())
      return err_message;
  }

  if (log != nullptr)
  {
    err_message = detail::dump_log_in_html(
        *log,
        msgstream() << dump_root_directory << "/log"
        );
    if (!err_message.empty())
      return err_message;
  }

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
      return msgstream() << "ERROR: sumfn::taint::summarise_all_functions() : "
                            "Cannot open the log file '" << log_filename << "'."
                         ;
  dump_html_prefix(ostr);
  ostr << "<h1>Taint Summaries</h1>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>Summarised objects</th>\n"
          "    <th>Summary</th>\n"
          "  </tr>\n"
          ;
  for (auto  it = computed_summaries.cbegin();
       it != computed_summaries.cend();
       ++it)
    ostr << "  <tr>\n"
            "    <td>" << to_html_text(it->first) << "</td>\n"
            "    <td><a href=\"./" << to_file_name(it->first)
         << "/index.html\">here</a></td>\n"
            "  </tr>\n"
            ;
  ostr << "</table>\n";

  ostr << "<p>Dump of whole analysed program is available "
          "<a href=\"./goto_model/index.html\">here</a></p>\n"
         ;

  if (log != nullptr)
    ostr << "<p>Log from summary computation is available "
            "<a href=\"./log/index.html\">here</a></p>\n"
         ;

  dump_html_suffix(ostr);

  return ""; // no error.
}


std::string  dump_in_html(
    object_summaryt const  summary,
    callback_dump_derived_summary_in_htmlt const&  summary_dump_callback,
    goto_modelt const&  program,
    std::string const&  dump_root_directory
    )
{
  fileutl::create_directory(dump_root_directory);

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
     return msgstream() << "ERROR: sumfn::taint::summarise_function() : Cannot "
                           "open the log file '" << log_filename << "'."
                        ;
  dump_html_prefix(ostr);
  ostr << "<h1>Summary of function '"
       << to_html_text(summary.first)
       << "'</h1>\n"
       ;
  ostr << "<h2>General properties</h2>\n"
       << "<p>Kind: " << summary.second->kind() << "</p>\n"
       << "<p>Description: " << summary.second->description() << "</p>\n"
       ;

  std::string const  err_message = summary_dump_callback(summary,program,ostr);
  if (!err_message.empty())
    ostr << "<p>DUMP FAILURE: " << to_html_text(err_message)  << "</p>\n";

  dump_html_suffix(ostr);

  return err_message;
}


std::string  to_file_name(std::string  result)
{
  std::replace( result.begin(),result.end(), ':', '.');
  std::replace( result.begin(),result.end(), '/', '.');
  std::replace( result.begin(),result.end(), '<', '[');
  std::replace( result.begin(),result.end(), '>', ']');
  return result;
}

std::string  to_html_text(std::string  result)
{
  detail::replace(result, "<", "&lt;");
  detail::replace(result, ">", "&gt;");
  return result;
}


void  dump_html_prefix(std::ostream&  ostr)
{
    ostr << "<!DOCTYPE html>\n";
    ostr << "<html>\n";
    ostr << "<head>\n";
    ostr << "<style>\n";
    ostr << "table, th, td {\n";
    ostr << "    border: 1px solid black;\n";
    ostr << "    border-collapse: collapse;\n";
    ostr << "}\n";
    ostr << "th, td {\n";
    ostr << "    padding: 5px;\n";
    ostr << "}\n";
    ostr << "h1, h2, h3, h4, p, a, table, ul { font-family: \"Liberation serif\", serif; }\n";
    ostr << "p, a, table, ul { font-size: 12pt; }\n";
    ostr << "h4 { font-size: 12pt; }\n";
    ostr << "h3 { font-size: 14pt; }\n";
    ostr << "h2 { font-size: 18pt; }\n";
    ostr << "h1 { font-size: 24pt; }\n";
    ostr << "tt { font-family: \"Liberation Mono\", monospace; }\n";
    ostr << "tt { font-size: 10pt; }\n";
    ostr << "body {\n";
    ostr << "    background-color: white;\n";
    ostr << "    color: black;\n";
    ostr << "}\n";
    ostr << "</style>\n";
    ostr << "</head>\n";
    ostr << "<body>\n";
}

void  dump_html_suffix(std::ostream&  ostr)
{
    ostr << "</body>\n";
    ostr << "</html>\n";
}


void  dump_instruction_code_in_html(
    goto_programt::instructiont const&  I,
    goto_modelt const&  program,
    std::ostream&  ostr
    )
{
  namespacet const  ns(program.symbol_table);
  switch(I.type)
  {
  case NO_INSTRUCTION_TYPE:
    ostr << "NO INSTRUCTION";
    break;
  case GOTO:
    if (!I.guard.is_true())
      ostr << "IF " << to_html_text(from_expr(ns, I.function, I.guard))
           << " THEN ";
    ostr << "GOTO ";
    for (auto  target_it = I.targets.begin();
         target_it != I.targets.end();
         ++target_it)
      ostr << (target_it == I.targets.begin() ? "" : ", ")
           << (*target_it)->target_number;
    break;
  case RETURN:
  case OTHER:
  case DECL:
  case DEAD:
  case FUNCTION_CALL:
  case ASSIGN:
    ostr << to_html_text(from_expr(ns, I.function, I.code));
    break;
  case ASSUME:
  case ASSERT:
    if (I.is_assume())
      ostr << "ASSUME ";
    else
      ostr << "ASSERT ";
    ostr << to_html_text(from_expr(ns, I.function, I.guard));
    break;
  case SKIP:
    ostr << "SKIP";
    break;
  case END_FUNCTION:
    ostr << "END_FUNCTION";
    break;
  case LOCATION:
    ostr << "LOCATION";
    break;
  case THROW:
    ostr << "THROW ";
    {
      irept::subt const&  exceptions =
          I.code.find(ID_exception_list).get_sub();
      for (auto  exceptions_it = exceptions.cbegin();
           exceptions_it != exceptions.cend();
           ++exceptions_it)
        ostr << (exceptions_it == exceptions.cbegin() ? "" : ", ")
             << exceptions_it->id()
             ;
    }
    if (I.code.operands().size() == 1)
      ostr << ": "
           << to_html_text(from_expr(ns, I.function, I.code.op0()))
           ;
    break;
  case CATCH:
    if (!I.targets.empty())
    {
      ostr << "CATCH-PUSH ";
      auto  exceptions_it =
          I.code.find(ID_exception_list).get_sub().cbegin();
      for (auto target_it = I.targets.cbegin();
           target_it != I.targets.end();
           ++target_it, ++exceptions_it)
        ostr << (target_it == I.targets.begin() ? "" : ", ")
             << exceptions_it->id() << "->"
             << (*target_it)->target_number;
    }
    else
      ostr << "CATCH-POP";
    break;
  case ATOMIC_BEGIN:
    ostr << "ATOMIC_BEGIN";
    break;
  case ATOMIC_END:
    ostr << "ATOMIC_END";
    break;
  case START_THREAD:
    ostr << "START THREAD ";
    for (auto  target_it = I.targets.begin();
         target_it != I.targets.end();
         ++target_it)
      ostr << (target_it == I.targets.begin() ? "" : ", ")
           << (*target_it)->target_number;
    break;
  case END_THREAD:
    ostr << "END THREAD";
    break;
  default:
    ostr << "&lt;UNKNOWN&gt;";
    break;
  }
}


}
