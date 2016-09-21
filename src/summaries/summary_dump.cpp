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
#include <iostream>
#include <iomanip>


namespace sumfn { namespace detail { namespace {


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
  detail::dump_html_prefix(ostr);
  ostr << "<h1>Code of function '" << to_html_text(as_string(raw_fn_name))
                                   << "'</h1>\n"
          ;
  detail::dump_html_suffix(ostr);
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
  detail::dump_html_prefix(ostr);
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
  detail::dump_html_suffix(ostr);
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
    database_of_summaries_t const&  summaries_to_compute,
    callback_dump_derived_summary_in_html const&  summary_dump_callback,
    std::string const&  dump_root_directory,
    goto_modelt const*  program
    )
{
  fileutl::create_directory(dump_root_directory);

  if (program != nullptr)
  {
    std::string const  err_message =
        detail::dump_goto_program_in_html(
            *program,
            msgstream() << dump_root_directory << "/goto_model"
            );
    if (!err_message.empty())
      return err_message;
  }

  for (auto  it = summaries_to_compute.cbegin();
       it != summaries_to_compute.cend();
       ++it)
  {
    std::string const  err_message = dump_in_html(
        *it,
        summary_dump_callback,
        msgstream() << dump_root_directory << "/" << to_file_name(it->first)
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
  detail::dump_html_prefix(ostr);
  ostr << "<h1>Taint Summaries</h1>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>Summarised objects</th>\n"
          "    <th>Summary</th>\n"
          "  </tr>\n"
          ;
  for (auto  it = summaries_to_compute.cbegin();
       it != summaries_to_compute.cend();
       ++it)
    ostr << "  <tr>\n"
            "    <td>" << to_html_text(it->first) << "</td>\n"
            "    <td><a href=\"./" << to_file_name(it->first)
         << "/index.html\">here</a></td>\n"
            "  </tr>\n"
            ;
  ostr << "</table>\n";
  if (program != nullptr)
    ostr << "<p>Dump of whole analysed program is available "
            "<a href=\"./goto_model/index.html\">here</a></p>\n"
         ;
  detail::dump_html_suffix(ostr);

  return ""; // no error.
}


std::string  dump_in_html(
    object_summary_t const  summary,
    callback_dump_derived_summary_in_html const&  summary_dump_callback,
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
  detail::dump_html_prefix(ostr);
  ostr << "<h1>Summary of function '"
       << to_html_text(summary.first)
       << "'</h1>\n"
       ;
  ostr << "<h2>General properties</h2>\n"
       << "<p>Kind: " << summary.second->kind() << "</p>\n"
       << "<p>Description: " << summary.second->description() << "</p>\n"
       ;

  std::string const  err_message = summary_dump_callback(summary,ostr);
  if (!err_message.empty())
    ostr << "<p>DUMP FAILURE: " << to_html_text(err_message)  << "</p>\n";

  detail::dump_html_suffix(ostr);

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


}
