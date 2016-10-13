/*******************************************************************\

Module: summary_dump

Author: Marek Trtik

Date: September 2016

It provides dump of computed summaries in human readable form.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#include <summaries/summary_dump.h>
#include <summaries/utility.h>
#include <util/file_util.h>
#include <util/msgstream.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <set>
#include <cstdlib>


static std::string  dump_access_paths_of_goto_program_in_html(
    goto_programt const&  program,
    irep_idt const  raw_fn_name,
    namespacet const&  ns,
    std::string const&  dump_root_directory
    )
{
  fileutl_create_directory(dump_root_directory);

  typedef std::pair<std::string, std::pair<std::string,std::string> >
          value_type;
  std::set<value_type>  result;
  {
    for (auto  it = program.instructions.cbegin();
         it != program.instructions.cend();
         ++it)
    {
      switch(it->type)
      {
      case ASSIGN:
        {
          code_assignt const&  asgn = to_code_assign(it->code);
          {
            std::string const  first = from_expr(ns, it->function, asgn.lhs());
            std::stringstream  second;
            dump_irept(asgn.lhs(),second);
            value_type const value{
                to_html_text(first),
                { to_file_name(first), to_html_text(second.str()) }
                };
            if (result.count(value) == 0UL)
              result.insert(value);
          }
          {
            set_of_access_pathst  access_paths;
            collect_access_paths(asgn.rhs(),ns,access_paths,false);
            for (auto const&  path : access_paths)
            {
              std::string const  first = from_expr(ns, it->function, path);
              std::stringstream  second;
              dump_irept(path,second);
              value_type const value{
                  to_html_text(first),
                  { to_file_name(first), to_html_text(second.str()) }
                  };
              if (result.count(value) == 0UL)
                result.insert(value);
            }
          }
        }
        break;
      case FUNCTION_CALL:
        {
          code_function_callt const&  fn_call = to_code_function_call(it->code);
          if (fn_call.function().id() == ID_symbol)
            for (const auto&  arg : fn_call.arguments())
            {
              std::string const  first = from_expr(ns, it->function, arg);
              std::stringstream  second;
              dump_irept(arg,second);
              value_type const value{
                  to_html_text(first),
                  { to_file_name(first), to_html_text(second.str()) }
                  };
              if (result.count(value) == 0UL)
                result.insert(value);
            }
        }
        break;
      default:
        break;
      }
    }
  }

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
      return msgstream() << "ERROR: sumfn::dump_access_paths_of_goto_program_"
                            "in_html() : Cannot open the log file '"
                         << log_filename << "'."
                         ;
  dump_html_prefix(ostr,"Access paths");
  ostr << "<h1>Dump of access paths in the function "
       << to_html_text(as_string(raw_fn_name))
       << "</h1>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>Access path</th>\n"
          "    <th>irept</th>\n"
          "  </tr>\n"
          ;
  for(value_type const& hname_fname_irep : result)
  {
    {
      std::string const  log_filename =
          msgstream() << dump_root_directory << "/"
                      << hname_fname_irep.second.first
                      << ".html";
      std::fstream  ostr(log_filename, std::ios_base::out);
      if (!ostr.is_open())
          return msgstream() << "ERROR: sumfn::dump_access_paths_of_goto_"
                                "program_in_html() : Cannot open the log file '"
                             << log_filename << "'."
                             ;
      dump_html_prefix(ostr,"IREPT");
      ostr << "<h1>Dump of IREPT of access path "
           << to_html_text(as_string(hname_fname_irep.first))
           << "</h1>\n"
              "<pre>\n"
           << hname_fname_irep.second.second
           << "</pre>\n"
           ;
      dump_html_suffix(ostr);
    }
    ostr << "  <tr>\n"
            "    <td>" << hname_fname_irep.first << "</td>\n"
            "    <td><a href=\"./" << hname_fname_irep.second.first
                                   << ".html\">here</a></td>\n"
            "  </tr>\n"
            ;
  }
  ostr << "  </table>\n";
  dump_html_suffix(ostr);
  return ""; // no error.

}


static std::string  dump_function_body_in_html(
    irep_idt const  raw_fn_name,
    goto_programt  const&  fn_body,
    goto_modelt const&  program,
    namespacet const  ns,
    std::string const&  dump_root_directory
    )
{
  fileutl_create_directory(dump_root_directory);

  std::string const  err_message =
      dump_access_paths_of_goto_program_in_html(
          fn_body,
          raw_fn_name,
          ns,
          msgstream() << dump_root_directory << "/IREPT"
          );
  if (!err_message.empty())
    return err_message;

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
      return msgstream() << "ERROR: sumfn::dump_function_body_in_html() : "
                            "Cannot open the log file '" << log_filename << "'."
                         ;
  dump_html_prefix(
        ostr,
        msgstream() << "Code[" << to_html_text(as_string(raw_fn_name)) << "]"
        );
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

  ostr << "<p>Dump of IREPTs of symbols used in the function body is "
          "<a href=\"./IREPT/index.html\">here</a></p>\n"
       ;

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


static std::string  dump_callgraph_in_svg(
    call_grapht const&  call_graph,
    goto_functionst const&  functions,
    std::string const&  svg_file_pathname
    )
{
  std::string const  dot_filename =
      msgstream() << svg_file_pathname << ".dot";
  {
    std::fstream  ostr(dot_filename, std::ios_base::out);
    if (!ostr.is_open())
        return msgstream() << "ERROR: sumfn::dump_callgraph_in_svg() : "
                              "Cannot open file '" << dot_filename << "'."
                           ;
    call_graph.output_dot(functions,ostr);
  }

  std::string const  command =
      msgstream() << "dot -Tsvg \"" << dot_filename
                  << "\" -o \"" << svg_file_pathname << "\"";
  std::system(command.c_str());

  return ""; // No error.
}


static std::string  dump_goto_program_in_html(
    goto_modelt const&  program,
    call_grapht const&  call_graph,
    std::string const&  dump_root_directory
    )
{
  fileutl_create_directory(dump_root_directory);

  namespacet const  ns(program.symbol_table);
  goto_functionst::function_mapt const&  functions =
      program.goto_functions.function_map;
  for(auto  it = functions.cbegin(); it != functions.cend(); it++)
    if(it->second.body_available())
    {
      std::string err_message =
          dump_function_body_in_html(
              it->first,
              it->second.body,
              program,
              ns,
              msgstream() << dump_root_directory << "/"
                          << to_file_name(as_string(it->first))
              );
      if (!err_message.empty())
        return err_message;
    }

  std::string const  call_graph_svg_file =
      msgstream() << dump_root_directory << "/call_graph.svg";
  dump_callgraph_in_svg(call_graph,program.goto_functions,call_graph_svg_file);

  std::vector<irep_idt>  inverted_topological_order;
  {
    std::unordered_set<irep_idt,dstring_hash>  processed;
    for (auto const&  elem : program.goto_functions.function_map)
      inverted_partial_topological_order(
            call_graph,
            elem.first,
            processed,
            inverted_topological_order
            );
  }

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
      return msgstream() << "ERROR: sumfn::dump_goto_program_in_html() : "
                            "Cannot open the log file '" << log_filename << "'."
                         ;
  dump_html_prefix(ostr,"Program");
  ostr << "<h1>Dump of analysed program</h1>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>Function name</th>\n"
          "    <th>Code</th>\n"
          "  </tr>\n"
          ;
  std::set<std::string>  ordered;
  for(auto  it = functions.cbegin(); it != functions.cend(); it++)
    if(it->second.body_available())
      ordered.insert(as_string(it->first));
  for (auto const& fn_name : ordered)
      ostr << "  <tr>\n"
              "    <td>" << to_html_text(fn_name) << "</td>\n"
              "    <td><a href=\"./" << to_file_name(fn_name)
                                     << "/index.html\">here</a></td>\n"
              "  </tr>\n"
              ;
  ostr << "</table>\n";

  ostr << "<h3>Call graph</h3>\n"
          "<img src=\"./call_graph.svg\" alt=\"call graph SVG file\">\n"
          "<p>Inverted (partial) topological order of functions (i.e. "
          "from callees to callers):</p>\n"
          "<ul>\n"
       ;
  for (irep_idt const&  fn_name : inverted_topological_order)
    ostr << "<li>" << to_html_text(as_string(fn_name)) << "</li>\n";
  ostr << "</ul>\n";

  dump_html_suffix(ostr);
  return ""; // no error.
}


static std::string  dump_log_in_html(
    std::ostream const&  source,
    std::string const&  dump_root_directory
    )
{
  fileutl_create_directory(dump_root_directory);

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
      return msgstream() << "ERROR: sumfn::dump_log_in_html() : "
                            "Cannot open the log file '" << log_filename << "'."
                         ;
  dump_html_prefix(ostr,"Log");
  ostr << "<h1>Log from the summary computation</h1>\n";
  ostr << source.rdbuf();
  dump_html_suffix(ostr);
  return ""; // no error.
}


static void  replace(
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


void  dump_irept(
    irept const&  irep,
    std::ostream&  ostr,
    std::string const&  shift)
{
  std::string const  local_shift = msgstream() << shift << "    ";
  std::string const  sub_shift = msgstream() << local_shift << "    ";
  ostr << shift << "IREP{\n"
       << local_shift << "id { " << irep.id() << " }\n"
       << local_shift << "sub {\n"
       ;
  for (auto const&  sub : irep.get_sub())
    dump_irept(sub,ostr,sub_shift);
  ostr << local_shift << "}\n"
       << local_shift << "named_sub {\n"
       ;
  for (auto const&  name_irep : irep.get_named_sub())
  {
    ostr << sub_shift << name_irep.first << " :\n";
    dump_irept(name_irep.second,ostr,sub_shift);
  }
  ostr << local_shift << "}\n"
       << shift << "}\n"
       ;
}


std::string  dump_in_html(
    database_of_summariest const&  computed_summaries,
    callback_dump_derived_summary_in_htmlt const&  summary_dump_callback,
    goto_modelt const&  program,
    call_grapht const&  call_graph,
    std::string const&  dump_root_directory,
    std::ostream* const  log
    )
{
  fileutl_create_directory(dump_root_directory);

  std::string  err_message =
      dump_goto_program_in_html(
          program,
          call_graph,
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
    err_message = dump_log_in_html(
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
      return msgstream() << "ERROR: sumfn::taint::taint_summarise_all_functions() : "
                            "Cannot open the log file '" << log_filename << "'."
                         ;
  dump_html_prefix(ostr,"Database");
  ostr << "<h1>Taint Summaries</h1>\n"
          "<table>\n"
          "  <tr>\n"
          "    <th>Summarised objects</th>\n"
          "    <th>Summary</th>\n"
          "  </tr>\n"
          ;
  std::set<summarised_object_idt> ordered_objects;
  for (auto  it = computed_summaries.cbegin();
       it != computed_summaries.cend();
       ++it)
    ordered_objects.insert(it->first);
  for (summarised_object_idt const&  id: ordered_objects)
    ostr << "  <tr>\n"
            "    <td>" << to_html_text(id) << "</td>\n"
            "    <td><a href=\"./" << to_file_name(id)
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
  fileutl_create_directory(dump_root_directory);

  std::string const  log_filename =
      msgstream() << dump_root_directory << "/index.html";
  std::fstream  ostr(log_filename, std::ios_base::out);
  if (!ostr.is_open())
     return msgstream() << "ERROR: sumfn::taint::taint_summarise_function() : "
                           "Cannot open the log file '" << log_filename << "'."
                        ;
  dump_html_prefix(
        ostr,
        msgstream() << "Summary[" << to_html_text(summary.first) << "]"
        );
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
  std::replace( result.begin(),result.end(), '#', '_');
  std::replace( result.begin(),result.end(), ':', '.');
  std::replace( result.begin(),result.end(), '/', '.');
  std::replace( result.begin(),result.end(), '<', '[');
  std::replace( result.begin(),result.end(), '>', ']');
  return result;
}

std::string  to_html_text(std::string  result)
{
  replace(result, "<", "&lt;");
  replace(result, ">", "&gt;");
  return result;
}


void  dump_access_path_in_html(
    access_path_to_memoryt const&  access_path,
    namespacet const&  ns,
    std::ostream&  ostr
    )
{
  if (is_identifier(access_path))
    ostr << to_html_text(name_of_symbol_access_path(access_path));
  else
    ostr << to_html_text(from_expr(ns, "", access_path));
}


void  dump_html_prefix(
    std::ostream&  ostr,
    std::string const&  page_name)
{
  ostr << "<!DOCTYPE html>\n"
          "<html>\n"
          "<head>\n"
          "<title>" << page_name << "</title>\n"
          "<style>\n"
          "table, th, td {\n"
          "    border: 1px solid black;\n"
          "    border-collapse: collapse;\n"
          "}\n"
          "th, td {\n"
          "    padding: 5px;\n"
          "}\n"
          "h1, h2, h3, h4, p, a, table, ul { "
              "font-family: \"Liberation serif\", serif; }\n"
          "p, a, table, ul { font-size: 12pt; }\n"
          "h4 { font-size: 12pt; }\n"
          "h3 { font-size: 14pt; }\n"
          "h2 { font-size: 18pt; }\n"
          "h1 { font-size: 24pt; }\n"
          "tt { font-family: \"Liberation Mono\", monospace; }\n"
          "tt { font-size: 10pt; }\n"
          "body {\n"
          "    background-color: white;\n"
          "    color: black;\n"
          "}\n"
          "</style>\n"
          "</head>\n"
          "<body>\n"
       ;
}

void  dump_html_suffix(std::ostream&  ostr)
{
    ostr << "</body>\n"
            "</html>\n"
         ;
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

void write_database_as_json(
  database_of_summariest const& computed_summaries,
  callback_summary_to_jsont summary_dump_callback,
  std::string const& dump_root_directory)
{
  std::unordered_map<std::string, unsigned> unique_names;
  std::unordered_set<std::string> used_filenames;
  json_objectt index;

  fileutl_create_directory(dump_root_directory);  
  
  for(const auto& row : computed_summaries)
  {
    std::string prefix=to_file_name(row.first);
    std::ostringstream filename;

    do
    {
      filename << prefix;
      unsigned unique_number=++unique_names[row.first];
      if(unique_number!=1)
        filename << '_' << unique_number;
      filename << ".json";
    } while(!used_filenames.insert(filename.str()).second);

    index[row.first]=json_stringt(filename.str());

    json_objectt as_json=summary_dump_callback(row);
    {
      std::fstream ostr(dump_root_directory+"/"+filename.str(), std::ios_base::out);
      ostr << as_json;
    }
    
  }

  {
    std::fstream  ostr(dump_root_directory+"/__index.json", std::ios_base::out);
    ostr << index;
  }
}
