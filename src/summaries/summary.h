/*******************************************************************\

Module: summary

Author: Marek Trtik

Date: September 2016

This module defines interfaces and functionality for all kinds of summaries.
It in particular comprises loop, function, and module summaries.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_SUMMARIES_SUMMARY_H
#define CPROVER_SUMMARIES_SUMMARY_H

#include <goto-programs/goto_model.h>
#include <json/json_parser.h>
#include <util/irep.h>
#include <util/message.h>
#include <util/json.h>
#include <util/file_util.h>
#include <string>
#include <unordered_map>
#include <memory>
#include <tuple>
#include <fstream>

/*******************************************************************\

   Class: summaryt

 Purpose:

This is a base class of summaries of any kind. It defines a mandatory
interface for any summary. It can be used for summarisation of loops,
functions, modules, etc. But of course, each kind of summary is supposed
to have a different (dedicated) implementation.

When you creating your summaries, you should subclass this summaryt type
and also provide a function object which is responsible for computation
of summaries.

\*******************************************************************/
class  summaryt
{
public:

  virtual ~summaryt() {}

  /*******************************************************************\
   It should return globally unique identifier of a 'kind' of the
   summaries. For example, it can be a unique name of an analysis which has
   computed them.
  \*******************************************************************/
  virtual std::string  kind() const noexcept = 0;

  /*******************************************************************\
   A textual human-readable description of the summaries.
  \*******************************************************************/
  virtual std::string  description() const noexcept { return ""; }

  // TODO: define other interface functions!!
};

class json_serialisable_summaryt : public summaryt {
 public:
  
  virtual void from_json(const json_objectt&)=0;
  virtual json_objectt to_json() const =0;
  
};

/*******************************************************************\
 We represent a summary of an object (loop, function, etc.) as a pair:
    [object-unique-identifier,summary-ptr].
 This is defined in the following three 'typedef' statements.
\*******************************************************************/
typedef std::string  summarised_object_idt;
typedef std::shared_ptr<summaryt const>  summary_ptrt;
typedef std::pair<summarised_object_idt,summary_ptrt>  object_summaryt;


/*******************************************************************\

   Class: summaryt

 Purpose:

It holds and caches all computed summaries of the same kind (i.e. those
whose method 'summaryt::kind()' returns the same string). The goal is to
provide fast access to computed summaries. The implementation provides
fast caching of frequently used summaries, streaming summaries to/from
the disc (to minimise memory occupation), and thread-safety of all accesses.

For each kind of summaries one should use a separate instance of this
database.

If you want to permanently store the content of the cache to the disc,
you have to do that manually (yourself) by enumerating all elements.

\*******************************************************************/
class  database_of_summariest
{
public:

  typedef std::unordered_map<summarised_object_idt,summary_ptrt>  cachet;
  typedef cachet  databaset;

  virtual ~database_of_summariest() {}

  template<typename  summary_typet>
  std::shared_ptr<summary_typet const>  find(
      summarised_object_idt const&  object_id
      ) const;

  virtual void  insert(object_summaryt const&  object_and_summary);

  databaset::const_iterator  cbegin() const;
  databaset::const_iterator  begin() const { return cbegin(); }  
  databaset::const_iterator  cend() const;
  databaset::const_iterator  end() const { return cend(); }

  std::size_t  count(const summarised_object_idt& id) const
  { return m_cache.count(id); }

  const summary_ptrt& operator[](const summarised_object_idt& id) const
  { return m_cache.at(id); }

protected:
  cachet  m_cache;
};


template<typename  summary_typet>
std::shared_ptr<summary_typet const>  database_of_summariest::find(
    summarised_object_idt const&  object_id
    ) const
{
  auto const  it = m_cache.find(object_id);
  return it == m_cache.cend() ?
            std::shared_ptr<summary_typet const>() :
            std::dynamic_pointer_cast<summary_typet const>(it->second)
            ;
}

typedef std::shared_ptr<database_of_summariest>  database_of_summaries_ptrt;

std::string to_file_name(std::string);

template<class SummaryType>
class summary_json_databaset : public database_of_summariest, public messaget {
 public:
  
 summary_json_databaset(const std::string& dirname) : database_dirname(dirname)
  {
    if(dirname!="")
      fileutl_create_directory(dirname);
    load_index();
  }

  void load_index()
  {
    if(database_dirname=="")
      return;
    std::string index_filename=database_dirname+"/"+"__index.json";
    if(!fileutl_file_exists(index_filename))
    {
      warning() << "Summaries: __index.json not found; starting with empty summary database" << eom;
      return;
    }
    jsont index;
    {
      std::ifstream index_stream(index_filename);
      if(parse_json(index_stream,index_filename,get_message_handler(),index))
        throw "Failed to parse summaries index";
      assert(index.is_array());
      for(const auto& entry : index.object)
        used_filenames.insert(entry.second.value);
    }
  }
    
  void load_all()
  {
    for(const auto& entry : index.object)
    {
      assert(entry.second.is_string() && "Summaries: expected __index value to be a string");
      load(entry.first,entry.second.value);
    }
  }

  bool load(const std::string& functionname)
  {
    // Already loaded?
    if(m_cache.count(functionname))
      return true;
  
    const auto& findit=index.object.find(id2string(functionname));
    if(findit==index.object.end())
    {
      warning() << "No summary available for " << functionname << eom;
      return false;
    }
  
    std::string entry_filename=database_dirname+"/"+findit->second.value;
    load(functionname, entry_filename);
    return true;
  }

  void load(const std::string& functionname, const std::string& filename)
  {
    if(!fileutl_file_exists(filename))
      throw "Summaries: function json not found";

    jsont entry_json;
    {
      std::ifstream entry_stream(filename);
      if(parse_json(entry_stream,filename,get_message_handler(),entry_json))
        throw "Failed to parse entry json";
    }
    if(!entry_json.is_object())
      throw "Summaries: expected entry json to contain an object";

    const auto& entry_obj=static_cast<const json_objectt&>(entry_json);
    auto new_entry=std::make_shared<SummaryType>();
    new_entry->from_json(entry_obj);
    m_cache[functionname]=new_entry;
  }

  virtual void insert(object_summaryt const& object)
  {
    const auto& functionname=object.first;
    std::string prefix=to_file_name(functionname);
    unsigned unique_number=0;
    std::string filename;

    do {
      std::ostringstream filename_ss;
      filename_ss << prefix;
      if(unique_number!=1)
        filename_ss << '_' << unique_number;
      filename_ss << ".json";
      filename=filename_ss.str();
    } while(!used_filenames.insert(filename).second);

    index[functionname]=json_stringt(filename);

    database_of_summariest::insert(object);
  }
  
  void save(const std::string& functionname)
  {
    if(database_dirname=="")
      return;
    std::string filename=index.object.at(functionname).value;
    json_objectt as_json=
      static_cast<const json_serialisable_summaryt*>((*this)[functionname].get())->to_json();
    std::ofstream ostr(database_dirname+"/"+filename);
    ostr << as_json;
  }

  void save_index()
  {
    if(database_dirname=="")
      return;
    std::string indexpath=database_dirname+"/__index.json";
    std::fstream  ostr(indexpath, std::ios_base::out);
    ostr << index;
  }

  void save_all()
  {
    for(const auto& entry : index.object)
      save(entry.first);
    save_index();
  }

 protected:
  const std::string database_dirname;
  json_objectt index;
  std::unordered_set<std::string> used_filenames;  

};

#endif
