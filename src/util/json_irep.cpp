/*******************************************************************\

Module: Util

Author: Thomas Kiley, thomas.kiley@diffblue.com

\*******************************************************************/

#include "irep.h"
#include "json.h"
#include "json_irep.h"

#include <algorithm>

/*******************************************************************\

Function: json_irept::json_irept

  Inputs:
   include_comments - when writing JSON, should the comments
                      sub tree be included.

 Outputs:

 Purpose: To convert to JSON from an irep structure by recurssively
          generating JSON for the different sub trees.

\*******************************************************************/

json_irept::json_irept(bool include_comments):
  include_comments(include_comments)
{}

/*******************************************************************\

Function: json_irept::convert_from_irep

  Inputs:
   irep - The irep structure to turn into json
   json - The json object to be filled up.

 Outputs:

 Purpose: To convert to JSON from an irep structure by recurssively
          generating JSON for the different sub trees.

\*******************************************************************/

void json_irept::convert_from_irep(const irept &irep, jsont &json) const
{
  json_objectt &irep_object=json.make_object();
  if(irep.id()!=ID_nil)
    irep_object["id"]=json_stringt(irep.id_string());

  convert_sub_tree("sub", irep.get_sub(), irep_object);
  convert_named_sub_tree("namedSub", irep.get_named_sub(), irep_object);
  if(include_comments)
  {
    convert_named_sub_tree("comment", irep.get_comments(), irep_object);
  }
}

/*******************************************************************\

Function: json_irept::convert_sub_tree

  Inputs:
   sub_tree_id - the name to give the subtree in the parent object
   sub_trees - the list of subtrees to parse
   parent - the parent JSON object who should be added to

 Outputs:

 Purpose: To convert to JSON from a list of ireps that are in an
          unlabelled subtree. The parent JSON object will get a key
          called sub_tree_id and the value shall be an array of JSON
          objects generated from each of the sub trees

\*******************************************************************/

void json_irept::convert_sub_tree(
  const std::string &sub_tree_id,
  const irept::subt &sub_trees,
  json_objectt &parent) const
{
  if(sub_trees.size()>0)
  {
    json_arrayt sub_objects;
    for(const irept &sub_tree : sub_trees)
    {
      json_objectt sub_object;
      convert_from_irep(sub_tree, sub_object);
      sub_objects.push_back(sub_object);
    }
    parent[sub_tree_id]=sub_objects;
  }
}

/*******************************************************************\

Function: json_irept::convert_named_sub_tree

  Inputs:
   sub_tree_id - the name to give the subtree in the parent object
   sub_trees - the map of subtrees to parse
   parent - the parent JSON object who should be added to

 Outputs:

 Purpose: To convert to JSON from a map of ireps that are in a
          named subtree. The parent JSON object will get a key
          called sub_tree_id and the value shall be a JSON object
          whose keys shall be the name of the sub tree and the value
          will be the object generated from the sub tree.

\*******************************************************************/

void json_irept::convert_named_sub_tree(
  const std::string &sub_tree_id,
  const irept::named_subt &sub_trees,
  json_objectt &parent) const
{
  if(sub_trees.size()>0)
  {
    json_objectt sub_objects;
    for(const auto &sub_tree : sub_trees)
    {
      json_objectt sub_object;
      convert_from_irep(sub_tree.second, sub_object);
      sub_objects[id2string(sub_tree.first)]=sub_object;
    }
    parent[sub_tree_id]=sub_objects;
  }
}

/*******************************************************************\

Function: json_irept::convert_from_json

  Inputs: input - json object to convert

 Outputs: result - irep equivalent of input

 Purpose: Deserialize a JSON irep representation.

\*******************************************************************/

void json_irept::convert_from_json(const jsont& in, irept &result) const
{
  bool found_id=false;
  for(const auto& keyval : in.object)
  {
    if(keyval.first=="id")
      found_id=true;
    else if(keyval.first!="sub" &&
            keyval.first!="namedSub" &&
            keyval.first!="comment")
    {
      throw "Found unexpected key in JSON input: '" + keyval.first + "'";
    }
  }

  if(!found_id)
    throw "Irep JSON representation must have a key 'id'";

  result.id(in["id"].value);

  if(in.object.count("sub"))
  {
    for(const auto& sub : in["sub"].array)
    {
      result.get_sub().push_back(irept());
      convert_from_json(sub, result.get_sub().back());
    }
  }

  if(in.object.count("namedSub"))
  {
    for(const auto& named_sub : in["namedSub"].object)
      convert_from_json(named_sub.second, result.get_named_sub()[named_sub.first]);
  }

  if(in.object.count("comment"))
  {
    for(const auto& comment : in["comment"].object)
      convert_from_json(comment.second, result.get_comments()[comment.first]);
  }
}
