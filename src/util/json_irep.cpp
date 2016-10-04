
#include "json_irep.h"

#include <string>
#include <algorithm>

json_objectt irep_to_json(const irept& in)
{
  json_objectt root;
  root["id"]=json_stringt(id2string(in.id()));

  json_arrayt subs;
  for(const auto& sub : in.get_sub())
    subs.push_back(irep_to_json(sub));
  root["subs"]=std::move(subs);

  json_objectt named_subs;
  for(const auto& named_sub : in.get_named_sub())
    named_subs[id2string(named_sub.first)]=irep_to_json(named_sub.second);
  root["named_subs"]=std::move(named_subs);

  json_objectt comments;
  for(const auto& comment : in.get_comments())
    comments[id2string(comment.first)]=irep_to_json(comment.second);
  root["comments"]=std::move(comments);

  return root;
}

irept irep_from_json(const jsont& in)
{
  std::vector<std::string> have_keys;
  for(const auto& keyval : in.object)
    have_keys.push_back(keyval.first);
  std::sort(have_keys.begin(),have_keys.end());
  assert(have_keys == std::vector<std::string>({"comments", "id", "named_subs", "subs"}) && "Not a JSON-irep");

  irept to_return(in["id"].value);

  for(const auto& sub : in["subs"].array)
    to_return.get_sub().push_back(irep_from_json(sub));

  for(const auto& named_sub : in["named_subs"].object)
    to_return.get_named_sub()[named_sub.first]=irep_from_json(named_sub.second);

  for(const auto& comment : in["comments"].object)
    to_return.get_comments()[comment.first]=irep_from_json(comment.second);

  return to_return;    
}
