
#include "taint_summary_json.h"

#include "util/json_irep.h"

#include <algorithm>
#include <memory>

static json_objectt taint_to_json(const taint_svaluet& svalue)
{
  json_objectt ret;
  ret["is_top"]=jsont::json_boolean(svalue.is_top());
  ret["is_bottom"]=jsont::json_boolean(svalue.is_bottom());  
  json_arrayt taints;
  for(const auto& sym : svalue.expression())
    taints.push_back(json_stringt(sym));
  ret["taints"]=taints;
  return ret;
}

static json_arrayt taint_map_to_json(
    const taint_map_from_lvalues_to_svaluest& map)
{
  json_arrayt values;
  for(const auto& elem : map)
  {
    json_objectt value;
    value["expr"]=irep_to_json(elem.first);
    value["taint"]=taint_to_json(elem.second);
    values.push_back(value);
  }
  return values;
}

json_objectt taint_summaryt::to_json() const
{
  json_objectt root;
  root["inputs"]=taint_map_to_json(input());
  root["outputs"]=taint_map_to_json(output());
  return root;
}

template<class maptype, class keytype>
void assert_has_keys(const maptype& m,
                     const std::vector<keytype>& expected, const char* detail)
{
  std::vector<keytype> keys;
  for(const auto& keyval : m)
    keys.push_back(keyval.first);
  std::sort(keys.begin(),keys.end());
  if(keys != expected)
    throw detail;
}

static bool bool_from_json(const jsont& js)
{
  if(js.is_true())
    return true;
  else if(js.is_false())
    return false;
  else
    throw "JSON object is not a boolean";
}

static taint_svaluet taint_from_json(const jsont& js)
{
  assert(js.is_object());
  const auto& js_object=static_cast<const json_objectt&>(js);
  assert_has_keys(js.object,
		  std::vector<std::string>({"is_bottom","is_top","taints"}),
		  "JSON object is not an svalue");
  taint_svaluet::expressiont taints;
  const jsont& js_taints=js_object["taints"];
  assert(js_taints.is_array());
  for(const auto& js_taint : js_taints.array)
  {
    assert(js_taint.is_string());
    taints.insert(js_taint.value);
  }
  return taint_svaluet(taints,
			       bool_from_json(js_object["is_bottom"]),
			       bool_from_json(js_object["is_top"]));
}

static taint_map_from_lvalues_to_svaluest taint_map_from_json(const jsont& js)
{
  assert(js.is_array());
  const auto& js_array=static_cast<const json_arrayt&>(js);
  taint_map_from_lvalues_to_svaluest ret;
  for(const auto& entry : js_array.array)
  {
    assert(entry.is_object());
    const auto& entry_obj=static_cast<const json_objectt&>(entry);
    assert_has_keys(entry_obj.object,
		    std::vector<std::string>({"expr","taint"}),
		    "JSON object is not a taint entry");
    irept irep=irep_from_json(entry_obj["expr"]);
    taint_svaluet taint=taint_from_json(entry_obj["taint"]);
    ret.insert(std::make_pair(static_cast<exprt&>(irep),taint));
  }
  return ret;
}

void taint_summaryt::from_json(const json_objectt& js)
{
  assert_has_keys(js.object,
		  std::vector<std::string>({"inputs","name","outputs"}),
		  "JSON object is not a taint summary");
  m_input=taint_map_from_json(js["inputs"]);
  m_output=taint_map_from_json(js["outputs"]);
}

