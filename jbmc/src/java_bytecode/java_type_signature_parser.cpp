// Copyright 2019 Diffblue Limited.

/// \file
/// Parser for Java type signatures

#include "java_type_signature_parser.h"
#include <ostream>
#include <util/parsable_string.h>

#include "java_types.h"

///////////////////////////////////////////////////////////
// static parse functions

static std::shared_ptr<java_ref_type_signaturet> parse_class_type(
  parsable_stringt &type_string,
  const java_generic_type_parameter_mapt &parameters);

static void parse_type_parameter_bounds(
  parsable_stringt &parameter_string,
  const java_generic_type_parameter_mapt &outer_parameters,
  const std::shared_ptr<java_generic_type_parametert> &result);

/// Parse a java_value_type_signaturet from a parsable_stringt pointing at an
/// appropriate part of a type signature
/// \param type_string A parsable_stringt pointing at an appropriate part of a
///   type signature
/// \param parameters A map giving the parameters in scope for this signature
/// \return The parsed java_value_type_signaturet
static std::shared_ptr<java_value_type_signaturet> parse_type(
  parsable_stringt &type_string,
  const java_generic_type_parameter_mapt &parameters)
{
  char first =
    type_string.get_first("Expected type string at end of signature");
  switch(first)
  {
  case 'B':
  case 'F':
  case 'D':
  case 'I':
  case 'C':
  case 'S':
  case 'Z':
  case 'V':
  case 'J':
    return std::make_shared<java_primitive_type_signaturet>(first);
  case '[':
    return std::make_shared<java_array_type_signaturet>(
      parse_type(type_string, parameters));
  case 'L': // Class type
    return parse_class_type(type_string, parameters);
  case 'T': // Type parameter
  {
    parsable_stringt parameter_name = type_string.split_at_first(
      ';', "Type parameter reference doesn't have closing semicolon");
    auto parameter = parameters.find(parameter_name);
    if(parameter == parameters.end())
      return std::make_shared<java_generic_type_parametert>(parameter_name,
        true);
    return parameter->second;
  }
  case '*': // Wildcard
    return std::make_shared<java_generic_type_parametert>();
  case '+': // Wildcard extends
  {
    std::shared_ptr<java_generic_type_parametert> result =
      std::make_shared<java_generic_type_parametert>(true);
    parse_type_parameter_bounds(type_string, parameters, result);
    return result;
  }
  case '-': // Wildcard super
  {
    std::shared_ptr<java_generic_type_parametert> result =
      std::make_shared<java_generic_type_parametert>(false);
    parse_type_parameter_bounds(type_string, parameters, result);
    return result;
  }
  default:
    throw unsupported_java_class_signature_exceptiont(
      std::string("Unknown type signature starting with ") + first);
  }
}

/// Parse the signature of a reference to a class type
/// \param type_string A parsable_stringt starting at the type signature of a
///   reference to a class
/// \param parameters The generic type parameters that may appear in the type
/// \return The parsed type
static std::shared_ptr<java_ref_type_signaturet> parse_class_type(
  parsable_stringt &type_string,
  const java_generic_type_parameter_mapt &parameters)
{
  // Check if a < or a . occurs before a ;
  std::pair<parsable_stringt, char> class_name_and_next =
    type_string.split_at_first_of(
      "<.;", "Class type doesn't have closing semicolon");
  java_type_signature_listt type_arguments;
  std::shared_ptr<java_ref_type_signaturet> inner_class;
  if(class_name_and_next.second == '<')
  {
    do
    {
      type_arguments.push_back(parse_type(type_string, parameters));
    } while(!type_string.try_skip('>'));
    if(type_string.try_skip(('.')))
      inner_class = parse_class_type(type_string, parameters);
    else
    {
      type_string.skip(
        ';', "Class type with type arguments doesn't have closing semicolon");
    }
  }
  else if(class_name_and_next.second == '.')
  {
    inner_class = parse_class_type(type_string, parameters);
  }
  return std::make_shared<java_ref_type_signaturet>(
    class_name_and_next.first, std::move(type_arguments), inner_class);
}

/// Parse a reference to a generic type parameter
/// \param parameter_string A parsable_stringt starting at the type signature
///   of a type parameter
/// \return The parsed type parameter
static std::shared_ptr<java_generic_type_parametert> parse_type_parameter(
  parsable_stringt &parameter_string,
  const java_generic_type_parameter_mapt &outer_parameters)
{
  std::shared_ptr<java_generic_type_parametert> result =
    std::make_shared<java_generic_type_parametert>(
      parameter_string.split_at_first(':', "No colon in type parameter bound"));
  parse_type_parameter_bounds(parameter_string, outer_parameters, result);
  return result;
}

/// Parse the bounds of a generic type parameter
/// \param parameter_string A parsable_stringt starting at the type signature
///   of a type parameter's bounds
/// \param result The parsed type parameter to add bounds to
static void parse_type_parameter_bounds(
  parsable_stringt &parameter_string,
  const java_generic_type_parameter_mapt &outer_parameters,
  const std::shared_ptr<java_generic_type_parametert> &result)
{
  java_generic_type_parameter_mapt parameter_map = outer_parameters;
  // Allow recursive definitions where the bound refers to the parameter itself
  parameter_map.emplace(result->name, result);
  if(!parameter_string.starts_with(':'))
    result->class_bound = parse_type(parameter_string, parameter_map);
  while(parameter_string.try_skip(':'))
  {
    result->interface_bounds.push_back(
      parse_type(parameter_string, parameter_map));
  }
  INVARIANT(
    result->class_bound != nullptr || !result->interface_bounds.empty(),
    "All type parameters have at least one bound");
}

/// Parse an optional collection of formal type parameters (e.g. on generic
/// methods of non-generic classes, generic static methods or generic classes).
/// \param parameters_string A parsable_stringt starting at where the
///   collection would appear
/// \return The parsed java_generic_type_parameter_listt
/// \example
/// This java method: static void <T, U extends V> foo(T t, U u, int x)
/// Would have this signature: <T:Ljava/lang/Object;U:LV;>(TT;TU;I)V
static java_generic_type_parameter_listt parse_type_parameters(
  parsable_stringt &parameters_string,
  const java_generic_type_parameter_mapt &outer_parameters)
{
  java_generic_type_parameter_listt parameter_list;
  java_generic_type_parameter_mapt parameter_map = outer_parameters;
  if(parameters_string.try_skip('<'))
  {
    do
    {
      parameter_list.push_back(parse_type_parameter(parameters_string,
        outer_parameters));
      parameter_map.emplace(parameter_list.back()->name, parameter_list.back());
    } while(!parameters_string.try_skip('>'));

    // Now we know about them all, resolve references:
    auto resolve_dangling_ref = [&](const java_value_type_signaturet &parent,
     std::shared_ptr<java_value_type_signaturet> &child) {
      if(auto child_arg =
        std::dynamic_pointer_cast<java_generic_type_parametert>(child)) {
        if(child_arg->is_dangling_reference()) {
          auto resolved = parameter_map.find(child_arg->name);
          if(resolved == parameter_map.end()) {
            throw parse_exceptiont("Dangling reference to generic parameter "
            + child_arg->name);
          }
          else {
            child = resolved->second;
          }
        }
      }
    };

    for(auto &parameter : parameter_list) {
      parameter->apply_visitor(resolve_dangling_ref);
    }
  }
  return parameter_list;
}


///////////////////////////////////////////////////////////
// java_type_signaturet derivatives

std::shared_ptr<java_value_type_signaturet>
java_value_type_signaturet::parse_single_value_type(
  const std::string &type_string,
  const java_generic_type_parameter_mapt &parameter_map)
{
  parsable_stringt type_str = type_string;
  std::shared_ptr<java_value_type_signaturet> type =
    parse_type(type_str, parameter_map);
  if(!type_str.empty())
    throw parse_exceptiont("Extra content after type signature");
  return type;
}

std::ostream &
operator<<(std::ostream &stm, const java_type_signature_listt &types)
{
  bool first = true;
  for(const std::shared_ptr<java_value_type_signaturet> &type : types)
  {
    if(!first)
      stm << ", ";
    else
      first = false;
    stm << *type;
  }
  return stm;
}

java_generic_type_parametert::java_generic_type_parametert()
  : java_generic_type_parametert(false)
{
  class_bound = std::make_shared<java_ref_type_signaturet>(
    "java/lang/Object",
    java_type_signature_listt {},
    nullptr);
}

std::string fresh_wildcard_name() {
  static std::size_t idx = 0;
  return std::string("Wildcard") + std::to_string(idx++);
}

typet java_generic_type_parametert::get_type(
  const std::string &class_name_prefix,
  bool include_bounds) const
{
  PRECONDITION(!is_dangling);
  // We currently only support one bound per variable, use the first
  const java_value_type_signaturet &bound_sig =
    *(class_bound != nullptr ? class_bound : interface_bounds[0]);
  typet bound = (include_bounds || is_wild())
                  ? bound_sig.get_type(class_name_prefix, false)
                  : bound_sig.get_raw_type();
  return java_generic_parametert(
    class_name_prefix + "::" + name, to_struct_tag_type(bound.subtype()));
}

void java_generic_type_parametert::full_output(
  std::ostream &stm,
  bool show_bounds) const
{
  stm << (is_wild() ? "?" : name);
  if(show_bounds)
  {
    stm << (bounds_are_upper ? " extends " : " super ");
    bool first = true;
    if(class_bound != nullptr)
    {
      stm << *class_bound;
      first = false;
    }
    for(const std::shared_ptr<java_value_type_signaturet> &interface_bound :
        interface_bounds)
    {
      if(!first)
        stm << " & ";
      else
        first = false;
      stm << *interface_bound;
    }
  }
}

void java_generic_type_parametert::collect_class_dependencies_from_bounds(
  std::set<irep_idt> &deps) const
{
  if(class_bound != nullptr)
    class_bound->collect_class_dependencies(deps);
  for(const std::shared_ptr<java_value_type_signaturet> &interface_bound :
      interface_bounds)
  {
    interface_bound->collect_class_dependencies(deps);
  }
}

typet java_generic_type_parametert::get_raw_type() const
{
  return (class_bound == nullptr ? interface_bounds[0] : class_bound)
    ->get_raw_type();
}

typet java_primitive_type_signaturet::get_type(
  const std::string &class_name_prefix,
  bool) const
{
  switch(type_character)
  {
  case 'B':
    return java_byte_type();
  case 'F':
    return java_float_type();
  case 'D':
    return java_double_type();
  case 'I':
    return java_int_type();
  case 'C':
    return java_char_type();
  case 'S':
    return java_short_type();
  case 'Z':
    return java_boolean_type();
  case 'V':
    return java_void_type();
  case 'J':
    return java_long_type();
  default:
    UNREACHABLE;
  }
}

void java_primitive_type_signaturet::output(std::ostream &stm) const
{
  switch(type_character)
  {
  case 'B':
    stm << "byte";
    break;
  case 'F':
    stm << "float";
    break;
  case 'D':
    stm << "double";
    break;
  case 'I':
    stm << "int";
    break;
  case 'C':
    stm << "char";
    break;
  case 'S':
    stm << "short";
    break;
  case 'Z':
    stm << "boolean";
    break;
  case 'V':
    stm << "void";
    break;
  case 'J':
    stm << "long";
    break;
  default:
    UNREACHABLE;
  }
}

typet java_primitive_type_signaturet::get_raw_type() const
{
  return get_type("", false);
}

void java_array_type_signaturet::collect_class_dependencies(
  std::set<irep_idt> &deps) const
{
  element_type->collect_class_dependencies(deps);
}

typet java_array_type_signaturet::make_array_type(
  const typet &result_element_type) const
{
  // If this is a reference array, we generate a plain array[reference]
  // with void* members, but note the real type in ID_C_element_type.
  std::shared_ptr<java_primitive_type_signaturet> primitive_elt_type =
    std::dynamic_pointer_cast<java_primitive_type_signaturet>(element_type);
  typet result = java_array_type(static_cast<char>(std::tolower(
    primitive_elt_type == nullptr ? 'A' : primitive_elt_type->type_character)));
  result.subtype().set(ID_element_type, result_element_type);
  return result;
}

typet java_array_type_signaturet::get_type(
  const std::string &class_name_prefix,
  bool include_bounds) const
{
  return make_array_type(
    element_type->get_type(class_name_prefix, include_bounds));
}

void java_array_type_signaturet::output(std::ostream &stm) const
{
  stm << *element_type << "[]";
}

typet java_array_type_signaturet::get_raw_type() const
{
  return make_array_type(element_type->get_raw_type());
}

java_ref_type_signaturet::java_ref_type_signaturet(
  std::string class_name,
  java_type_signature_listt type_arguments,
  std::shared_ptr<java_ref_type_signaturet> inner_class)
  : type_arguments(std::move(type_arguments)),
    inner_class(std::move(inner_class))
{
  PRECONDITION(class_name.find('.') == std::string::npos);
  std::replace(class_name.begin(), class_name.end(), '/', '.');
  this->class_name = std::move(class_name);
}

void java_ref_type_signaturet::collect_class_dependencies(
  std::set<irep_idt> &deps) const
{
  deps.insert(class_name);
  for(const std::shared_ptr<java_value_type_signaturet> &type_arg :
      type_arguments)
  {
    type_arg->collect_class_dependencies(deps);
  }
}

typet java_ref_type_signaturet::get_type(
  const std::string &class_name_prefix,
  bool include_bounds) const
{
  PRECONDITION(!inner_class); // Currently not supported

  std::string identifier = "java::" + class_name;
  struct_tag_typet struct_tag_type(identifier);
  struct_tag_type.set(ID_C_base_name, class_name);

  if(type_arguments.empty())
    return java_reference_type(struct_tag_type);

  java_generic_typet result(struct_tag_type);
  std::transform(
    type_arguments.begin(),
    type_arguments.end(),
    std::back_inserter(result.generic_type_arguments()),
    [&](const std::shared_ptr<java_value_type_signaturet> &type_argument) {
      const typet type =
        type_argument->get_type(class_name_prefix, include_bounds);
      const reference_typet *ref_type =
        type_try_dynamic_cast<reference_typet>(type);
      if(ref_type == nullptr)
        throw unsupported_java_class_signature_exceptiont(
          "All generic type arguments should be references");
      return *ref_type;
    });
  return std::move(result);
}

void java_ref_type_signaturet::output(std::ostream &stm) const
{
  stm << class_name;
  if(!type_arguments.empty())
    stm << "<" << type_arguments << ">";
  if(inner_class)
    stm << "." << *inner_class;
}

typet java_ref_type_signaturet::get_raw_type() const
{
  return get_without_arguments().get_type("", false);
}

std::ostream &operator<<(
  std::ostream &stm,
  const java_generic_type_parameter_listt &parameters)
{
  bool first = true;
  for(const std::shared_ptr<java_generic_type_parametert> &parameter :
      parameters)
  {
    if(!first)
      stm << ", ";
    else
      first = false;
    stm << *parameter;
  }
  return stm;
}


///////////////////////////////////////////////////////////
// java_class_type_signaturet

java_class_type_signaturet::java_class_type_signaturet(
  const std::string &type_string,
  const java_generic_type_parameter_mapt &outer_parameter_map)
{
  parsable_stringt type_str = type_string;
  explicit_type_parameters =
    parse_type_parameters(type_str, outer_parameter_map);
  type_parameter_map = outer_parameter_map;
  for(const std::shared_ptr<java_generic_type_parametert> &parameter :
      explicit_type_parameters)
  {
    type_parameter_map.emplace(parameter->name, parameter);
  }
  do
    bases.push_back(parse_type(type_str, type_parameter_map));
  while(!type_str.empty());
}

const java_class_type_signaturet java_class_type_signaturet::object_type;

void java_class_type_signaturet::collect_class_dependencies(
  std::set<irep_idt> &deps) const
{
  for(const std::shared_ptr<java_generic_type_parametert> &parameter :
      explicit_type_parameters)
  {
    parameter->collect_class_dependencies_from_declaration(deps);
  }
  for(const std::shared_ptr<java_value_type_signaturet> &base : bases)
    base->collect_class_dependencies(deps);
}

typet java_class_type_signaturet::get_type(
  const std::string &class_name_prefix,
  bool include_bounds) const
{
  java_class_typet result;
  if(!explicit_type_parameters.empty())
    result = java_generic_class_typet{};
  // Only populate the sections that we have generic info for -- i.e., the
  // formal generic parameters and the base types -- as the rest is still
  // done by java_bytecode_convert_classt::convert.
  for(const auto &parameter : explicit_type_parameters) {
    to_java_generic_class_type(result).generic_types().push_back
    (parameter->get_parameter_type
    (class_name_prefix, include_bounds));
  }

  for(const auto &base : bases) {
    auto base_type = to_java_reference_type(base->get_type(class_name_prefix,
      include_bounds));

    result.bases().emplace_back(to_struct_tag_type(base_type.subtype()));
  }

  return std::move(result);
}

void java_class_type_signaturet::output(std::ostream &stm) const
{
  stm << "class Foo";
  if(!explicit_type_parameters.empty())
  {
    stm << "<";
    bool first = true;
    for(const std::shared_ptr<java_generic_type_parametert> &parameter :
        explicit_type_parameters)
    {
      if(!first)
        stm << ", ";
      else
        first = false;
      parameter->full_output(stm, true);
    }
    stm << ">";
  }
  stm << " extends " << *bases[0];
  if(bases.size() != 1)
  {
    stm << " implements ";
    bool first = true;
    for(std::size_t i = 1; i < bases.size(); ++i)
    {
      if(!first)
        stm << ", ";
      else
        first = false;
      stm << *bases[i];
    }
  }
}


///////////////////////////////////////////////////////////
// java_method_type_signaturet

java_method_type_signaturet::java_method_type_signaturet(
  const std::string &type_string,
  java_generic_type_parameter_mapt class_parameter_map)
{
  parsable_stringt type_str = type_string;
  explicit_type_parameters =
    parse_type_parameters(type_str, class_parameter_map);
  type_parameter_map = class_parameter_map;
  for(const std::shared_ptr<java_generic_type_parametert> &parameter :
      explicit_type_parameters)
  {
    type_parameter_map.emplace(parameter->name, parameter);
  }
  type_str.skip('(', "No '(' at start of method signature");
  while(!type_str.try_skip(')'))
    parameters.push_back(parse_type(type_str, type_parameter_map));
  return_type = parse_type(type_str, type_parameter_map);
  if(!type_str.empty()) {
    // Allow a generic 'throws' spec, which we currently don't parse.
    if(!type_str.starts_with('^'))
      throw parse_exceptiont("Extra content after type signature");
  }
}

void java_method_type_signaturet::collect_class_dependencies(
  std::set<irep_idt> &deps) const
{
  for(const std::shared_ptr<java_generic_type_parametert> &parameter :
      explicit_type_parameters)
  {
    parameter->collect_class_dependencies_from_declaration(deps);
  }
  for(const std::shared_ptr<java_value_type_signaturet> &param : parameters)
    param->collect_class_dependencies(deps);
  return_type->collect_class_dependencies(deps);
}

typet java_method_type_signaturet::get_type(
  const std::string &class_name_prefix,
  bool include_bounds) const
{
  code_typet::parameterst parameter_types;
  std::transform(
    parameters.begin(),
    parameters.end(),
    std::back_inserter(parameter_types),
    [&](const std::shared_ptr<java_value_type_signaturet> &parameter) {
      return code_typet::parametert(
        parameter->get_type(class_name_prefix, include_bounds));
    });
  return java_method_typet{
    std::move(parameter_types),
    return_type->get_type(class_name_prefix, include_bounds)};
}

void java_method_type_signaturet::output(std::ostream &stm) const
{
  stm << *return_type << " f";
  if(!explicit_type_parameters.empty())
  {
    stm << "<";
    bool first = true;
    for(const std::shared_ptr<java_generic_type_parametert> &parameter :
        explicit_type_parameters)
    {
      if(!first)
        stm << ", ";
      else
        first = false;
      parameter->full_output(stm, true);
    }
    stm << ">";
  }
  stm << "(" << parameters << ")";
}
