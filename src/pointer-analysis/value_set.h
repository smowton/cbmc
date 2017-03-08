/*******************************************************************\

Module: Value Set

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

/// \file
/// Value Set

#ifndef CPROVER_POINTER_ANALYSIS_VALUE_SET_H
#define CPROVER_POINTER_ANALYSIS_VALUE_SET_H

#include <set>

#include <util/mp_arith.h>
#include <util/reference_counting.h>

#include "object_numbering.h"
#include "value_sets.h"

class namespacet;

class objectt
{
 public:
 objectt():offset_is_set(false)
  {
  }

  explicit objectt(const mp_integer &_offset):
  offset(_offset),
    offset_is_set(true)
    {
    }

  mp_integer offset;
  bool offset_is_set;
  bool offset_is_zero() const
  { return offset_is_set && offset.is_zero(); }
};

class object_map_dt
{
  typedef std::map<unsigned, objectt> data_typet;
  data_typet data;

 public:
  // NOLINTNEXTLINE(readability/identifiers)
  typedef data_typet::iterator iterator;
  // NOLINTNEXTLINE(readability/identifiers)
  typedef data_typet::const_iterator const_iterator;
  // NOLINTNEXTLINE(readability/identifiers)
  typedef data_typet::value_type value_type;
  // NOLINTNEXTLINE(readability/identifiers)
  typedef data_typet::key_type key_type;

  iterator begin() { return data.begin(); }
  const_iterator begin() const { return data.begin(); }
  const_iterator cbegin() const { return data.cbegin(); }

  iterator end() { return data.end(); }
  const_iterator end() const { return data.end(); }
  const_iterator cend() const { return data.cend(); }

  size_t size() const { return data.size(); }
  bool empty() const { return data.empty(); }

  void erase(key_type i) { data.erase(i); }
  void erase(const_iterator it) { data.erase(it); }

  objectt &operator[](key_type i) { return data[i]; }
  objectt &at(key_type i) { return data.at(i); }
  const objectt &at(key_type i) const { return data.at(i); }

  template <typename It>
    void insert(It b, It e) { data.insert(b, e); }

  template <typename T>
    const_iterator find(T &&t) const { return data.find(std::forward<T>(t)); }

  static const object_map_dt blank;

  object_map_dt()=default;

 protected:
  ~object_map_dt()=default;
};

typedef reference_counting<object_map_dt> object_mapt;

class value_set_opst
{
 public:
  virtual void apply_code(
    const codet &code,
    const namespacet &ns)=0;

  virtual void assign(
    const exprt &lhs,
    const exprt &rhs,
    const namespacet &ns,
    bool is_simplified,
    bool add_to_sets)=0;

  virtual void assign_rec(
    const exprt &lhs,
    const object_mapt &values_rhs,
    const std::string &suffix,
    const namespacet &ns,
    bool add_to_sets)=0;

  virtual void get_value_set(
    const exprt &expr,
    object_mapt &dest,
    const namespacet &ns,
    bool is_simplified) const=0;

  virtual void get_value_set_rec(
    const exprt &expr,
    object_mapt &dest,
    const std::string &suffix,
    const typet &original_type,
    const namespacet &ns) const=0;

  virtual void get_reference_set(
    const exprt &expr,
    object_mapt &dest,
    const namespacet &ns) const=0;

  virtual void get_reference_set_rec(
    const exprt &expr,
    object_mapt &dest,
    const namespacet &ns) const=0;
};

/// Base value-set functionality, used unmodified
/// in value_sett below, or used/inherited by a customisation
class basic_value_sett:public value_set_opst
{
public:
  basic_value_sett():
    location_number(0),
    custom_value_set_ops(*this)
  {
  }

 basic_value_sett(value_set_opst &custom_ops):
    location_number(0),
    custom_value_set_ops(custom_ops)
  {
  }

  // Can't define a sensible copy-constructor: where would my
  // custom-value-set-ops pointer come from?
  basic_value_sett(const basic_value_sett &other)=delete;

  basic_value_sett &operator=(const basic_value_sett &other)
  {
    // Do possibly-throwing operation first, and against a temporary
    // such that if it does this object remains as-was.
    auto temp_values_copy(other.values);
    values.swap(temp_values_copy);

    location_number=other.get_location_number();

    // Keep my custom-value-set-ops pointer as before.
    return *this;
  }

  static bool field_sensitive(
    const irep_idt &id,
    const typet &type,
    const namespacet &);

  static object_numberingt object_numbering;

  typedef irep_idt idt;

  void set(object_mapt &dest, const object_map_dt::value_type &it) const
  {
    dest.write()[it.first]=it.second;
  }

  bool insert(object_mapt &dest, const object_map_dt::value_type &it) const
  {
    return insert(dest, it.first, it.second);
  }

  bool insert(object_mapt &dest, const exprt &src) const
  {
    return insert(dest, object_numbering.number(src), objectt());
  }

  bool insert(
    object_mapt &dest,
    const exprt &src,
    const mp_integer &offset) const
  {
    return insert(dest, object_numbering.number(src), objectt(offset));
  }

  bool insert(object_mapt &dest, unsigned n, const objectt &object) const;

  bool insert(object_mapt &dest, const exprt &expr, const objectt &object) const
  {
    return insert(dest, object_numbering.number(expr), object);
  }

  struct entryt
  {
    object_mapt object_map;
    idt identifier;
    std::string suffix;

    entryt()
    {
    }

    entryt(const idt &_identifier, const std::string &_suffix):
      identifier(_identifier),
      suffix(_suffix)
    {
    }
  };

  exprt to_expr(const object_map_dt::value_type &it) const;

  typedef std::set<exprt> expr_sett;

  typedef std::set<unsigned int> dynamic_object_id_sett;

  #ifdef USE_DSTRING
  typedef std::map<idt, entryt> valuest;
  #else
  typedef std::unordered_map<idt, entryt, string_hash> valuest;
  #endif

  void read_value_set(
    const exprt &expr,
    value_setst::valuest &dest,
    const namespacet &ns) const;

  expr_sett &get(
    const idt &identifier,
    const std::string &suffix);

  void make_any()
  {
    values.clear();
  }

  void clear()
  {
    values.clear();
  }

  entryt &get_entry(
    const entryt &e, const typet &type,
    const namespacet &);

  void output(
    const namespacet &ns,
    std::ostream &out) const;

  valuest values;

  // true = added something new
  bool make_union(object_mapt &dest, const object_mapt &src) const;

  // true = added something new
  bool make_union(const valuest &new_values);

  // true = added something new
  bool make_union(const basic_value_sett &new_values)
  {
    return make_union(new_values.values);
  }

  void guard(
    const exprt &expr,
    const namespacet &ns);

  void apply_code(
    const codet &code,
    const namespacet &ns) override;

  void assign(
    const exprt &lhs,
    const exprt &rhs,
    const namespacet &ns,
    bool is_simplified,
    bool add_to_sets) override;

  void do_function_call(
    const irep_idt &function,
    const exprt::operandst &arguments,
    const namespacet &ns);

  // edge back to call site
  void do_end_function(
    const exprt &lhs,
    const namespacet &ns);

  void read_reference_set(
    const exprt &expr,
    value_setst::valuest &dest,
    const namespacet &ns) const;

  bool eval_pointer_offset(
    exprt &expr,
    const namespacet &ns) const;

  void get_value_set_rec(
    const exprt &expr,
    object_mapt &dest,
    const std::string &suffix,
    const typet &original_type,
    const namespacet &ns) const override;

  void get_value_set(
    const exprt &expr,
    object_mapt &dest,
    const namespacet &ns,
    bool is_simplified) const override;

  void get_reference_set(
    const exprt &expr,
    object_mapt &dest,
    const namespacet &ns) const override
  {
    custom_value_set_ops.get_reference_set_rec(expr, dest, ns);
  }

  void get_reference_set_rec(
    const exprt &expr,
    object_mapt &dest,
    const namespacet &ns) const override;

  void dereference_rec(
    const exprt &src,
    exprt &dest) const;

  void assign_rec(
    const exprt &lhs,
    const object_mapt &values_rhs,
    const std::string &suffix,
    const namespacet &ns,
    bool add_to_sets) override;

  void do_free(
    const exprt &op,
    const namespacet &ns);

  exprt make_member(
    const exprt &src,
    const irep_idt &component_name,
    const namespacet &ns);

  void set_location_number(unsigned n)
  {
    location_number=n;
  }

  unsigned get_location_number() const
  {
    return location_number;
  }

 protected:
  /// For use only by value_sett
  basic_value_sett(
    const valuest &values,
    unsigned location_number):
  values(values),
  location_number(location_number),
  custom_value_set_ops(*this)
  {
  }

 private:
  /// Internal calls to any of the methods defined in value_set_opst should
  /// be dispatched against this reference, to give an opportunity for code
  /// wishing to customise their behaviour to intervene.
  unsigned location_number;
  value_set_opst &custom_value_set_ops;
};

/// Uses basic_value_sett without a custom_value_set_ops pointer, thereby
/// permitting a copy-constructor definition.
class value_sett:public basic_value_sett
{
 public:
  value_sett():
    basic_value_sett()
  {
  }

  value_sett(const value_sett &other):
    basic_value_sett(other.values, other.get_location_number())
  {
  }
};

/// Heritable skeleton for a customisation of basic_value_sett, which has
/// a basic_value_sett and forwards methods that aren't customisation points
/// but which are expected by value_set_domaint.
/// This also provides a likely-sensible constructor and copy-constructor.
template<class underlying_value_sett> class custom_value_sett
{
public:
  /// Builds a test_value_set, configuring our underlying_value_set object to
  /// defer to our custom logic
  custom_value_sett(value_set_opst *custom_ops):
    underlying_value_set(*custom_ops)
  {
  }

  /// Copies a custom_value_set, copying our underlying_value_set object
  /// but setting it to defer to a given instance's custom logic
  custom_value_sett(
    value_set_opst *custom_ops,
    const custom_value_sett<underlying_value_sett> &other):
    underlying_value_set(*custom_ops)
  {
    underlying_value_set=other.underlying_value_set;
  }

  custom_value_sett &operator=(const custom_value_sett &other)=default;

  void read_reference_set(
    const exprt &expr,
    value_setst::valuest &dest,
    const namespacet &ns) const
  {
    underlying_value_set.read_reference_set(expr, dest, ns);
  }

  void read_value_set(
    const exprt &expr,
    value_setst::valuest &dest,
    const namespacet &ns) const
  {
    underlying_value_set.read_value_set(expr, dest, ns);
  }

  void output(
    const namespacet &ns,
    std::ostream &out) const
  {
    underlying_value_set.output(ns, out);
  }

  void clear()
  {
    underlying_value_set.clear();
  }

  void do_end_function(
    const exprt &lhs,
    const namespacet &ns)
  {
    underlying_value_set.do_end_function(lhs, ns);
  }

  void do_function_call(
    const irep_idt &function,
    const exprt::operandst &arguments,
    const namespacet &ns)
  {
    underlying_value_set.do_function_call(function, arguments, ns);
  }

  void guard(
    const exprt &expr,
    const namespacet &ns)
  {
    underlying_value_set.guard(expr, ns);
  }

  void set_location_number(unsigned n)
  {
    underlying_value_set.set_location_number(n);
  }

  unsigned get_location_number() const
  {
    return underlying_value_set.get_location_number();
  }

  bool make_union(const custom_value_sett<underlying_value_sett> &other)
  {
    return underlying_value_set.make_union(other.underlying_value_set);
  }

protected:
  underlying_value_sett underlying_value_set;
};

#endif // CPROVER_POINTER_ANALYSIS_VALUE_SET_H
