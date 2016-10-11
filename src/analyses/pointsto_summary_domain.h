/*******************************************************************\

Module: pointsto_summary_domain

Author: Marek Trtik

Date: Octomber 2016


@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_POINTSTO_SUMMARY_DOMAIN_H
#define CPROVER_POINTSTO_SUMMARY_DOMAIN_H

#include <summaries/summary.h>
#include <summaries/utility.h>
#include <goto-programs/goto_model.h>
#include <goto-programs/goto_functions.h>
#include <util/irep.h>
#include <util/msgstream.h>
#include <unordered_set>
#include <sstream>
#include <string>
#include <tuple>
#include <tuple>


class pointsto_expressiont;

template<typename T>
class pointesto_detail_is_expression
{
public:
  static const bool value = false;
};

template<>
class pointesto_detail_is_expression<pointsto_expressiont>
{
public:
  static const bool value = true;
};


template<typename T>
inline bool  pointsto_is_of(const irept& irep)
{
  return pointesto_detail_is_expression<T>::value || irep.id() == T::keyword();
}

template<typename T>
inline const T&  pointsto_as(const irept& irep)
{
  assert(pointsto_is_of<T>(irep));
  return static_cast<const T&>(irep);
}


class pointsto_expressiont : public irept
{
public:
  static dstring keyword();
  pointsto_expressiont(const dstring&  keyword);
};


class pointsto_set_of_offsetst : public irept
{
public:
  typedef std::unordered_set<irep_idt,dstring_hash>  offset_namest;

  static dstring keyword();

  pointsto_set_of_offsetst(
      const offset_namest&  offset_names,
      bool const is_exact
      );

  void  get_offset_names(offset_namest&  output_names) const;
  bool  is_exact() const;
};


class pointsto_address_shiftt
    : public irept
{
public:
  static dstring keyword();

  pointsto_address_shiftt(
      const pointsto_expressiont&  targets,
      const pointsto_set_of_offsetst&  offsets
      );

  const pointsto_expressiont&  get_targets() const;
  const pointsto_set_of_offsetst&  get_offsets() const;
};


class pointsto_symbolic_set_of_targetst
    : public pointsto_expressiont
{
public:
  static dstring keyword();

  pointsto_symbolic_set_of_targetst();
  const irep_idt&  get_symbolic_set_name() const;

private:
  static irep_idt  make_fresh_symbol_name();
};


class pointsto_set_of_concrete_targetst
    : public pointsto_expressiont
{
public:
  typedef std::tuple<irep_idt,unsigned int,irep_idt>  concrete_targett;
  typedef std::vector<concrete_targett>  concrete_targetst;

  static dstring keyword();

  pointsto_set_of_concrete_targetst(
      const irep_idt&  function_name,
      const unsigned int  location_number,
      const irep_idt&  target_name
      );
  pointsto_set_of_concrete_targetst(const concrete_targetst&  targets);

  std::size_t  get_num_targets() const;
  const irep_idt&  get_function_name(const std::size_t target_index) const;
  unsigned int  get_location_number(const std::size_t target_index) const;
  const irep_idt&  get_target_name(const std::size_t target_index) const;
};


class pointsto_address_dereferencet
    : public pointsto_expressiont
{
public:
  static dstring keyword();

  pointsto_address_dereferencet(
      const pointsto_address_shiftt&  address_shift
      );

  const pointsto_address_shiftt&  get_address_shift() const;
};


class pointsto_subtract_sets_of_targetst
    : public pointsto_expressiont
{
public:
  static dstring keyword();

  pointsto_subtract_sets_of_targetst(
      const pointsto_expressiont&  left,
      const pointsto_expressiont&  right
      );

  const pointsto_expressiont&  get_left() const;
  const pointsto_expressiont&  get_right() const;
};


class pointsto_union_sets_of_targetst
    : public pointsto_expressiont
{
public:
  static dstring keyword();

  pointsto_union_sets_of_targetst(
      const pointsto_expressiont&  left,
      const pointsto_expressiont&  right
      );

  const pointsto_expressiont&  get_left() const;
  const pointsto_expressiont&  get_right() const;
};


class pointsto_map_from_pointers_to_targetst
{
public:

  pointsto_map_from_pointers_to_targetst(
      const pointsto_expressiont&  set_of_pointers_,
      const pointsto_expressiont&  set_of_targets_
      );

  const pointsto_expressiont&  get_set_of_pointers() const noexcept
  { return set_of_pointers; }

  const pointsto_expressiont&  get_set_of_targets() const noexcept
  { return set_of_targets; }

private:
  pointsto_expressiont  set_of_pointers;
  pointsto_expressiont  set_of_targets;
};


class pointsto_summaryt
{
public:

  pointsto_summaryt(
      const pointsto_map_from_pointers_to_targetst&  mapping_of_symbols_,
      const std::vector<pointsto_map_from_pointers_to_targetst>&  rules_
      );

  const pointsto_map_from_pointers_to_targetst&
  get_mapping_of_symbols() const noexcept
  { return mapping_of_symbols; }

  const std::vector<pointsto_map_from_pointers_to_targetst>&
  get_rules() const noexcept
  { return rules; }

private:
  pointsto_map_from_pointers_to_targetst  mapping_of_symbols;
  std::vector<pointsto_map_from_pointers_to_targetst>  rules;
};

#endif
