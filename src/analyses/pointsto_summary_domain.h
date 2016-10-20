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
#include <unordered_map>
#include <sstream>
#include <string>
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

template<typename T>
inline const T*  pointsto_as(const irept* irep)
{
  if (pointsto_is_of<T>(*irep))
    return static_cast<const T*>(irep);
  return nullptr;
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
  typedef std::set<irep_idt>  offset_namest;

  static dstring keyword();

  pointsto_set_of_offsetst(
      const offset_namest&  offset_names,
      bool const is_exact
      );

  std::size_t  get_num_offsets() const;
  const irep_idt&  get_offset_name(const std::size_t offset_index) const;

  bool  is_exact() const;
  bool  contains(const irep_idt&  offset_name) const;
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


class pointsto_null_targett
    : public pointsto_expressiont
{
public:
  static dstring keyword();
  pointsto_null_targett();
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
  typedef std::set<irep_idt> target_namest;

  static dstring keyword();

  pointsto_set_of_concrete_targetst(
      const irep_idt&  target_name
      );
  pointsto_set_of_concrete_targetst(
      const target_namest&  targets
      );

  bool empty() const { return get_num_targets() == 0UL; }
  std::size_t  get_num_targets() const;
  const irep_idt&  get_target_name(const std::size_t target_index) const;

  bool  contains(const irep_idt&  target_name) const;
};


class pointsto_set_of_address_shifted_targetst
    : public pointsto_expressiont
{
public:
  static dstring keyword();

  pointsto_set_of_address_shifted_targetst(
      const pointsto_address_shiftt& shift
      );

  const pointsto_address_shiftt&  get_address_shift() const;
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
  typedef std::unordered_set<pointsto_expressiont,irep_hash,irep_full_eq>
          operants_sett;

  static dstring keyword();

  pointsto_union_sets_of_targetst(
      const pointsto_expressiont&  left,
      const pointsto_expressiont&  right
      );

  pointsto_union_sets_of_targetst(
      const operants_sett&  operands
      );

  std::size_t  get_num_operands() const;
  const pointsto_expressiont&  get_operand(
      const std::size_t operand_index
      ) const;
};


class pointsto_if_empty_then_elset
    : public pointsto_expressiont
{
public:
  static dstring keyword();

  pointsto_if_empty_then_elset(
      const pointsto_expressiont&  conditional_targets,
      const pointsto_expressiont&  true_branch_targets,
      const pointsto_expressiont&  false_branch_targets
      );

  const pointsto_expressiont&  get_conditional_targets() const;
  const pointsto_expressiont&  get_true_branch_targets() const;
  const pointsto_expressiont&  get_false_branch_targets() const;
};


typedef std::unordered_map<pointsto_expressiont,pointsto_expressiont,
                           irep_hash,irep_full_eq>
        pointsto_rulest;


pointsto_expressiont  pointsto_expression_empty_set_of_targets();
bool  pointsto_is_empty_set_of_targets(const pointsto_expressiont& a);


pointsto_expressiont  pointsto_expression_normalise(
    const pointsto_expressiont&  a
    );

//template<typename pointsto_expression_typet>
//pointsto_expression_typet pointsto_expression_normalise(
//    const pointsto_expression_typet& expression
//    )
//{
//  return pointsto_as<pointsto_expression_typet>(
//              pointsto_expression_normalise(
//                  static_cast<const pointsto_expressiont&>(expression)
//                  )
//              );
//}


pointsto_expressiont  pointsto_evaluate_expression(
    const pointsto_rulest&  domain_value,
    const pointsto_expressiont&  expression
    );

pointsto_expressiont  pointsto_evaluate_access_path(
    const pointsto_rulest&  domain_value,
    const access_path_to_memoryt&  access_path,
    const bool  as_lvalue,
    const irep_idt&  fn_name,
    const unsigned int  location_id,
    const namespacet&  ns
    );


pointsto_expressiont  pointsto_temp_prune_pure_locals(
    const pointsto_expressiont&  a,
    namespacet const&  ns
    );


#endif
