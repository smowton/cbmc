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

class pointsto_symbolic_set_of_targetst : public irept
{
public:
  static const dstring keyword()
  { return ID_pointsto_access_paths_definition_symbolic; }

  pointsto_symbolic_set_of_targetst(const irep_idt&  symbolic_set_name)
    : irept(keyword())
  {
    get_sub().push_back(irept(symbolic_set_name));
  }

  const irep_idt&  get_symbolic_set_name() const
  { return get_sub().back().id(); }
};

class pointsto_set_of_concrete_targetst : public irept
{
public:
  static const dstring keyword()
  { return ID_pointsto_access_paths_definition_concrete; }

  typedef std::tuple<irep_idt,unsigned int,irep_idt>  concrete_targett;
  typedef std::vector<concrete_targett>  concrete_targetst;

  pointsto_set_of_concrete_targetst(
      const irep_idt&  function_name,
      const unsigned int  location_number,
      const irep_idt&  target_name
      )
    : pointsto_set_of_concrete_targetst({
            concrete_targett(function_name,location_number,target_name)
            })
  {}

  pointsto_set_of_concrete_targetst(const concrete_targetst&  targets)
    : irept(keyword())
  {
    for (const auto&  target : targets)
    {
      irept  concrete("concrete");
      concrete.get_sub().push_back(irept(std::get<0>(target)));
      concrete.get_sub().push_back(irept(
              msgstream() << std::get<1>(target) << msgstream::end()
              ));
      concrete.get_sub().push_back(irept(std::get<2>(target)));

      get_sub().push_back(concrete);
    }
  }

  std::size_t  get_num_targets() const { return get_sub().size(); }

  const irep_idt&  get_function_name(const std::size_t target_index) const
  { return get_sub().at(target_index).get_sub().at(0).id(); }

  unsigned int  get_location_number(const std::size_t target_index) const
  {
    std::stringstream sstr(
          as_string(get_sub().at(target_index).get_sub().at(1).id())
          );
    unsigned int  result;
    sstr >> result;
    return result;
  }

  const irep_idt&  get_target_name(const std::size_t target_index) const
  { return get_sub().at(target_index).get_sub().at(2).id(); }
};

class pointsto_set_of_offsetst : public irept
{
public:
  static const dstring keyword()
  { return ID_pointsto_access_paths_definition_offsets; }

  typedef std::unordered_set<irep_idt,dstring_hash>  offset_namest;

  pointsto_set_of_offsetst(const offset_namest&  offset_names)
    : irept(keyword())
  {
    for (auto const&  offset : offset_names)
      get_sub().push_back(irept(offset));
  }

  void  get_offset_names(offset_namest&  output_names)
  {
    for (const irept&  offset : get_sub())
      output_names.insert(offset.id());
  }
};

class pointsto_address_shiftt : public irept
{
public:
  static const dstring keyword()
  { return ID_pointsto_access_paths_shift; }

  pointsto_address_shiftt(
      const pointsto_symbolic_set_of_targetst&  targets,
      const pointsto_set_of_offsetst&  offsets
      )
    : irept(keyword())
  {
    get_sub().push_back(targets);
    get_sub().push_back(get_nil_irep());
    get_sub().push_back(offsets);
  }

  pointsto_address_shiftt(
      const pointsto_set_of_concrete_targetst&  targets,
      const pointsto_set_of_offsetst&  offsets
      )
    : irept(keyword())
  {
    get_sub().push_back(get_nil_irep());
    get_sub().push_back(targets);
    get_sub().push_back(offsets);
  }

  bool  has_symbolic_targets() const
  { return !(get_sub().front() == get_nil_irep()); }

  bool  has_concrete_targets() const { return !has_symbolic_targets(); }

  const pointsto_symbolic_set_of_targetst&  get_symbolic_targets() const
  {
    return static_cast<const pointsto_symbolic_set_of_targetst&>(
                get_sub().front()
                );
  }

  const pointsto_set_of_concrete_targetst&  get_concrete_targets() const
  {
    return static_cast<const pointsto_set_of_concrete_targetst&>(
                get_sub().at(1)
                );
  }

  const pointsto_set_of_offsetst&  get_offsets() const
  {
    return static_cast<const pointsto_set_of_offsetst&>(
                get_sub().back()
                );
  }
};


#endif
