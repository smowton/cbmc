/*******************************************************************\

Module: pointsto_summary_domain

Author: Marek Trtik

Date: Octomber 2016


@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_POINTSTO_SUMMARY_DOMAIN_DUMP_H
#define CPROVER_POINTSTO_SUMMARY_DOMAIN_DUMP_H

#include <analyses/pointsto_summary_domain.h>
#include <summaries/summary_dump.h>
#include <string>
#include <iosfwd>


std::string  pointsto_dump_expression_in_html(
    const pointsto_expressiont&  expression,
    std::ostream&  ostr
    );

std::string  pointsto_dump_null_target_in_html(
    const pointsto_null_targett&,
    std::ostream&  ostr
    );

std::string  pointsto_dump_symbolic_set_of_targets_in_html(
    const pointsto_symbolic_set_of_targetst&  targets,
    std::ostream&  ostr
    );

std::string  pointsto_dump_set_of_concrete_targets_in_html(
    const pointsto_set_of_concrete_targetst&  targets,
    std::ostream&  ostr
    );

std::string  pointsto_dump_address_shifted_targets_in_html(
    const pointsto_set_of_address_shifted_targetst&  targets,
    std::ostream&  ostr
    );

std::string  pointsto_dump_address_dereference_in_html(
    const pointsto_address_dereferencet&  targets,
    std::ostream&  ostr
    );

std::string  pointsto_dump_address_shift_in_html(
    const pointsto_address_shiftt&  shift,
    std::ostream&  ostr
    );

std::string  pointsto_dump_set_of_offsetst_in_html(
    const pointsto_set_of_offsetst&  offsets,
    std::ostream&  ostr
    );

std::string  pointsto_dump_subtract_sets_of_targets_in_html(
    const pointsto_subtract_sets_of_targetst&  expression,
    std::ostream&  ostr
    );

std::string  pointsto_dump_union_sets_of_targets_in_html(
    const pointsto_union_sets_of_targetst&  expression,
    std::ostream&  ostr
    );

std::string  pointsto_dump_if_empty_then_else_in_html(
    const pointsto_if_empty_then_elset&  expression,
    std::ostream&  ostr
    );


std::string  pointsto_dump_rules_in_html(
    pointsto_rulest const&  rules,
    std::ostream&  ostr,
    const std::string&  shift = ""
    );



#endif
