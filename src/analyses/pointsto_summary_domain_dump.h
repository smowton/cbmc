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

std::string  pointsto_dump_symbolic_set_of_targets_in_html(
    const pointsto_symbolic_set_of_targetst&  targets,
    std::ostream&  ostr
    );

std::string  pointsto_dump_set_of_concrete_targets_in_html(
    const pointsto_set_of_concrete_targetst&  targets,
    std::ostream&  ostr
    );


std::string  pointsto_dump_rules_in_html(
    pointsto_rulest const&  rules,
    std::ostream&  ostr,
    const std::string&  shift = ""
    );



#endif
