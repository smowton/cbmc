/*******************************************************************\

Module: taint_summary_libmodels

Author: Marek Trtik

Date: November 2016

This module provides loading and applying models of library functions
of analysed program to the process of taint analysis.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_TAINT_SUMMARY_LIBMODELS_H
#define CPROVER_TAINT_SUMMARY_LIBMODELS_H

#include <goto-analyzer/taint_summary.h>
#include <util/irep.h>
#include <string>


class  taint_summary_libmodelst
{
public:
  static taint_summary_libmodelst&  instance();

  void  clear();
  std::string  load(std::string const&  libmodels_json_file_pathname);

  bool  has_model_of_function(irep_idt const  fn_name) const;
  taint_summary_ptrt  get_model_of_function(irep_idt const  fn_name) const;

private:
};


#endif
