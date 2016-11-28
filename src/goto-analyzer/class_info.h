/*******************************************************************\

Module: class_info

Author: Marek Trtik

Date: November 2016

This module provides a dump of information about a Java class(es) (like
full name, list of parent classes, list of methods, etc.) into a JSON
file.

@ Copyright Diffblue, Ltd.

\*******************************************************************/

#ifndef CPROVER_CLASS_INFO_H
#define CPROVER_CLASS_INFO_H

#include <string>


void  dump_class_info_in_json(
    std::string const&  output_dir
    );


#endif
