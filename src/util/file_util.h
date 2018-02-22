/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/


#ifndef CPROVER_UTIL_FILE_UTIL_H
#define CPROVER_UTIL_FILE_UTIL_H

#include <string>

/// This constant defines a maximum name length of any file created by
/// any module of the CProver. The value of the constant was inferred
/// from the most restrictive file system we use on our workstations:
/// 'ecryptfs'.
const std::size_t MAX_FILE_NAME_SIZE = 140;

void delete_directory(const std::string &path);

std::string get_current_working_directory();

std::string concat_dir_file(const std::string &directory,
                            const std::string &file_name);

std::string make_valid_filename(
  std::string filename,
  const std::size_t max_size = MAX_FILE_NAME_SIZE);

#endif // CPROVER_UTIL_FILE_UTIL_H
