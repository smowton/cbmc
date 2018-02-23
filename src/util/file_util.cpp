/*******************************************************************\

Module: File Utilities

Author:

Date: January 2012

\*******************************************************************/

/// \file
/// File Utilities

#include "file_util.h"

#include "invariant.h"

#include <cerrno>
#include <cassert>
#include <cstring>

#include <fstream>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <vector>

#if defined(__linux__) ||                       \
  defined(__FreeBSD_kernel__) ||                \
  defined(__GNU__) ||                           \
  defined(__unix__) ||                          \
  defined(__CYGWIN__) ||                        \
  defined(__MACH__)
#include <unistd.h>
#include <dirent.h>
#include <cstdio>
#include <sys/stat.h>
#endif

#ifdef _WIN32
#include <io.h>
#define NOMINMAX // Don't define 'min', masking std::min
#include <windows.h>
#include <direct.h>
#include <Shlwapi.h>
#undef NOMINMAX
#include <util/unicode.h>
#define chdir _chdir
#define popen _popen
#define pclose _pclose
#endif

/// \return current working directory
std::string get_current_working_directory()
{
  #ifndef _WIN32
  errno=0;
  char *wd=realpath(".", nullptr);
  INVARIANT(
    wd!=nullptr && errno==0,
    std::string("realpath failed: ")+strerror(errno));

  std::string working_directory=wd;
  free(wd);
  #else
  char buffer[4096];
  DWORD retval=GetCurrentDirectory(4096, buffer);
  CHECK_RETURN(retval>0);
  std::string working_directory(buffer);
  #endif

  return working_directory;
}

/// deletes all files in 'path' and then the directory itself
#ifdef _WIN32

void delete_directory_utf16(const std::wstring &path)
{
  std::wstring pattern=path + L"\\*";
  // NOLINTNEXTLINE(readability/identifiers)
  struct _wfinddata_t info;
  intptr_t hFile=_wfindfirst(pattern.c_str(), &info);
  if(hFile!=-1)
  {
    do
    {
      if(wcscmp(info.name, L".")==0 || wcscmp(info.name, L"..")==0)
        continue;
      std::wstring sub_path=path+L"\\"+info.name;
      if(info.attrib & _A_SUBDIR)
        delete_directory_utf16(sub_path);
      else
        DeleteFileW(sub_path.c_str());
    }
    while(_wfindnext(hFile, &info)==0);
    _findclose(hFile);
    RemoveDirectoryW(path.c_str());
  }
}

#endif

void delete_directory(const std::string &path)
{
#ifdef _WIN32
  delete_directory_utf16(utf8_to_utf16_little_endian(path));
#else
  DIR *dir=opendir(path.c_str());
  if(dir!=nullptr)
  {
    struct dirent *ent;
    while((ent=readdir(dir))!=nullptr)
    {
      // Needed for Alpine Linux
      if(strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..")==0)
        continue;

      std::string sub_path=path+"/"+ent->d_name;

      struct stat stbuf;
      int result=stat(sub_path.c_str(), &stbuf);
      if(result!=0)
        throw std::string("Stat failed: ")+std::strerror(errno);

      if(S_ISDIR(stbuf.st_mode))
        delete_directory(sub_path);
      else
      {
        result=remove(sub_path.c_str());
        if(result!=0)
          throw std::string("Remove failed: ")+std::strerror(errno);
      }
    }
    closedir(dir);
  }
  rmdir(path.c_str());
#endif
}

/// \par parameters: directory name and file name
/// \return concatenation of directory and file, if the file path is relative
std::string concat_dir_file(
  const std::string &directory,
  const std::string &file_name)
{
#ifdef _WIN32
  return (file_name.size()>1 &&
          file_name[0]!='/' &&
          file_name[1]!=':') ?
    file_name : directory+"\\"+file_name;
#else
  return (!file_name.empty() && file_name[0]=='/') ?
    file_name : directory+"/"+file_name;
#endif
}

/// Replaces invalid characters in a file name using a hard-coded list of
/// replacements.
/// This is not designed to operate on path names and will replace folder
/// seperator characters.
/// \param file_name: The file name to sanitize.
/// \param max_length: The maximum length for the file name. If the name is
///                    longer, then its length will be cut to the max_length.
std::string make_valid_filename(
  std::string file_name,
  const std::size_t max_length)
{
  std::replace(file_name.begin(), file_name.end(), '#', '_');
  std::replace(file_name.begin(), file_name.end(), '$', '_');
  std::replace(file_name.begin(), file_name.end(), ':', '.');
  std::replace(file_name.begin(), file_name.end(), '/', '.');
  std::replace(file_name.begin(), file_name.end(), '\\', '.');
  std::replace(file_name.begin(), file_name.end(), '<', '[');
  std::replace(file_name.begin(), file_name.end(), '>', ']');
  if(file_name.size() > max_length)
    file_name.resize(max_length);
  return file_name;
}
