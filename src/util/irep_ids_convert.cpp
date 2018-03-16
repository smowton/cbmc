/*******************************************************************\

Module: Build pre-initialized entries for C-string container

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#include <iostream>
#include <string>

#define USE_DSTRING

int main(int argc, const char **argv)
{
  if(argc!=2)
    return 1;

  std::cout << "// Generated by irep_ids_convert"
            << std::endl << std::endl;

  if(std::string(argv[1])=="header")
  {
    std::string line;

    std::cout << "#ifndef CPROVER_UTIL_IREP_IDS_H" << std::endl;
    std::cout << "#define CPROVER_UTIL_IREP_IDS_H" << std::endl;
    std::cout << std::endl;

    unsigned count=1;

    while(getline(std::cin, line))
    {
      if(line=="")
        continue;

      std::cout << "#define ID_";

      std::size_t pos=line.find(' ');

#ifdef USE_DSTRING
      if(pos==std::string::npos)
        std::cout << line
                  << " dstringt(" << count << ", 0)";
      else
        std::cout << std::string(line, 0, pos)
                  << " dstringt(" << count << ", 0)"
                  << " // "
                  << std::string(line, pos+1, std::string::npos);
#else
      if(pos==std::string::npos)
        std::cout << line
                  << " \"" << line << "\"";
      else
        std::cout << std::string(line, 0, pos)
                  << " \"" << std::string(line, 0, pos) << "\""
                  << " // "
                  << std::string(line, pos+1, std::string::npos);
#endif

      std::cout << std::endl;

      count++;
    }

    std::cout << std::endl;
    std::cout << "#endif" << std::endl;
  }
  else if(std::string(argv[1])=="table")
  {
    std::string line;

    std::cout << "  \"\"," << std::endl;

    while(getline(std::cin, line))
    {
      if(line=="")
        continue;

      std::cout << "  \"";

      std::size_t pos=line.find(' ');

      if(pos==std::string::npos)
        std::cout << line << "\",";
      else
        std::cout << std::string(line, pos+1, std::string::npos)
                  << "\", // ID_"
                  << std::string(line, 0, pos);

      std::cout << std::endl;
    }
  }

  return 0;
}