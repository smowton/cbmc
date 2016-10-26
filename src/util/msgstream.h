/////////////////////////////////////////////////////////////////////////////
//
// Module: msgstream
// Author: Marek Trtik
//
// It allows for formated output into a string.
//
// @ Copyright Diffblue, Ltd.
//
/////////////////////////////////////////////////////////////////////////////


#ifndef UTIL_MSGSTREAM_HPP_INCLUDED
#define UTIL_MSGSTREAM_HPP_INCLUDED

#include <string>
#include <sstream>


struct  msgstream
{
  struct end {};
  template<typename T>
  msgstream&  operator<<(T const& value) { m_stream << value; return *this; }
  std::string  get() const { return m_stream.str(); }
  operator std::string() const { return get(); }
  std::string  operator<<(end const&) { return get(); }
  std::string  operator<<(end (*)()) { return get(); }
private:
  std::ostringstream  m_stream;
};

inline constexpr msgstream::end  endmsg() noexcept { return msgstream::end(); }


#endif
