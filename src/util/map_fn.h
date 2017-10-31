/*******************************************************************\

 Module: Map function onto container helper

 Author: Diffblue Limited. All rights reserved.

\*******************************************************************/

#include <iterator>

template<typename Container, typename Callable>
Container map_fn(const Callable &callable, const Container &input)
{
  Container result;
  std::transform(
    begin(input),
    end(input),
    std::inserter(result, end(result)),
    callable);
  return result;
}
