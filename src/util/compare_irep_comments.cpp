
#include "compare_irep_comments.h"
#include "irep.h"

typedef std::pair<const irep_idt, irept> named_sub_pair;

bool equal_with_comments_pair(const named_sub_pair &i1, const named_sub_pair &i2)
{
  return i1.first==i2.first &&
    irep_equal_with_comments(i1.second,i2.second);
}

// Like irept::operator==, but considers comments as well as conventional subexpressions.
bool irep_equal_with_comments(const irept &i1, const irept &i2)
{
  if(i1.id()!=i2.id())
    return false;
  if(i1.get_sub().size()!=i2.get_sub().size())
    return false;
  if(i1.get_named_sub().size()!=i2.get_named_sub().size())
    return false;
  if(i1.get_comments().size()!=i2.get_comments().size())
    return false;
  if(!std::equal(i1.get_sub().begin(),
                 i1.get_sub().end(),
                 i2.get_sub().begin(),
                 irep_equal_with_comments))
    return false;
  if(!std::equal(i1.get_named_sub().begin(),
                 i1.get_named_sub().end(),
                 i2.get_named_sub().begin(),
                 equal_with_comments_pair))
    return false;
  if(!std::equal(i1.get_comments().begin(),
                 i1.get_comments().end(),
                 i2.get_comments().begin(),
                 equal_with_comments_pair))
    return false;
  return true;
}
