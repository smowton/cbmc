
#ifndef JAVA_POINTER_CASTS_H
#define JAVA_POINTER_CASTS_H

exprt clean_deref(const exprt ptr);

bool find_superclass_with_type(exprt &ptr,const typet &target_type,
                               const namespacet &ns);

exprt make_clean_pointer_cast(const exprt &ptr,const typet &target_type,
                              const namespacet &ns);

#endif
