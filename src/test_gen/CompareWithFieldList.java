package com.diffblue.java_testcase;

import java.util.HashSet;
import java.lang.reflect.Field;

public class CompareWithFieldList {

  static boolean debug = false;

  static HashSet<Class> primitives;
  
  static {
    primitives = new HashSet<Class>();
    primitives.add(Boolean.class);
    primitives.add(Character.class);
    primitives.add(Byte.class);
    primitives.add(Short.class);
    primitives.add(Integer.class);
    primitives.add(Long.class);
    primitives.add(Float.class);
    primitives.add(Double.class);
  }

  private static Field getField(Class c, String name) {
    while(c != null)
    {
      try {
	return c.getDeclaredField(name);
      }
      catch(NoSuchFieldException e) {
	c = c.getSuperclass();
      }
    }
    return null;
  }

  private static void fail(Object actual, Object expected, String prefix)
  {
    String actual_str = actual == null ? "null" : (actual.getClass().getName() + " " + actual.toString());
    String expected_str = expected == null ? "null" : (expected.getClass().getName() + " " + expected.toString());
    String field_str = prefix.equals("") ? "" : ("Field " + prefix + ": ");
    throw new UnexpectedMockParameterException(field_str + "Expected " + expected_str + " got " + actual_str);
  }
  
  // Returns on success or throws on mismatch.
  public static void compare(Object real, Object primitive_or_fieldlist, String prefix) {

    if(real == null)
    {
      if(primitive_or_fieldlist == null) {
        if(debug)
          System.err.printf("%s null as expected\n", prefix);
	return;
      }
      fail(real, primitive_or_fieldlist, prefix);
    }
    if(real.equals(primitive_or_fieldlist))
    {
      if(debug)
        System.err.printf("%s = %s as expected\n", prefix, real.toString());
      return;
    }
    if(primitive_or_fieldlist == null)
      fail(real, primitive_or_fieldlist, prefix);
    if(primitives.contains(primitive_or_fieldlist.getClass()))
      fail(real, primitive_or_fieldlist, prefix);
    if(primitive_or_fieldlist.getClass().isArray())
    {
      if(!real.getClass().isArray())
	fail(real, primitive_or_fieldlist, prefix);
      Object[] lhs_array=(Object[])real;
      Object[] rhs_array=(Object[])primitive_or_fieldlist;
      if(lhs_array.length!=rhs_array.length)
	fail(real, primitive_or_fieldlist, prefix);
      for(int i = 0; i < lhs_array.length; ++i)
      {
	String newPrefix = prefix + "[" + i + "]";
	compare(lhs_array[i], rhs_array[i], newPrefix);
      }
      return;
    }
    if(!(primitive_or_fieldlist instanceof FieldList))
      throw new RuntimeException("Right-hand operand must be a primitive or a FieldList object");

    FieldList rhs=(FieldList)primitive_or_fieldlist;
    for(FieldValue v : rhs.fields)
    {
      Field f = getField(real.getClass(), v.name);
      if(f == null)
	throw new RuntimeException("Real object of class " + real.getClass().getName() + " did not have expected field " + v.name);
      f.setAccessible(true);
      Object realval;
      try {
        realval = f.get(real);
      } catch(IllegalAccessException e) {
        // Should be impossible.
        throw new RuntimeException(e);
      }
      String newPrefix = prefix + "." + v.name;
      compare(realval, v.value, newPrefix);
    }
    
  }

}
