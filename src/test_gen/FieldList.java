package com.diffblue.java_testcase;

public class FieldList {
  public ArrayList<FieldValue> fields;
  public FieldList() { fields = new ArrayList<FieldValue>(); }
  public void add(String name, Object value) { fields.add(new FieldValue(name, value)); }
}

class FieldValue {
  public FieldValue(String n, Object v) { name = n; value = v; }
  public String name;
  public Object value;
}
