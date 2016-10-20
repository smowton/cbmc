#ifndef EXTERNAL_VALUE_SET_H
#define EXTERNAL_VALUE_SET_H

// An access path entry, indicating that an external object was accessed using e.g.
// member-x--of-dereference (represented "->x") at function f location (instruction offset) z.

const std::string ACCESS_PATH_LOOP_TAG=".<any-path>";

class access_path_entry_exprt : public exprt
{
 public:
  inline access_path_entry_exprt():exprt("access-path-entry") {}
  inline access_path_entry_exprt(const irep_idt& label,
                                 const irep_idt& function,
                                 const irep_idt& loc)
    :exprt("access-path-entry")
  {
    set_label(label);
    set("access-path-function", function);
    set("access-path-loc", loc);
  }

 static access_path_entry_exprt get_loop_tag() {
   return access_path_entry_exprt(ACCESS_PATH_LOOP_TAG, "", "");
 }
  
  inline irep_idt label() const { return get("access-path-label"); }
  inline void set_label(const irep_idt& i) { set("access-path-label", i); }
  inline irep_idt function() const { return get("access-path-function"); }
  inline irep_idt loc() const { return get("access-path-loc"); }
  inline bool is_loop() const { return label()==ACCESS_PATH_LOOP_TAG; }
};

static inline access_path_entry_exprt& to_access_path_entry(exprt& e) {
  return static_cast<access_path_entry_exprt&>(e);
}

static inline const access_path_entry_exprt& to_access_path_entry(const exprt& e) {
  return static_cast<const access_path_entry_exprt&>(e);
}

enum local_value_set_analysis_modet {
  LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET,
  LOCAL_VALUE_SET_ANALYSIS_EXTERNAL_SET_PER_ACCESS_PATH
};

// Represents an external unknown points-to set that can't be directly referenced with a symbol,
// such as "arg1->x"

class external_value_set_exprt : public exprt
{
 public:
  inline external_value_set_exprt():exprt("external-value-set")
  {
    operands().resize(1);
    op0().id(ID_unknown);
  }

  inline external_value_set_exprt(const typet &type, const constant_exprt& label, const local_value_set_analysis_modet mode, bool modified):
    exprt("external-value-set",type)
  {
    operands().push_back(label);
    set("#lva_mode",i2string((int)mode));
    set("modified",i2string((int)modified));
  }

  inline local_value_set_analysis_modet analysis_mode() const
  {
    return (local_value_set_analysis_modet)get_int("#lva_mode");
  }

  inline bool is_modified() const
  {
    return get_bool("modified");
  }

  inline exprt &label() { return op0(); }
  inline const exprt &label() const { return op0(); }

  inline size_t access_path_size() const { return operands().size()-1; }
  inline access_path_entry_exprt& access_path_entry(size_t index)
  {
    return to_access_path_entry(operands()[index+1]);
  }
  inline const access_path_entry_exprt& access_path_entry(size_t index) const
  {
    return to_access_path_entry(operands()[index+1]);
  }
  inline const access_path_entry_exprt& access_path_back() const
  {
    assert(operands().size()>1);
    return to_access_path_entry(operands().back());
  }
  inline void access_path_push_back(const access_path_entry_exprt& newentry)
  {
    copy_to_operands(newentry);
  }
  std::string get_access_path_label() const
  {
    if(analysis_mode()==LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET)
      return "external_objects";
    std::string ret=id2string(to_constant_expr(label()).get_value());
    for(size_t i=0,ilim=access_path_size(); i!=ilim; ++i)
      ret+=id2string(access_path_entry(i).label());
    return ret;
  }
  std::string get_access_path_basename() const
  {
    if(analysis_mode()==LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET)
      return "external_objects";    
    assert(access_path_size()!=0);
    std::string ret=id2string(to_constant_expr(label()).get_value());
    for(size_t i=0,ilim=access_path_size()-1; i!=ilim; ++i)
      ret+=id2string(access_path_entry(i).label());
    return ret;
  }
  bool access_path_loops() const
  {
    if(access_path_size()<2) return false;
    return access_path_entry(access_path_size()-2).is_loop();
  }
  void create_access_path_loop()
  {
    copy_to_operands(access_path_entry_exprt::get_loop_tag());
  }
  void replace_access_path_tail(const access_path_entry_exprt& newtail)
  {
    operands()[operands().size()-1]=newtail;
  }

  void extend_access_path(const access_path_entry_exprt& newentry)
  {
    if(analysis_mode()==LOCAL_VALUE_SET_ANALYSIS_SINGLE_EXTERNAL_SET)
    {
      // Any attempt to extend a path yields <all-externals>->fieldname
      label()=constant_exprt("external_objects",string_typet());
      if(access_path_size()==0)
        access_path_push_back(newentry);
      else
        replace_access_path_tail(newentry);
    }
    else
    {
      if(access_path_loops())
      {
        // Replace the existing tail field with this one.
        replace_access_path_tail(newentry);
      }
      else
      {
        for(size_t i=0,ilim=access_path_size(); i!=ilim; ++i)
        {
          if(access_path_entry(i).label()==newentry.label())
          {
            create_access_path_loop();
            break;
          }
        }
        access_path_push_back(newentry);
      }
    }
  }

  external_value_set_exprt as_modified() const
  {
    external_value_set_exprt copy=*this;
    copy.set("modified",ID_1);
    return copy;
  }
    
};

static inline external_value_set_exprt& to_external_value_set(exprt& e) {
  return static_cast<external_value_set_exprt&>(e);
}

static inline const external_value_set_exprt& to_external_value_set(const exprt& e) {
  return static_cast<const external_value_set_exprt&>(e);
}

#endif
