
#ifndef CPROVER_MOCK_ENVRIONMENT_H
#define CPROVER_MOCK_ENVRIONMENT_H

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <sstream>
#include <functional> // for std::hash

// Supporting types for the map tracking instance method interception

struct java_type {
  std::string classname;
  bool is_primitive;

  bool operator==(const java_type& other) const
  {
    return classname == other.classname && is_primitive == other.is_primitive;
  }
};

struct method_signature {
  
  const std::string classname;
  const std::string methodname;
  const std::vector<java_type> argtypes;

  method_signature() = default;
  
method_signature(const std::string& cn,const std::string& mn,const std::vector<java_type> ats) :
  classname(cn),methodname(mn),argtypes(ats) {}

  bool operator==(const method_signature& other) const
  {
    return other.classname == classname &&
           other.methodname == methodname &&
           other.argtypes == argtypes;
  }

};

namespace std {

  template<> struct hash<java_type> {
    size_t operator()(const java_type& jt) const {
      return hash<string>()(jt.classname);
    }
  };
  
  template<> struct hash<method_signature> {

    size_t operator()(const method_signature& m) const {

      size_t ret = hash<string>()(m.classname) ^
	hash<string>()(m.methodname);

      for(auto iter : m.argtypes)
	ret ^= hash<java_type>()(iter);

      return ret;

    }
  
  };
}

struct method_answer {

  std::string answer_object;
  std::string answer_list;
  bool is_static;

  method_answer() = default;
  
method_answer(const std::string& ao,const std::string& al, bool is) :
  answer_object(ao),answer_list(al),is_static(is) {}
  
};

struct init_statement {
  enum statement_type { SCOPE_OPEN,SCOPE_CLOSE,STATEMENT };
  statement_type type;
  std::string statementText;

  static init_statement scopeOpen() { return { SCOPE_OPEN,"" }; };
  static init_statement scopeClose() { return { SCOPE_CLOSE,"" }; };
  static init_statement statement(const std::string& s) { return { STATEMENT,s }; };    
  
};

class mock_environment_builder {

  // Track mock classes that have been instantiated and so need an instance-list
  // and answer object connections.
  std::unordered_set<std::string> mock_instances_exist;

  // Track methods that have an answer object set up.
  std::unordered_map<method_signature,method_answer> answer_objects;

  // Build up a set of classes that need PowerMock setup (those whose constructors and/or static methods we need to intercept)
  std::set<std::string> powermock_classes;

  // Track classes that have already had mockStatic executed:
  std::set<std::string> static_mocked_classes;

  // List of instance methods with known bodies:
  std::vector<struct method_signature> elaborated_instance_methods;

  std::ostringstream mock_prelude;

  // Newline character plus indenting for the prelude:
  std::string prelude_newline;
  
 public:

  mock_environment_builder(unsigned int ip);
  
  // Add a mock to mock_instance_names. Returns a statement to execute while instancename
  // is still in scope.
  std::string register_mock_instance(const std::string& tyname,const std::string& instancename);

  // Intercept the next constructor call to tyname and return a fresh mock instance.
  std::string instantiate_mock(const std::string& tyname,bool is_constructor);

  method_answer* add_to_answer_list(const std::string& targetclass,const std::string& methodname,const std::vector<java_type>& argtypes,const java_type& rettype,const std::string& retval,bool is_static);
  
  // Intercept the next instance call to targetobj.methodname(paramtype0,paramtype1,...) and return retval.
  void instance_call(const std::string& targetclass,const std::string& methodname,const std::vector<java_type>& argtypes,const java_type& rettype,const std::string& retval);

  // Write instance method interception code that can only be generated once all required intercepts are known.
  std::string finalise_instance_calls();
  
  // Intercept the next static call to targetclass.methodname(argtypes...) and return retval.
  void static_call(const std::string& targetclass,const std::string& methodname,const std::vector<java_type>& argtypes,const java_type& rettype,const std::string& retval);

  // Return retval the next time a targetclass is constructed.
  void constructor_call(const std::string& callingclass,const std::string& targetclass,const std::vector<java_type>& argtypes,const std::string& retval);
  
  // Return annotations needed for the main class to run under JUnit:
  std::string get_class_annotations();

  void add_to_prelude(const std::vector<init_statement>&);
  void print_statements(const std::vector<init_statement>&,std::ostringstream&);
  
  // Return the mock setup code that should directly precede the test entry point.
  std::string get_mock_prelude() { return mock_prelude.str(); }

  void note_elaborated_instance_method(const std::string& cn,
				       const std::string& mn,
				       const std::vector<java_type>& ats) {
    elaborated_instance_methods.push_back(method_signature(cn,mn,ats));
  }

  // Verify functions, similar to call statements above:
  void verify_static_calls(const std::string& targetclass,const std::string& methodname,const std::vector<java_type>& argtypes, const std::vector<std::vector<std::string> >& calls, std::vector<init_statement>& stmts);

  void verify_constructor_calls(const std::string& targetclass,const std::string& methodname,const std::vector<java_type>& argtypes, const std::vector<std::vector<std::string> >& calls, std::vector<init_statement>& stmts);

  void verify_instance_calls(const std::string& targetclass,const std::string& methodname,const std::vector<java_type>& argtypes, const std::vector<std::vector<std::string> >& calls, std::vector<init_statement>& stmts);
  
};

#endif
