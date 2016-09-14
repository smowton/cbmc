
#include "java_test_source_factory.h"
#include "mock_environment_builder.h"

#include <iostream>
#include <assert.h>

/*******************************************************************\

Function: mock_envrionment_builder

  Inputs: Indent level (spaces)

 Outputs: (constructor)

 Purpose:

\*******************************************************************/

mock_environment_builder::mock_environment_builder(unsigned int ip)
{

  prelude_newline='\n';
  for(unsigned int i=0; i<ip; ++i)
    prelude_newline+=' ';
  mock_prelude << prelude_newline;
}

/*******************************************************************\

Function: register_mock_instance

  Inputs: Class and instance name

 Outputs: Statements to include in the mock setup prelude

 Purpose: Add instancename to the list of mock classname objects,
          for later use setting up Answer objects.

\*******************************************************************/

std::string mock_environment_builder::register_mock_instance(
    const std::string &tyname,const std::string &instancename)
{

  std::string instanceList=tyname+"_instances";
  qualified2identifier(instanceList);
  if(mock_instances_exist.insert(tyname).second)
    mock_prelude << "java.util.ArrayList<" << tyname << "> " << instanceList
		 << "=new java.util.ArrayList<" << tyname << ">();"
		 << prelude_newline;
  return prelude_newline+instanceList+".add("+instancename+");";
}

/*******************************************************************\

Function: instantiate_mock

  Inputs: Desired class name

 Outputs: Expression to create a fresh mock instance.

 Purpose: Create a new mock

\*******************************************************************/

std::string
mock_environment_builder::instantiate_mock(const std::string &tyname,
                                           bool is_constructor)
{

  return "org.mockito.Mockito.mock("+tyname+".class);";
}

// Return retval the next time a targetclass is constructed.
// We don't use argtypes at the moment.
void mock_environment_builder::constructor_call(
    const std::string &callingclass,const std::string &targetclass,
    const std::vector<java_type>&argtypes,const std::string &retval)
{

  // Note that the *caller* (not the callee) needs PrepareForTest.
  powermock_classes.insert(callingclass);

  mock_prelude << "org.powermock.api.mockito.PowerMockito.whenNew("
	       << targetclass << ".class).withAnyArguments().thenReturn("
	       << retval << ");" << prelude_newline;
}

/*******************************************************************\

Function: classname_to_symname

  Inputs: Class name

 Outputs: Symbol name

 Purpose: Escape dots to underscores in java class names

\*******************************************************************/

static std::string classname_to_symname(const std::string &classname)
{

  std::string ret=classname;
  for(size_t i=0,ilim=classname.length(); i!=ilim; ++i)
    if(ret[i]=='.')
      ret[i]='_';
  return ret;
}

/*******************************************************************\

Function: box_java_type

  Inputs: Primitive type name

 Outputs: Boxed type name

 Purpose: Convert e.g. int to Integer.

\*******************************************************************/

static std::string box_java_type(const java_type &unboxed)
{

  if(!unboxed.is_primitive)
    return unboxed.classname;
  if(unboxed.classname=="boolean")
    return "Boolean";
  else if(unboxed.classname=="byte")
    return "Byte";
  else if(unboxed.classname=="char")
    return "Character";
  else if(unboxed.classname=="float")
    return "Float";
  else if(unboxed.classname=="int")
    return "Integer";
  else if(unboxed.classname=="long")
    return "Long";
  else if(unboxed.classname=="short")
    return "Short";
  else if(unboxed.classname=="double")
    return "Double";
  else
    assert(0 && "Unknown java primtive?");
}

/*******************************************************************\

Function: instance_call

  Inputs: Description of a call to (targetclass)somevar.methodname(argtypes[0]
          ... argtypes[i]) which returns retval,of type rettype. All values 
          and types have already been converted to Java expressions.

 Outputs: None (stores a mock script entry in mock_prelude)

 Purpose: Requests that the next call to an instance method with this
          description should return 'retval'.

\*******************************************************************/

// Intercept the next instance call to targetclass::methodname(paramtype0,
// paramtype1,...) and return retval.
// At the moment we don't care which instance of targetclass was called against.
method_answer* mock_environment_builder::static_or_instance_call(
    const std::string &targetclass,const std::string &methodname,
    const std::vector<java_type> &argtypes,const java_type &rettype,
    const std::string &retval,bool is_static)
{

  method_signature sig(targetclass,methodname,argtypes);
  method_answer dummy_ans;

  auto insertresult=
    answer_objects.insert(std::make_pair(sig,dummy_ans));

  if(insertresult.second)
  {

    // This is the first interception of targetclass::methodname (for this
    // overload). Set up a response list and answer object:

    std::ostringstream answerlist;
    answerlist << classname_to_symname(targetclass) << "_" << methodname;
    for(auto iter : argtypes)
      answerlist << "_" << iter.classname;

    std::string al=answerlist.str();
    std::string ao=answerlist.str();
    al+="_answer_list";
    ao+="_answer_object";

    qualified2identifier(al);
    qualified2identifier(ao);

    insertresult.first->second=method_answer(ao,al,is_static);

    std::string boxed_type=box_java_type(rettype);

    mock_prelude << "final java.util.ArrayList<" << boxed_type << "> " << al
		 << "=new java.util.ArrayList<" << boxed_type << ">();"
		 << prelude_newline
		 << "final com.diffblue.java_testcase.IterAnswer " << ao
		 << "=new com.diffblue.java_testcase.IterAnswer<"
		 << boxed_type << "> (" << al << ");" << prelude_newline;
  }

  // Add the desired return value to the list:
  auto& found=insertresult.first->second;
  mock_prelude << found.answer_list << ".add(" << retval << ");"
	       << prelude_newline;

  return insertresult.second ? &found : 0;
}

void mock_environment_builder::instance_call(
    const std::string &targetclass,const std::string &methodname,
    const std::vector<java_type> &argtypes,const java_type &rettype,
    const std::string &retval)
{
  static_or_instance_call(targetclass,methodname,argtypes,rettype,retval,false);
}

/*******************************************************************\

Function: generate_when_statement

  Inputs: Description of a call to targetclass.methodname(argtypes)

 Outputs: Mockito argument matching spec

 Purpose: Generates a mockito statement like when(A.f(anyInt()))

\*******************************************************************/

static void generate_arg_matchers(std::ostringstream &printto,
                                  const std::vector<java_type> &argtypes)
{

  for(unsigned int i=0,ilim=argtypes.size(); i<ilim; ++i)
  {

    const auto &arg=argtypes[i];
    if(i!=0)
      printto << ",";

    // Accept anyInt,anyShort,anyDouble,etc for primitives,or isA to match
    // object types.

    if(arg.is_primitive)
      printto << "org.mockito.Matchers.any" << (char)toupper(arg.classname[0])
	      << arg.classname.substr(1) << "()";
    else
      printto << "org.mockito.Matchers.isA(" << arg.classname << ".class)";
  }

}

/*******************************************************************\

Function: generate_when_statement

  Inputs: Description of a call to targetclass.methodname(argtypes)

 Outputs: Mockito argument matching spec

 Purpose: Generates a mockito statement like when(A.f(anyInt()))

\*******************************************************************/

static void generate_when_statement(std::ostringstream &printto,
                                    const std::string &targetclass,
                                    const std::string &methodname,
                                    const std::vector<java_type> &argtypes)
{

  printto << "org.mockito.Mockito.when(" << targetclass << "." << methodname
	  << "(";
  generate_arg_matchers(printto,argtypes);
  printto << "))";
}

/*******************************************************************\

Function: finalise_instance_calls

  Inputs: None

 Outputs: Final mock object setup statements,to be included in a test case
          before user code is called but after all needed objects have been
          created.

 Purpose: Links Mockito Answer objects with every instance of a mocked class
          that has been created.

\*******************************************************************/

std::string mock_environment_builder::finalise_instance_calls()
{

  // We've created a number of mock objects of various types. Hook them up to
  // their type-global
  // list of function return values.

  std::ostringstream result;
  result << prelude_newline;

  for(auto iter : answer_objects)
  {

    if(iter.second.is_static)
      continue;

    const auto &cname=iter.first.classname;
    if(!mock_instances_exist.count(cname))
    {
      std::cout << "Warning: class " << cname
	        << " has instance method mocks but never instantiated\n";
    }

    std::string instanceList=cname+"_instances";
    std::string instanceIter=cname+"_iter";

    qualified2identifier(instanceList);
    qualified2identifier(instanceIter);

    result << "for(" << cname << " " << instanceIter << " : " << instanceList
	   << ')' << prelude_newline << "  ";
    generate_when_statement(result,instanceIter,iter.first.methodname,
                          iter.first.argtypes);
    result << ".thenAnswer(" << iter.second.answer_object << ");"
	   << prelude_newline;
  }

  // Punch through to real code whenever the real implementation is available:
  for(auto iter : elaborated_instance_methods)
  {
    const auto &cname=iter.classname;
    if(!mock_instances_exist.count(cname))
      continue;
    
    // An elaborated method may be mocked if it has an opaque super call:
    if(answer_objects.count(iter))
      continue;

    std::string instanceList=cname+"_instances";
    std::string instanceIter=cname+"_iter";

    result << "for(" << cname << " " << instanceIter << " : " << instanceList
	   << ')' << prelude_newline << "  ";
    generate_when_statement(result,instanceIter,iter.methodname,
                          iter.argtypes);
    result << ".thenCallRealMethod();"
	   << prelude_newline;
  }

  return result.str();
}

/*******************************************************************\

Function: static_call

As instance_call above, but for Java static methods.

\*******************************************************************/

void mock_environment_builder::static_call(
    const std::string &targetclass,const std::string &methodname,
    const std::vector<java_type> &argtypes,const java_type &rettype,
    const std::string &retval)
{

  // Intercepting static calls needs PowerMockito setup:
  powermock_classes.insert(targetclass);
  auto inserted=static_mocked_classes.insert(targetclass);
  // Call mockStatic the first time a particular type is needed:
  if(inserted.second)
    mock_prelude << "org.powermock.api.mockito.PowerMockito.mockStatic("
		 << targetclass << ".class);" << prelude_newline;

  auto addresult=static_or_instance_call(targetclass,methodname,argtypes,rettype,retval,true);
  if(addresult)
  {
    // Attach the answer object the first time a given *method* is called:
    generate_when_statement(mock_prelude,targetclass,methodname,argtypes);
    mock_prelude << ".thenAnswer(" << addresult->answer_object << ");" << prelude_newline;
  }

}

/*******************************************************************\

Function: get_class_annotations

  Inputs: None

 Outputs: Class annotations needed given the mock objects that were created

 Purpose: Forces the test to run under PowerMock if necessary,and gives
          PrepareForTest annotations where required.

\*******************************************************************/

std::string mock_environment_builder::get_class_annotations()
{

  if(powermock_classes.size()==0)
    return "";

  std::ostringstream out;
  out << "@org.junit.runner.RunWith(org.powermock.modules.junit4.PowerMockRunner.class)\n";
  out << "@org.powermock.core.classloader.annotations.PrepareForTest( { ";

  for(std::set<std::string>::iterator it=powermock_classes.begin(),
                                      itend=powermock_classes.end();
      it!=itend; ++it)
  {
    if(it!=powermock_classes.begin())
      out << ",";
    out << *it << ".class";
  }

  out << " } )";

  return out.str();
}

void mock_environment_builder::print_statements(
  const std::vector<init_statement>&statements,
  std::ostringstream &printto)
{

  for(const auto &s : statements)
  {
    switch(s.type)
    {
    case init_statement::SCOPE_OPEN:
      printto << '{';
      prelude_newline+="  ";
      printto << prelude_newline;
      break;
    case init_statement::SCOPE_CLOSE:
      //printto << "\b\b";
      if(prelude_newline.length()>=3)
        prelude_newline.erase(prelude_newline.length() - 2,2);
      printto << '}' << prelude_newline;
      break;
    case init_statement::STATEMENT:
      printto << s.statementText << ';' << prelude_newline;
    }
  }
}

/*******************************************************************\

Function: add_to_prelude

  Inputs: Raw statements to be inserted into the mock object setup commands.

 Outputs: None

 Purpose: The source factory uses this to include setup that uses Reflector to
          set field values.

\*******************************************************************/

void mock_environment_builder::add_to_prelude(
  const std::vector<init_statement>&statements)
{
  print_statements(statements,mock_prelude);
}

void mock_environment_builder::verify_static_calls(
  const std::string& targetclass,
  const std::string& methodname,
  const std::vector<java_type>& argtypes,
  size_t ncalls,
  std::vector<init_statement>& stmts)
{
  std::ostringstream prep_call;
  prep_call << "org.powermock.api.mockito.PowerMockito.verifyStatic(" <<
    "org.mockito.Mockito.times(" << ncalls << "))";
  
  stmts.push_back(init_statement::statement(prep_call.str()));

  std::ostringstream static_call;
  static_call << targetclass << '.' << methodname << '(';
  generate_arg_matchers(static_call,argtypes);
  static_call << ')';

  stmts.push_back(init_statement::statement(static_call.str())); 
}

void mock_environment_builder::verify_constructor_calls(
  const std::string& targetclass,
  const std::string& methodname,
  const std::vector<java_type>& argtypes,
  size_t ncalls,
  std::vector<init_statement>& stmts)
{
  std::ostringstream constructor_call;
  constructor_call << "org.powermock.api.mockito.PowerMockito.verifyNew(" <<
    targetclass << ".class, org.mockito.Mockito.times(" << ncalls << "))";
  if(argtypes.size()==0)
    constructor_call << ".withNoArguments()";
  else
  {
    constructor_call << ".withArguments(";
    generate_arg_matchers(constructor_call,argtypes);
    constructor_call << ')';
  }
  stmts.push_back(init_statement::statement(constructor_call.str()));
}

void mock_environment_builder::verify_instance_calls(
  const std::string& targetclass,
  const std::string& methodname,
  const std::vector<java_type>& argtypes,
  size_t ncalls,
  std::vector<init_statement>& stmts)
{
  std::ostringstream instance_call;

  method_signature sig(targetclass,methodname,argtypes);
  const auto& answer_record=answer_objects.at(sig);
  
  // For the time being, just check that a call happened at all:
  instance_call << "assert(" << answer_record.answer_object << ".callArguments.size()"
                << " == " << ncalls << ')';
  stmts.push_back(init_statement::statement(instance_call.str()));
}
    
