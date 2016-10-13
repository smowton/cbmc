#include <goto-analyzer/pointsto_temp_analyser.h>
#include <analyses/pointsto_summary_domain_dump.h>
#include <goto-programs/goto_functions.h>
#include <iostream>

pointsto_temp_summaryt::pointsto_temp_summaryt(
    const pointsto_rulest&  input_,
    const pointsto_rulest&  output_,
    const pointsto_temp_domain_ptrt  domain_
    )
  : input(input_)
  , output(output_)
  , domain(domain_)
{}

std::string  pointsto_temp_summaryt::kind() const noexcept
{
  return "cbmc://src/analyses/pointsto_temp_analyser";
}

std::string  pointsto_temp_summaryt::description() const noexcept
{
  return "Temporary summary-based points-to analysis. Its goal is to provide\n"
         "an impression, how to use points-to summary domain specification\n"
         "provided in files src/analyses/pointsto_summary_domain.h(cpp)."
         ;
}


static void  initialise_domain(
    irep_idt const&  function_id,
    goto_functionst::goto_functiont const&  function,
    goto_functionst::function_mapt const&  functions_map,
    namespacet const&  ns,
    database_of_summariest const&  database,
    pointsto_temp_domaint&  domain,
    std::ostream* const  log
    )
{
  pointsto_rulest  entry_map;
  for (std::size_t  i = 0UL; i != function.type.parameters().size(); ++i)
  {
    const irep_idt& target_name =
        function.type.parameters().at(i).get_identifier();
    const irept& raw_type =  function.type.parameters().at(i).find(ID_type);
    if (raw_type != get_nil_irep())
    {
      const typet&  target_type = static_cast<const typet&>(raw_type);
      if (target_type.id() != ID_pointer)
          continue;
    }

    entry_map.insert({
          pointsto_set_of_concrete_targetst(target_name),
          pointsto_symbolic_set_of_targetst()
          });
  }

  domain.insert({function.body.instructions.cbegin(),entry_map});
  for (auto  it = std::next(function.body.instructions.cbegin());
       it != function.body.instructions.cend();
       ++it)
    domain.insert({it,pointsto_rulest{}});

  if (log != nullptr)
  {
    *log << "<h3>Initialising the domain</h3>\n"
            "<p>Domain value at the entry location:</p>\n"
         ;
    pointsto_dump_rules_in_html(
        domain.at(function.body.instructions.cbegin()),
        *log
        );
    *log << "<p>Domain value at all other locations:</p>\n";
    pointsto_dump_rules_in_html(
        domain.at(std::prev(function.body.instructions.cend())),
        *log
        );
  }
}


typedef std::unordered_set<instruction_iteratort,
                           instruction_iterator_hashert>
        solver_work_set_t;

static void  initialise_workset(
    goto_functionst::goto_functiont const&  function,
    solver_work_set_t&  work_set
    )
{
  for (auto  it = function.body.instructions.cbegin();
       it != function.body.instructions.cend();
       ++it)
    work_set.insert(it);
}


static bool  pointsto_temp_equal(
    const pointsto_rulest&  a,
    const pointsto_rulest&  b
    )
{
  return a == b;
}


static bool  pointsto_temp_less_than(
    const pointsto_rulest&  a,
    const pointsto_rulest&  b
    )
{
  if (b.size() <= a.size())
    return false;
  for (const auto&  elem : a)
  {
    auto const  it = b.find(elem.first);
    if (it == b.cend() || !(elem.second == it->second))
      return false;
  }
  return true;
}


static pointsto_rulest  pointsto_temp_join(
    const pointsto_rulest&  a,
    const pointsto_rulest&  b
    )
{
  pointsto_rulest  result = a;
  for (const auto&  elem : b)
  {
    if (pointsto_is_empty_set_of_targets(elem.first) ||
        pointsto_is_empty_set_of_targets(elem.second))
      continue;
    auto it = result.find(elem.first);
    if (it == b.end())
      result.insert(elem);
    else if (elem.second != it->second)
        it->second =
            pointsto_expression_normalise(
                  pointsto_union_sets_of_targetst(elem.second,it->second)
                  );
  }
  return result;
}


static pointsto_rulest  pointsto_temp_assign(
    const pointsto_rulest&  a,
    const access_path_to_memoryt&  lhs,
    const access_path_to_memoryt&  rhs,
    const irep_idt&  fn_name,
    const unsigned int  location_id,
    const namespacet&  ns
    )
{
  pointsto_expressiont const  left =
      pointsto_evaluate_access_path(a,lhs,true,fn_name,location_id,ns);
  pointsto_expressiont const  right =
      pointsto_evaluate_access_path(a,rhs,false,fn_name,location_id,ns);
  pointsto_rulest  result;
  for (const auto&  elem : a)
    result =
        pointsto_temp_join(
            result,
            {{  pointsto_expression_normalise(
                    pointsto_subtract_sets_of_targetst(
                        elem.first,
                        left
                        )
                    ),
                elem.second }}
            );
  result = pointsto_temp_join(result,{{left,right}});
  return result;
}


static pointsto_rulest  pointsto_temp_transform(
    const pointsto_rulest&  a,
    goto_programt::instructiont const&  I,
    const irep_idt&  caller_ident,
    const goto_functionst::function_mapt&  functions_map,
    const database_of_summariest&  database,
    const namespacet&  ns,
    std::ostream* const  log
    )
{
  pointsto_rulest  result = a;
  switch(I.type)
  {
  case ASSIGN:
    {
      code_assignt const&  asgn = to_code_assign(I.code);
      if (is_pointer(asgn.lhs(),ns))
      {
        if (log != nullptr)
        {
          *log << "<p>\nRecognised ASSIGN instruction to a pointer '";
          dump_access_path_in_html(asgn.lhs(),ns,*log);
          *log << "'.</p>\n";
        }

        result = pointsto_temp_assign(
                      a,
                      asgn.lhs(),
                      asgn.rhs(),
                      caller_ident,
                      I.location_number,
                      ns
                      );
      }
      else
      {
        if (log != nullptr)
          *log << "<p>\nRecognised ASSIGN instruction NOT writing to a pointer."
                  " So, we use identity as a transformation function.</p>\n";
      }
    }
    break;
  case FUNCTION_CALL:
    if (log != nullptr)
      *log << "<p>!!! WARNING !!! : Unsupported instruction FUNCTION_CALL "
              "reached. So, we use identity as a transformation function.</p>\n"
           ;
    break;
  case DEAD:
    if (log != nullptr)
      *log << "<p>!!! WARNING !!! : Unsupported instruction DEAD reached. "
              "So, we use identity as a transformation function.</p>\n";
    break;
  case NO_INSTRUCTION_TYPE:
    if (log != nullptr)
      *log << "<p>Recognised NO_INSTRUCTION_TYPE instruction. "
              "The transformation function is identity.</p>\n";
    break;
  case SKIP:
    if (log != nullptr)
      *log << "<p>Recognised SKIP instruction. "
              "The transformation function is identity.</p>\n";
    break;
  case END_FUNCTION:
    if (log != nullptr)
      *log << "<p>Recognised END_FUNCTION instruction. "
              "The transformation function is identity.</p>\n";
    break;
  case GOTO:
    if (log != nullptr)
      *log << "<p>Recognised GOTO instruction. "
              "The transformation function is identity.</p>\n";
    break;
  case RETURN:
  case OTHER:
  case DECL:
  case ASSUME:
  case ASSERT:
  case LOCATION:
  case THROW:
  case CATCH:
  case ATOMIC_BEGIN:
  case ATOMIC_END:
  case START_THREAD:
  case END_THREAD:
    if (log != nullptr)
      *log << "<p>!!! WARNING !!! : Unsupported instruction reached. "
              "So, we use identity as a transformation function.</p>\n";
    break;
    break;
  default:
    throw std::runtime_error("ERROR: In 'pointsto_temp_transform' - "
                             "Unknown instruction!");
    break;
  }
  return result;
}


static void  pointsto_temp_build_summary_from_computed_domain(
    pointsto_temp_domain_ptrt const  domain,
    pointsto_rulest&  output,
    goto_functionst::function_mapt::const_iterator const  fn_iter,
    namespacet const&  ns,
    std::ostream* const  log
    )
{
  const pointsto_rulest&  end_svalue =
      domain->at(std::prev(fn_iter->second.body.instructions.cend()));

  if (log != nullptr)
  {
    *log << "<h3>Building points-to summary from the computed domain</h3>\n"
         << "<p>It is computed from the symbolic value "
            "at location "
         << std::prev(fn_iter->second.body.instructions.cend())->location_number
         << ":</p>\n"
         ;
    pointsto_dump_rules_in_html(end_svalue,*log);
    if (!end_svalue.empty())
      *log << "<p>Processing individual rules:</p>\n";
    *log << "<ul>\n";
  }

  for (auto  it = end_svalue.cbegin(); it != end_svalue.cend(); ++it)
  {
    pointsto_expressiont const  pruned_pointers =
        pointsto_temp_prune_pure_locals(it->first,ns);
    if (!pointsto_is_empty_set_of_targets(pruned_pointers))
    {
      pointsto_expressiont const  pruned_targets =
          pointsto_temp_prune_pure_locals(it->second,ns);

      output.insert({pruned_pointers,pruned_targets});

      if (log != nullptr)
      {
        *log << "<li>TAKING: ";
        pointsto_dump_expression_in_html(pruned_pointers,*log);
        *log << " &rarr; ";
        pointsto_dump_expression_in_html(pruned_targets,*log);
        *log << "</li>\n";
      }
    }
    else
      if (log != nullptr)
      {
        *log << "<li>EXCLUDING: ";
        pointsto_dump_expression_in_html(it->first,*log);
        *log << " &rarr; ";
        pointsto_dump_expression_in_html(it->second,*log);
        *log << "</li>\n";
      }
  }

  if (log != nullptr)
    *log << "</ul>\n";
}


void  pointsto_temp_summarise_all_functions(
    goto_modelt const&  program,
    database_of_summariest&  summaries_to_compute,
    call_grapht const&  call_graph,
    std::ostream* const  log
    )
{
  std::vector<irep_idt>  inverted_topological_order;
  {
    std::unordered_set<irep_idt,dstring_hash>  processed;
    for (auto const&  elem : program.goto_functions.function_map)
      inverted_partial_topological_order(
            call_graph,
            elem.first,
            processed,
            inverted_topological_order
            );
  }
  for (auto const&  fn_name : inverted_topological_order)
  {
    goto_functionst::function_mapt  const  functions_map =
        program.goto_functions.function_map;
    auto const  fn_it = functions_map.find(fn_name);
    if (fn_it != functions_map.cend() && fn_it->second.body_available())
      summaries_to_compute.insert({
          as_string(fn_name),
          pointsto_temp_summarise_function(
              fn_name,
              program,
              summaries_to_compute,
              log
              ),
          });
  }
}


pointsto_temp_summary_ptrt  pointsto_temp_summarise_function(
    irep_idt const&  function_id,
    goto_modelt const&  instrumented_program,
    database_of_summariest const&  database,
    std::ostream* const  log
    )
{
  if (log != nullptr)
    *log << "<h2>Called sumfn::taint::taint_summarise_function( "
         << to_html_text(as_string(function_id)) << " )</h2>\n"
         ;

  goto_functionst::function_mapt const&  functions =
      instrumented_program.goto_functions.function_map;
  auto const  fn_iter = functions.find(function_id);

  namespacet const  ns(instrumented_program.symbol_table);

  assert(fn_iter != functions.cend());
  assert(fn_iter->second.body_available());

  pointsto_temp_domain_ptrt  domain = std::make_shared<pointsto_temp_domaint>();
  initialise_domain(
        function_id,
        fn_iter->second,
        functions,
        ns,
        database,
        *domain,
        log
        );
  pointsto_rulest const  input =
      domain->at(fn_iter->second.body.instructions.cbegin());

int iii = 0;

  solver_work_set_t  work_set;
  initialise_workset(fn_iter->second,work_set);
  while (!work_set.empty())
  {
    ++iii;
    if (iii > 50)
    {
      std::cout << "ERROR: The analysis was early terminated (after 50 steps). "
                   "The fixed point was not reached yet.\n";
      break;
    }

    instruction_iteratort const  src_instr_it = *work_set.cbegin();
    work_set.erase(work_set.cbegin());

    pointsto_rulest const&  src_value =
        domain->at(src_instr_it);

    goto_programt::const_targetst successors;
    fn_iter->second.body.get_successors(src_instr_it, successors);
    for(auto  succ_it = successors.begin();
        succ_it != successors.end();
        ++succ_it)
      if (*succ_it != fn_iter->second.body.instructions.cend())
      {
        instruction_iteratort const  dst_instr_it = *succ_it;
        pointsto_rulest&  dst_value = domain->at(dst_instr_it);
        pointsto_rulest const  old_dst_value = dst_value;

        if (log != nullptr)
        {
          *log << "<h3>Processing transition: "
               << src_instr_it->location_number << " ---[ "
               ;
          dump_instruction_code_in_html(
              *src_instr_it,
              instrumented_program,
              *log
              );
          *log << " ]---> " << dst_instr_it->location_number << "</h3>\n"
               ;
          *log << "<p>Source value:</p>\n";
          pointsto_dump_rules_in_html(src_value,*log);
          *log << "<p>Old destination value:</p>\n";
          pointsto_dump_rules_in_html(old_dst_value,*log);
        }

        pointsto_rulest const  transformed =
            pointsto_temp_transform(
                src_value,
                *src_instr_it,
                function_id,
                functions,
                database,
                ns,
                log
                );
        dst_value = pointsto_temp_join(transformed,old_dst_value);

        if (log != nullptr)
        {
          *log << "<p>Transformed value:</p>\n";
          pointsto_dump_rules_in_html(transformed,*log);
          *log << "<p>Resulting destination value:</p>\n";
          pointsto_dump_rules_in_html(dst_value,*log);
        }

        if ( !(pointsto_temp_equal(dst_value,old_dst_value) ||
               pointsto_temp_less_than(dst_value,old_dst_value)) )
        {
          work_set.insert(dst_instr_it);

          if (log != nullptr)
            *log << "<p>Inserting instruction at location "
                 << dst_instr_it->location_number << " into 'work_set'.</p>\n"
                 ;
        }
      }
  }

  pointsto_rulest  output;
  pointsto_temp_build_summary_from_computed_domain(
        domain,
        output,
        fn_iter,
        ns,
        log
        );
  return std::make_shared<pointsto_temp_summaryt>(input,output,domain);
}
