
#include "local_safe_pointers.h"

void local_safe_pointerst::operator()(const goto_programt &goto_program)
{
  std::set<exprt> checked_expressions;

  for(const auto &instruction : goto_program.instructions)
  {
    // Handle control-flow convergence pessimistically:
    if(instruction.incoming_edges.size() > 1)
      checked_expressions.clear();
    // Retrieve working set for forward GOTOs:
    else if(instruction.is_target())
      checked_expressions = non_null_expressions[instruction.location_number];

    // Save the working set at this program point:
    if(!checked_expressions.empty())
      non_null_expressions[instruction.location_number] = checked_expressions;

    switch(instruction.type)
    {
    // No-ops:
    case DECL:
    case DEAD:
    case ASSERT:
    case SKIP:
    case LOCATION:
      break;

    // Possible checks:
    case ASSUME:
      if(auto checked_expr = get_null_checked_expr(instruction.guard()))
        checked_expressions.insert(*checked_expr);
      break;

    case GOTO:
      if(!instruction.is_backwards_goto())
      {
        if(auto checked_expr_and_taken =
           get_conditional_checked_expr(instruction.guard()))
        {
          const exprt &checked_expr = checked_expr_and_direction->first;
          bool checked_when_taken = checked_expr_and_direction->second;

          auto &taken_checked_expressions =
            non_null_expressions[instruction.get_target()->location_number];
          taken_checked_expressions = checked_expressions;

          if(checked_when_taken)
            taken_checked_expressions.insert(checked_expr);
          else
            checked_expressions.insert(checked_expr);

          break;
        }
        // Otherwise fall through to...
      }

    default:
      // Pessimistically assume all other instructions might overwrite any
      // pointer with a possibly-null value.
      checked_expressions.clear();
      break;
    }
  }
}
