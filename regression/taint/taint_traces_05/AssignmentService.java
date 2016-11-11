import java.util.List;
import java.util.LinkedList;

public class AssignmentService {
	public static List getSubmissions(String assignment) {
	  return new LinkedList();
	}
  public static AssignmentSubmissionEdit editSubmission(String param0) {
    if (param0 == null)
      return null;
    return new DummyAssignmentSubmissionEdit();
  }
}

