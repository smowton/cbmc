public class DummyAssignmentSubmissionEdit implements AssignmentSubmissionEdit {
  public void setSubmittedText(String submissionText) {
    TaintSink.receive_taint(submissionText.charAt(0));
  }
}

