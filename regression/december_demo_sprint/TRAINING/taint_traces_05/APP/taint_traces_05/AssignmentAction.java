import java.util.HashMap;
import java.util.List;
import java.io.InputStream;
import java.io.IOException;
import java.util.zip.ZipInputStream;

public class AssignmentAction {
  public void doUpload_all(RunData data) {
    ParameterParser params = data.getParameters();
    FileItem fileFromUpload = null;
    fileFromUpload = params.getFileItem("file");
    InputStream fileContentStream = fileFromUpload.getInputStream();
    HashMap submissionTable = new HashMap();
    List submissions = null;
    submissions = AssignmentService.getSubmissions("some_param");
    submissionTable = uploadAll_parseZipFile(fileContentStream,submissionTable);
    uploadAll_updateSubmissions(submissionTable,submissions);
  }

  private HashMap uploadAll_parseZipFile(
        InputStream fileContentStream,
        HashMap submissionTable
        ) {
    ZipInputStream zis = new ZipInputStream(fileContentStream);
    String comment = getBodyTextFromZipHtml(zis,true);
    submissionTable.put("some_key",comment);
    return submissionTable;
  }
  
  private void uploadAll_updateSubmissions(
        HashMap submissionTable,
        List submissions
        ) {
    if (submissions == null)
      return;
    AssignmentSubmissionEdit sEdit = editSubmission();
    if (sEdit != null)
      sEdit.setSubmittedText((String)submissionTable.get("some_key"));
  }

  private AssignmentSubmissionEdit editSubmission() {
    AssignmentSubmissionEdit rv = AssignmentService.editSubmission("string");
    return rv;
  }

  private String getBodyTextFromZipHtml(InputStream zin, boolean convertNewLines) {
    return readIntoString(zin);
  }

  private String readIntoString(InputStream zin) {
    StringBuilder buffer = new StringBuilder();
    int size = 2048;
    byte[] data = new byte[2048];
    try {
      size = zin.read(data, 0, data.length);
      buffer.append(new String(data, 0, size));
    } catch (IOException e) {
    }
    return buffer.toString();
  }
}

