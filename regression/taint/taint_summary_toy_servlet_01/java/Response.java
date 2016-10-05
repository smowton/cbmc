class Response implements HttpServletResponse {

  public Response() {
    this.writer = new PrintWriter();
    this.contentType = 0;
  }

  @Override
  public void  setContentType(String s) {
    if (s == "text/html;charset=UTF-8")
      contentType = 1;
  }

  @Override
  public PrintWriter  getWriter() {
    if (contentType != 0)
      return writer;
    if (contentType == 0) {
      writer.println("<!DOCTYPE html>");
      writer.println("<html>");
      writer.println("<head>");
      writer.println("  <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");
      writer.println("  <title>ERROR</title>");
      writer.println("</head>");
      writer.println("<body>");
      writer.println("  <h1>ERROR: Response.getWriter() : 'Content type' not specified.</h1>");
      writer.println("</body>");
      writer.println("</html>");
      contentType = -1;
    }
    return new PrintWriter();
  }

  private PrintWriter  writer;
  private int  contentType;
}

