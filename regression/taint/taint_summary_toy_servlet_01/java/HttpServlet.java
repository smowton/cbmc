public abstract class HttpServlet {

  public void doGet(HttpServletRequest request, HttpServletResponse response) {
    response.setContentType("text/html;charset=UTF-8");
    final PrintWriter out = response.getWriter();
    out.println("<!DOCTYPE html>");
    out.println("<html>");
    out.println("<head>");
    out.println("  <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");
    out.println("  <title>Not supported</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("  <h1>GET operation is not supported.</h1>");
    out.println("</body>");
    out.println("</html>");
  }

}

