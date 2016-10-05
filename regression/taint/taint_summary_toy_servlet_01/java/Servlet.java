public class Servlet extends HttpServlet {

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) {
    response.setContentType("text/html;charset=UTF-8");
    final PrintWriter out = response.getWriter();
    out.println("<!DOCTYPE html>");
    out.println("<html>");
    out.println("<head>");
    out.println("  <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");
    out.println("  <title>Story</title>");
    out.println("</head>");
    out.println("<body>");
    String  username = request.getParameter("username");
    String  password = request.getParameter("password");
    String  story = Database.read(username,password);
    out.println("  <h1>Story of " + username + "</h1>");
    out.println("  <p>");
    out.println(Sanitiser.run(story));
    out.println("  </p>");
    out.println("</body>");
    out.println("</html>");
  }

}

