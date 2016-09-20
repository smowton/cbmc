package xss.tst01;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public final class FormServlet extends HttpServlet {

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    response.setContentType("text/html;charset=UTF-8");
    final PrintWriter out = response.getWriter();
    try {
      out.println("<!DOCTYPE html>");
      out.println("<html>");
      out.println("<head>");
      out.println("  <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");
      out.println("  <title>xss.tst01</title>");
      out.println("</head>");
      out.println("<body>");
      out.println("  <h1>XSS test 01 - RESULT</h1>");

      // XSS-SOURCE
      final String user_text = request.getParameter("usertext");

      // XSS-SINK: Here XSS issue MAY occur!
      out.println("  <p>You have entered the text: " + user_text + "</p>");
      
      if (user_text.contains("<"))
        out.println("  <p>Your input is tainted!</p>");
      else
        // XSS-SINK: Here XSS issue CANNOT occur!
        out.println("  <p>Your input '" + user_text + "' is not tainted.</p>");

      out.println("</body>");
      out.println("</html>");
    } finally {
      out.close();
    }
  }


}