package xss.tst01;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public final class RootServlet extends HttpServlet {

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    response.setContentType("text/html;charset=UTF-8");
    PrintWriter out = response.getWriter();
    try {
      out.println("<!DOCTYPE html>");
      out.println("<html>");
      out.println("<head>");
      out.println("  <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>");
      out.println("  <title>xss.tst01.RootServlet</title>");
      out.println("</head>");
      out.println("<body>");
      out.println("  <h1>XSS test 01 : ROOT</h1>");
      out.println("  <p>Request URI: " + request.getRequestURI() + "</p>");
      out.println("  <p>Protocol: " + request.getProtocol() + "</p>");
      out.println("  <p>PathInfo: " + request.getPathInfo() + "</p>");
      out.println("  <p>Remote Address: " + request.getRemoteAddr() + "</p>");
      out.println("  <p>A Random Number: " + Math.random() + "</p>");
      out.println("  <form method=\"get\" action=\"tst01/form.html\">");
      out.println("    <input type=\"submit\" value=\"Go to test form.\" />");
      out.println("  </form>");
      out.println("</body>");
      out.println("</html>");
    } finally {
      out.close();
    }
  }

}
