
public final class Main {

  public static void main(String[] args) {
    Request  request = new Request("alice","feeler");
    Response response = new Response();
    Servlet  servlet = new Servlet();
    servlet.doGet(request,response);
    String result = response.getWriter().getBuffer();
    if (result.contains("<script>"))
      System.out.println("XSS!");
    else
      System.out.println("OK!");
  }

}

