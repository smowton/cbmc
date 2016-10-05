class Request implements HttpServletRequest {

  public Request(String username, String password) {
    this.username = username;
    this.password = password;
  }

  @Override
  public String  getParameter(String param) {
    if (param == "username")
      return username;
    if (param == "password")
      return password;
    return "Unknown parameter.";
  }

  private String username;
  private String password;
}

