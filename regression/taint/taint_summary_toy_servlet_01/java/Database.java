public class Database {

  public static String read(String username, String password) {
    if (username == "john" && password == "antenna")
      return "Once upon a time there was a king.";
    if (username == "alice" && password == "feeler")
      return "Once upon a time there was a <script>badcode</script> king.";
    return "Wrong user name or password.";
  }

}

