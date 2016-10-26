public class PrintWriter {

  public PrintWriter() {
    this.buffer = "";
  }

  public void  print(String s) {
    buffer += s;
  }

  public void  println(String s) {
    print(s);
    print("\n");
  }

  public String  getBuffer() {
    return buffer;
  }

  private String  buffer;
}

