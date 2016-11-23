import java.lang.*;
import java.io.PrintWriter;
public final class __diffblue_full_class_name_parser__ {
  public static void main(String[] args) {
    String full_name = "";
    try {
      ClassLoader.getSystemClassLoader().loadClass(args[0]);
    } catch(NoClassDefFoundError e) {
      final String errorMsg = e.getMessage();
      final int begin = errorMsg.indexOf("(wrong name: ") +
                              new String("(wrong name: ").length();
      final int end = errorMsg.indexOf(")");
      full_name = errorMsg.substring(begin,end);
    } catch(Exception e) {}
    try {
      PrintWriter ofile = new PrintWriter(args[1]);
      ofile.println(full_name);
      ofile.close();
    } catch(Exception e) {}
  }
}

