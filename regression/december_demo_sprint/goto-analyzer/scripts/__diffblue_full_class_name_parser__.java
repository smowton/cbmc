import java.lang.*;
import java.io.PrintWriter;
public final class __diffblue_full_class_name_parser__ {
  public static void main(String[] args) {
    String full_name = "";
    try {
      full_name = ClassLoader.getSystemClassLoader().loadClass(args[0])
                             .getName()
                             .replace(".","/");
    } catch(NoClassDefFoundError e) {
      final String errorMsg = e.getMessage();
      int begin = errorMsg.indexOf("(wrong name: ");
      if (begin != -1) {
        begin += new String("(wrong name: ").length();
        final int end = errorMsg.indexOf(")");
        full_name = errorMsg.substring(begin,end);
      } else
        full_name = errorMsg;
    } catch(Exception e) {}
    try {
      PrintWriter ofile = new PrintWriter(args[1]);
      ofile.println(full_name);
      ofile.close();
    } catch(Exception e) {}
  }
}

