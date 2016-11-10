public class TaintSource {
  static int taintedGlobal = 10;
  public static int get_tainted_int() {
    return taintedGlobal;
  }
}

