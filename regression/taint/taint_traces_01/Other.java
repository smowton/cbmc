public class Other {

  public static void branches(int x) {
    if (x > 100)
      --x;
    else
      ++x;
    
    while (x > 0)
      if (x < 50)
       --x;
      else
        x = x - 2;
  }

  public static void XX() {
    int xx = Main.GG;
    Main.GG = xx;
  }

  public static void YY() {
    int yy = Main.GG;
    Main.GG = yy;
  }

  public static int baz0(int a0) {
    return baz1(a0);
  }

  public static int baz1(int a0) {
    return a0;
  }
}

