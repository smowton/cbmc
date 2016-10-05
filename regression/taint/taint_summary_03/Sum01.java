class Source {
  public static int receive1() { return 0; }
  public static int receive2() { return 0; }
}

class Sink {
  public static void send1(int value) {}
  public static void send2(int value) {}
}

class Local {

  public Local() {
    this.LL = 400;
  }

  public int baz(int aa) {
    LL = aa + Source.receive1();
    if (aa < 350)
      return LL + GG;
    return 2000;
  }

  private int LL;
  private static int  GG = 300;
}


public final class Sum01 {

  public Sum01() {
    this.L = 200;
  }

  public int bar(int a) {
    L = a;
    if (a < 150) {
      Sink.send2(a + L);
      return L + G;
    }
    else
      L += Source.receive2();
    return 1000;
  }

  public int foo(int x, final int y, final Local local) {
    int w = Source.receive2();
    if (x < y) {
      x = bar(x) + y;
      Sink.send1(x+y);
    }
    else {
      G = local.baz(x + w) + y;
      Sink.send2(G + y);
   }
    L = G;
    return x + 5;
  }

  public static void main() {
    Sum01 s = new Sum01();
    Local l = new Local();
    s.foo(G,50,l);
  }

  private int L;
  private static int  G = 100;
}

