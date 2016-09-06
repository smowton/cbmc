package cprover.cbmc.function_summaries.java_transitive_dependences;

final class C0 {

  public C0(int c0, int c1) {
    this.c0 = c0;
    this.c1 = c1;
  }

  public int f0(int x) {
    return x + c0;
  }

  public int f1(int x) {
    return x + c1 + f0(x - c1);
  }

  public static int f2(int x) {
    return x + 1;
  }

  private final int c0;
  private final int c1;
}

final class C1 {

  public C1(final C0 pC0, final int c1) {
    this.pC0 = pC0;
    this.c1 = c1;
  }

  public int f0(int x) {
    C0 pC0 = new C0(x,x-1);
    return pC0.f0(x + c1) + this.pC0.f1(x + c1);
  }

  public int f1(int x) {
    return x + c1 + f0(x - c1) + C0.f2(x);
  }

  private final C0 pC0;
  private final int c1;
}

final class C2 {

  public C2(int x, int y) {
    this.pC0 = new C0(x,y);
    this.pC1 = new C1(new C0(y,x),y);
  }

  public int f0(int x) {
    return pC0.f0(x) + pC1.f1(x);
  }

  public int f1(int x) {
    return pC0.f1(x) + pC0.f0(x) - pC0.f2(x);
  }

  private final C0 pC0;
  private final C1 pC1;
}

public final class Main {

  public static int f0() {
    final C0 pC0 = new C0(1,2);
    final C1 pC1 = new C1(pC0,3);
    final C2 pC2 = new C2(4,5);
    return pC2.f0(0) + pC2.f1(0) + pC1.f1(0);
  }

  public static void main(final String[] args) {
    f0();
  }
}

