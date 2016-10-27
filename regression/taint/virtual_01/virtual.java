public class virtual {

  public static int main(int unknown, int taint1, int taint2) {

    base b = new base();
    child c = new child();
    base touse = unknown > 0 ? b : c;
    return touse.f(taint1,taint2);

  }

}

class base {

  int f(int arg1, int arg2) { return arg2; }

}

class child extends base {

  int f(int arg1, int arg2) { return arg1; }

}
