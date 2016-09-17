public class recursion3
{
  static int f(int n)
  {
    int arg_copy = n;
    int to_ret;
    if(n <= 0)
      to_ret=1;
    else
      to_ret = n * f(n-1);
    return to_ret + arg_copy;
  }

  public static void main()
  {
    int ret = f(1);
    assert(ret == 2);
  }
}
