class array2
{
  public static void main(String[] args)
  {
    int size=3;
    int a[]=new int[size];
    for (int i=0; i < size; ++i)
      assert(a[i] == 0);
  }
}
