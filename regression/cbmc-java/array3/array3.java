class array3
{
  public static void main(String[] args)
  {
    int size=new java.util.Random().nextInt();
    if (size < 0) return;
    int a[]=new int[size];
    for (int i=0; i < size; ++i)
      assert a[i] == 0;
  }
}
