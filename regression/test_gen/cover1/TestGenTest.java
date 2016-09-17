class A
{
  public int a_field_0;

  public A(int a_field_0)
  {
    this.a_field_0=a_field_0;
  }
}


public class TestGenTest
{
  public static void f(A param0, int param1)
  {
    TestGenTest tCovDummy = new TestGenTest();
    A aCovDummy = new A(0);

    int a_field_0=param0.a_field_0;
    int sum = a_field_0 + param1;
              
    int x;
    if(sum > 10)
     {
       x = 99;
     }
     else
     {
       x = 101;
     }
  }
}
