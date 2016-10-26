/////////////////////////////////////////////////////////////////////
//
// Module: main.c
// Author: Marek Trtik
// Description:
//
//
// @ Copyright DiffBlue, Ltd.
//
/////////////////////////////////////////////////////////////////////

int f4(int x, int y)
{
  return x - 2;
}

int f3(int x)
{
  return x + 1;
}

int f1(int x)
{
  return 2 * f3(x);
}

int f2(int x)
{
  return f3(x) + f4(x,x);
}

int f0(int x, int y)
{
  return f1(x) + f2(y);
}

int main()
{
  return f0(1,2) + f1(2) - f2(1);
}

