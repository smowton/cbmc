int main(int argc, char **argv) {
  int i = 0;
  if(argc % 2)
    i = argc;
  else {
    __CPROVER_assume(0);
    i = 2;
  }

  assert(i == argc);
}
