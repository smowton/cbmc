Onyx
~~~~

Web-based application that manages participant baseline interviews at biobanks
assessment centres or clinics.

4,916 commits
17 branches
46 releases
12 contributors
GPL-3.0


Website: http://www.obiba.org/
Repository: https://github.com/obiba/onyx


Installation on Ubuntu:

1. Open a terminal in the directory of this readme file and clone:
      git clone https://github.com/obiba/onyx
2. Rename the created directory "onyx" to "Onyx"
3. Enter the directory "Onyx" and do the following:
      git checkout 778b7920abf3ccc589393f2d5cc5f63a8ecc9fa7 .
      mvn clean package
4. Copy the resulting files to ../BENCHMARK (relative path to this README.txt
   file):
      cd .. 
      python ./copy_binaries.py

