Ginco
~~~~~~~~~~

GINCO is a free software developped by the Ministry of Culture and Communication
(France) and is dedicated to the management of vocabularies. GINCO is released
under the terms of the CeCiLL v2 license.

1,836 commits
6 branches
49 releases
9 contributors

Website: http://culturecommunication.github.io/ginco/
Repository: https://github.com/culturecommunication/ginco


1. Open a terminal in the directory of this readme file and clone:
      git clone https://github.com/culturecommunication/ginco
2. Rename the created directory "ginco" to "Ginco"
3. Enter the directory "Ginco" and build with maven:
      git checkout e6ae1b436e308d3b712482b596f4f636aacd2e97 .
      mvn clean package
4. Copy the resulting files to ../BENCHMARK (relative path to this README.txt
   file):
      cd .. 
      python ./copy_binaries.py

