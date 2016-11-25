mediaManager
~~~~~~~~~~~~

Web application which provides an interface to a collection of media.
Source code on github, only one contributor, draft.

Webpage:  
Repo URL: https://github.com/jamescoll/mediaManager

Installation on Ubuntu:

1. Open a terminal in the directory of this readme file and clone:
git clone https://github.com/jamescoll/mediaManager
(Installation tested with commit bd8ffff7d4116d06a9ddfc6f53c2283ce18034bf)
2. Enter the directory and build with maven:
cd mediaManager
mvn clean package

The resulting JAR file is then located in the sub-directory: ./target

5. Copy the resulting WAR/JAR file(s) to ../BENCHMARK directory (relative path to this README.txt file):
mkdir ../../BENCHMARK
mv target/* ../../BENCHMARK/

