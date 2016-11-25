DSpace
~~~~~~

DSpace is an open source application used by more than 1000+ organizations and institutions worldwide to provide durable access to digital resources.
The github repository has 8,934 commits, 85 releases, 107 contributors.


Webpage: http://www.dspace.org/
Repository: https://github.com/DSpace/DSpace

Installation on Ubuntu:

1. Open a terminal in the directory of this readme file and clone DSpace:
git clone https://github.com/DSpace/DSpace
(Installation tested with commit 462ed4437c2f60812af1c207d8309212dbf893f6)
2. Enter the directory and build with maven:
cd DSpace
mvn clean package

Several files are built in different directories. The main web application seems to be dspace-sword and the corresponding WAR/JAR files are in dspace-sword/target/
3. Copy the resulting WAR/JAR file(s) to ../BENCHMARK directory (relative path to this README.txt file):
mkdir ../../BENCHMARK
mv dspace-sword/target/* ../../BENCHMARK/
