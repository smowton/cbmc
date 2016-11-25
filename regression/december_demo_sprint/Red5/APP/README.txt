



1. Open a terminal in the directory of this readme file and clone Red5:
git clone https://github.com/Red5/red5-server
2. Enter the directory and build with maven:
cd red5-server/
mvn clean package

The resulting JAR files are in the subdirectory target/
3. Copy the resulting JAR file to ../BENCHMARK (relative path to this README.txt file):
mkdir ../../BENCHMARK
mv target/* ../../BENCHMARK/
