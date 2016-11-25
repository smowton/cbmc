Fotoalbum
~~~~~~~~~~

Small webapplication for photo albums available on github.
Only 1 contributor.

Website: http://schrell.de:9090/slideshow/
Repository: https://github.com/foto-andreas/slideshow


1. Open a terminal in the directory of this readme file and clone encuestame:
git clone https://github.com/foto-andreas/slideshow
2. Enter the directory and checkout the right commit:
cd slideshow
git checkout 924a537fce365a19b7db84bb542143acbc771e6b
3. Build with maven:
mvn clean package


4. Copy the resulting files to ../BENCHMARK (relative path to this README.txt file):
mkdir ../BENCHMARK
mv target/* ../BENCHMARK/
