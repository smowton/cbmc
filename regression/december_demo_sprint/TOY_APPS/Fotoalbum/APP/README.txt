Fotoalbum
~~~~~~~~~~

Small webapplication for photo albums available on github.
Only 1 contributor.

Website: http://schrell.de:9090/slideshow/
Repository: https://github.com/foto-andreas/slideshow


1. Open a terminal in the directory of this readme file and clone encuestame:
      git clone https://github.com/foto-andreas/slideshow
2. Rename the created directory "slideshow" to "Fotoalbum"
3. Enter the directory and checkout the right commit:
      cd Fotoalbum/
      git checkout 924a537fce365a19b7db84bb542143acbc771e6b .
4. Build with maven:
      mvn clean package
5. Copy the resulting files to ../BENCHMARK (relative path to this README.txt
   file):
      cd .. 
      python ./copy_binaries.py
