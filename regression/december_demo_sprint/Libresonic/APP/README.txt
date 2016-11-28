Libresonic
~~~~~~~~~~
Libresonic is a free, web-based media streamer, providing ubiqutious access to music.
Can be used to share music with friends, or to listen to your own music while at work.

91 commits
2 branches
4 releases
12 contributors
GPL-3.0

Website: http://libresonic.org
Repository: https://github.com/Libresonic/libresonic


1. Open a terminal in the directory of this readme file and clone:
git clone https://github.com/Libresonic/libresonic
2. Enter the directory and build with maven:
cd libresonic/
git checkout 46a282900f636dc884cb157d156cf33fbae9182f
mvn clean package

3. Copy the resulting files to ../BENCHMARK (relative path to this README.txt file):
mkdir ../../BENCHMARK
mv */target/* ../../BENCHMARK/


