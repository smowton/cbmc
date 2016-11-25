Encuestame
~~~~~~~~~~

Encuestame is an Open Source Java web application to publish, collect, share and measure the opinion of the people thought the social media or private environments.
Private or public surveys, protected by password, widgets embeddable, ready for mobile and multi language.
4,316 commits
9 branches
38 releases
5 contributors
License: Apache-2.0

Website: http://www.encuestame.org
Repository: https://github.com/encuestame/encuestame


1. Open a terminal in the directory of this readme file and clone encuestame:
git clone https://github.com/encuestame/encuestame
git checkout 42cb745cbf15c9b40e497242898c2f75ded278f71
2. Enter the directory and build with maven:
cd encuestame/
mvn clean package

The main web application seems to be in enme-war and the resulting WAR file is in enme-war/web-app/tomcat-webapp/target/.

3. Copy the resulting files to ../BENCHMARK (relative path to this README.txt file):
mkdir ../BENCHMARK
mv enme-war/web-app/tomcat-webapp/target/* ../BENCHMARK/


--
Note: Each sub directory of the main directory may have subdirectories which also have build jar and war files.
To get them all you can try:
mv */target/* */*/target/* */*/*/target/* ../../BENCHMARK/
