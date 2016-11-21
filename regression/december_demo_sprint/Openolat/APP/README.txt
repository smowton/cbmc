Openolat
~~~~~~~~

OpenOLAT is a learning platform offering an extensive set of features that is written in Java.
The code is open source and is hosted on a public Mercurial repository.

Home web: http://www.openolat.com/
Repo URL: http://hg.openolat.org/openolat105/

Installation on Ubuntu:

1. Install TortoiseHg (http://tortoisehg.bitbucket.org/)
2. Use TortoiseHg to clone the OpenOlat source code from http://hg.openolat.org/openolat105/
3. Open terminat in the directory ehere you cloned OpenOlat into and type there: mvn clean package

The resulting WAR file "openolat-lms-10.5-SNAPSHOT.war" is then located in the sub-directory: ./target

!!! Copy the resulting WAR/JAR file(s) to ../BENCHMARK directory (relative path to this README.txt file)
    to be consistent with structure of this evaluation !!!

----

Note: There is a GIT fork of Openolat (https://github.com/klemens/openolat.git). I tried to build the
      commit ece4e16b2567e7b62da8c578bf8b7a6b09766579, but the build has failed. So, do not use it!!
