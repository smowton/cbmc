Red5
~~~~

Red5 is an Open Source Flash Server written in Java.

Home web: none
Repository URL: https://github.com/Red5/red5-server
Commits: 400
Releases: 31
Contributors: 10
Analysed branch: master
Analysed commit: 3b9811a7a32cd3f7866144ceacf964bd92096abe

1. Open a terminal in the directory of this readme file and clone Red5:
      git clone https://github.com/Red5/red5-server
2. Rename the created directory "red5-server" to "Red5".
3. Enter into the renamed directory and type there the following commands:
      git checkout 3b9811a7a32cd3f7866144ceacf964bd92096abe .
      mvn clean package
   The resulting JAR files are in the subdirectory "target".
4. Copy content of the subdirectory "target" into the directory
   "../../BENCHMARK", i.e. "../BENCHMARK" relative path to this README.txt file.
   Note that the destination directory perhaps does not exist yet.

