

Installation on Ubuntu:

1. Open a terminal in the directory of this readme file and download jforum 3:
wget http://github.com/rafaelsteil/jforum3/zipball/master -O jforum3.zip
2. Unzip the files: unzip jforum3.zip
3. Enter the rafaelsteil-jforum3-9f7eb05 directory and edit the file pom.xml:
change line 108 for:
        	<artifactId>hibernate-core</artifactId>
        	<version>3.3.1.GA</version>
4. Run maven: mvn clean package

The resulting WAR file "....war" is then located in the sub-directory: ./target

5. Copy the resulting WAR/JAR file(s) to ../BENCHMARK directory (relative path to this README.txt file)


----
Note: I tried to build by cloning jforum3's git at https://github.com/rafaelsteil/jforum3 but failed.
