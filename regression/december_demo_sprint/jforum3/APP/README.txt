JForum3
~~~~~~~

TODO: add description

Homepage WEB: TODO!
Repository URL: http://github.com/rafaelsteil/jforum3
Analysed branch: master
Analysed commit: bb847ea32f0abc7e3d0eb67fe8bbf88c7becfce4
Commints: TODO!
Releases: TODO!
Contributors: TODO!

Installation on Ubuntu:

1. Open a terminal in the directory of this readme file and download jforum 3:
      wget http://github.com/rafaelsteil/jforum3/zipball/master -O jforum3.zip
2. Unzip the files:
      unzip jforum3.zip
3. Rename the created directory from "rafaelsteil-jforum3-9f7eb05" to "jforum3".
4. Enter the jforum3 directory and edit the file pom.xml:
   Lines 108 and 109 should look like these:
      <artifactId>hibernate-core</artifactId>
      <version>3.3.1.GA</version>
5. Run maven:
      mvn clean package
6. Copy content of the created "target" directory into "../../BENCHMARK"
   directory (the target directory probably does not exists yet).

----
Note: I tried to build by cloning jforum3's git at
          https://github.com/rafaelsteil/jforum3
      but failed.

