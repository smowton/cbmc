SocialSDK
~~~~~~~~~

IBM Social Business Toolkit SDK. Set of libraries and code samples used for
connecting to the IBM Social Platform. It covers many products like IBM
Connections, IBM Notes/Domino, IBM Sametime. It includes support for many
authentication mechanisms, as well as comprehensive wrappers for the REST APIs.
The SDK can be run on Java-based application servers such WebSphere Application
Server, WebSphere Portal, IBM Domino, and Apache Tomcat.


10,954 commits
2 branches
26 releases
27 contributors


Website: https://developer.ibm.com/social
Repository: https://github.com/OpenNTF/SocialSDK


1. Open a terminal in the directory of this readme file and clone SocialSDK
      git clone https://github.com/OpenNTF/SocialSDK
2. Enter the created directory "SocialSDK" and build with maven:
      cd SocialSDK/
      git checkout 4f07c13180aa27152e08adf6440b6692e5a54d3b .
      mvn clean package
2. Copy the resulting files to ../BENCHMARK (relative path to this README.txt
   file):
      cd .. 
      python ./copy_binaries.py

