DSpace
~~~~~~

DSpace is an open source application used by more than 1000+ organizations and
institutions worldwide to provide durable access to digital resources.


Webpage: http://www.dspace.org/
Repository: https://github.com/DSpace/DSpace
Analysed branch: master
Analysed commit: 462ed4437c2f60812af1c207d8309212dbf893f6
Commits: 8 934
Releases: 85
Contributors: 107

Installation on Ubuntu:

1. Open a terminal in the directory of this readme file and clone DSpace:
      git clone https://github.com/DSpace/DSpace
2. Enter the directory type the following commands:
      git checkout 462ed4437c2f60812af1c207d8309212dbf893f6 .
      cd DSpace
      mvn clean package
3. Copy built binaries into the installation directory by typing this command
   into the terminal:
      python ./copy_binaries.py

