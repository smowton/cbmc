Alfresco Community Edition
~~~~~~~~~~~~~~~~~~

Alfresco is a leading repository for Enterprise Content Management (ECM), 
providing Document  Management, Collaboration, Records Management, Knowledge 
Management, and Web Content Services.


9,834 commits
1 branch
29 releases
3 contributors
LGPL-3.0

Analysed branch: master
Analysed commit: 2c1eff9953d3105e738f7b06ba9ba8a079ca4c24

Website: https://www.alfresco.com/
Repository: https://github.com/Alfresco/community-edition


1. Open a terminal in the directory of this readme file and clone:
      git clone https://github.com/Alfresco/community-edition
2. Rename the created sub-directory "community-edition" to "Alfresco".
3. Enter the directory "Alfresco" and build it using maven.
4. Check out the commit "2c1eff9953d3105e738f7b06ba9ba8a079ca4c24" by typing:
      git checkout 2c1eff9953d3105e738f7b06ba9ba8a079ca4c24 .
5. Enter the directory "Alfresco" and build it using maven:
      mvn clean package -DskipTests
6. Copy the resulting files to ../BENCHMARK (relative path to this README.txt
   file):
      cd .. 
      python ./copy_binaries.py

