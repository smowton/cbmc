Automation scripts for goto-analyser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The root script is "run.py" located in this directory (i.e. directory containig
this README.txt file). Scripts providing functionality of different parts of the
whole pipe-line are in the sub-directory "scripts". You will never need to
use scripts in "scripts" sub-directory directory. All you need is provided by
the root script "run.py". For details how to use this script opon a terminal
in this directory and type: python ./run.py --help

Automation scripts assume a presence of some data to be installed into
a sub-directory "data". Here is the intallation procedure for Ubuntu:

1. Create this structure of durectories under this directory:
      data/openjdk-8-rt.jar-unpacked
      data/openjdk-8-rt.jar-unpacked-PRUNED/java/lang
2. Unpack content of "rt.jar" of "Java OpenJDK 8" into directory:
      data/openjdk-8-rt.jar-unpacked
   Note: the rt.jar file is typically located here:
      /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/rt.jar
   Note: I recommend to use "jar" utility with options "xvf" specified to unpack
         the content of the JAR file.
3. Copy class file "data/openjdk-8-rt.jar-unpacked/java/lang/String.class" to
   "data/openjdk-8-rt.jar-unpacked-PRUNED/java/lang/String.class".


HINT: To run the anlyser on a benchmark do this:
    1. Open terminal in this directory.
    2. Type the command there:
          $ python ./run.py -E "../Sakai"
       That will evaluate the bechmark "Sakai". Or type:
          $ python ./run.py -E "../TRAINING/taint_traces_05"
       That will evaluate the training bechmark "taint_traces_05".

NOTE: The analyser is "lazy". It uses information saved from the previous
      executions of the benchmarks for the current analysis. If you want to
      reanalyse the benchmarks from scratch, then add also option --rebuild.
      E.g.:
        $ python ./run.py -E "../Sakai" --rebuild

