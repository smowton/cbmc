December demo
~~~~~~~~~~~~~

This is an installation and usage guide for the evaluation framework of the
demo. Read it carefully!

1. Directory structure

The evaluation will be done inside this directory (and sub-directories).
There are two special sub-directories:

    ./goto-analyser
        It represents the analyser. Whenever you want to run the analyser
        on a benchmark (Java web app) you have to go into this sub-directory
        and run there a script "run.py". There are also located other scripts
        and data providing fully automated analysis of benchmarks.

    ./TRAINING
        This is a root directory of traning benchmarks. They serve us only for
        debugging purposes. They won't be part of the evaluation (demo).

All remaining sub-directories in this directory represent root directories
of genuine benchmarks which will be used in the evaluation. Names of these
directories should match names of the corresponding Java web applications.

There is also file "INFO.txt" in this directory. It contains general info about 
this demo (its specification) received from meetings and discussions with
management.

1.1. Directory structure of a benchmark

Each benchmark directory (including training ones) must have this structure
(sub-directories and files):

    ./APP
          /<java-web-app-sources-dir>
          README.txt
          roots.json
          taint.json
    
The sub-directory "<java-web-app-install-dir>" is a diretory, into which the
repository of a particular Java web application have be clonned into. Name of
this directory can be arbitrary (but application's name is a good practice).
The directory is initially empty (or missing completely). It is your task to
download/clone its repository, check-out a particulat commit and build it.
All instructions for these tasks are available in the "README.txt".

The file "README.txt" provides an installation and building guide of the
considered java web application. Besides that it also contains a brief
description of the application. 
IMPORTANT NOTE: The installation directory for a benchmark always is the
                directory "BENCHMARK" at the same level as "./APP" directory.
                If you fail to force the building system of the application
                to install binaries into that directory, then you are supposed
                to copy binaries manually (from the standard build locations of
                the application). The reason for that is simple, analyser's
                scripts assume binaries of the benchmark are located there.

The file "roots.json" contains a list of "root" runctions (methods of classes)
in which the analysis is supposed to start. The analyser will automatically be
executed on the benchmark once per each function in this file. This file is
analyser specific.

The file "taint.json" contains a specification of taint sources/sanitisers/sinks
for that particular java web application. This file is also analyser specific.

Once the benchmark is redy for analysis the structure should be the following:

    ./APP
          /<java-web-app-sources-dir>
              ...
          README.txt
          roots.json
          taint.json
    ./BENCHMARK
        ...

Once you run analysis on the benchmark the directory structure will be the
following:

    ./APP
          /<java-web-app-sources-dir>
              ...
          README.txt
          roots.json
          taint.json
    ./BENCHMARK
        ...
    ./BENCHMARK_EXT
        ...
    ./RESULTS(.aux)
        ...    
    
The directory "BENCHMARK_EXT" represents a temp directory for the analyser.
The analyser converts WAR and JAR files located in "BENCHMARK" directory
into a form compatible with the analyser and stores the resulting JAR files
into the directory BENCHMARK_EXT.

The directories "RESULTS" and "RESULTS.aux" represent root directories where
the analyser writes all results from the analysis, including all statistics,
etc. We discuss structure of results later. True results go only to "RESULTS".
The directory "RESULTS.aux" is auxiliary. We use it for debug purposes - until
we update the analyser so that it is able to produce results usable for the
evaluation.


2. Directory structure of analyser

The directory "goto-analyser" has this structure:

    ./data
          /openjdk-8-rt.jar-unpacked
          /openjdk-8-rt.jar-unpacked-PRUNED
    ./scripts
    README.txt
    run.py

Initially the directory "data" is empty (or missing completely). You are
supposed to prepare these before you can actually run the analyser. Details
about this installation are discussed in the "README.txt" file. This file
also discusses how the actually run the analyser of some benchmark.

The directory "scripts" contains Python scripts implementing individual parts
of the analysis pipeline. They are ment to be internal. You do not have to
deal with them.

The "run.py" is the root script of the analyser. Whenever you want to run the
analyser, use this Python script.


3. Structure of results

TODO!

