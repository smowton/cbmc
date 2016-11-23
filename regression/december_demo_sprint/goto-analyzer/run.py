import scripts.mkbench
import scripts.analyser
import argparse
import os
import shutil
import json


def __get_my_dir(): return os.path.dirname(os.path.realpath(__file__))


def parse_cmd_line():
    parser = argparse.ArgumentParser(
        description="This is the root script for running goto-analyser on a Java web application.")
    parser.add_argument("-V","--version", action="store_true",
                        help="Prints a version string.")
    parser.add_argument("-E", "--evaluation-dir", type=str,
                         help="An evaluation directory of defined structure and containing a Java web application and "
                              "its binaries in standard sub-directories. This option will automatically set all those "
                              "options from { -C, -S, -B, -T, -R } which were not specified.")
    parser.add_argument("-C", "--spec-dir", type=str,
                         help="A directory containing all specification files for the analyser (like 'taint.json') "
                              "which should be used for the analysed Java web application.")
    parser.add_argument("-S", "--sources-dir", type=str,
                         help="A root directory of source code of the analysed Java web application.")
    parser.add_argument("-B", "--binaries-dir", type=str,
                         help="A root directory of built binaries (WAR/JAR/CLASS files) of the analysed Java web application.")
    parser.add_argument("-T", "--temp-dir", type=str,
                         help="A directory which the analyser may use for creating, deleting, writing, and reading temporary files.")
    parser.add_argument("-R", "--results-dir", type=str,
                         help="A directory into which all results from the analysis will be stored.")
    parser.add_argument("--rebuild", action="store_true",
                        help="When specified, the directories -T and -R are deleted at the beginning of the analysis.")
    return parser.parse_args()


def __main():
    cmdline = parse_cmd_line()

    if cmdline.version:
        print("This is goto-analyzer version 0.1.0.")
        return

    if cmdline.evaluation_dir is not None:
        if cmdline.spec_dir is None:
            cmdline.spec_dir = os.path.abspath(os.path.join(cmdline.evaluation_dir,"APP"))
        if cmdline.sources_dir is None:
            cmdline.sources_dir = os.path.abspath(os.path.join(cmdline.spec_dir,os.path.basename(cmdline.evaluation_dir)))
        if cmdline.binaries_dir is None:
            cmdline.binaries_dir = os.path.abspath(os.path.join(cmdline.evaluation_dir,"BENCHMARK"))
        if cmdline.temp_dir is None:
            cmdline.temp_dir = os.path.abspath(os.path.join(cmdline.evaluation_dir,"BENCHMARK_EXT"))
        if cmdline.results_dir is None:
            cmdline.results_dir = os.path.abspath(os.path.join(cmdline.evaluation_dir, "RESULTS"))

    if cmdline.spec_dir is None:
        print("ERROR: Directory containing specification files was not specified.")
        return
    if not os.path.exists(cmdline.spec_dir) or os.path.isfile(cmdline.spec_dir):
        print("ERROR: Directory containing specification files does not exists: " + cmdline.spec_dir)
        return
    if cmdline.sources_dir is None:
        print("ERROR: Sources dir of the analysed Java web application was not specified.")
        return
    if not os.path.exists(cmdline.sources_dir) or os.path.isfile(cmdline.sources_dir):
        print("ERROR: Sources dir of the analysed Java web application does not exists: " + cmdline.sources_dir)
        return
    if cmdline.binaries_dir is None:
        print("ERROR: Binaries dir of the analysed Java web application was not specified.")
        return
    if not os.path.exists(cmdline.binaries_dir) or os.path.isfile(cmdline.binaries_dir):
        print("ERROR: Binaries dir of the analysed Java web application does not exists: " + cmdline.binaries_dir)
        return
    if cmdline.temp_dir is None:
        print("ERROR: Temp dir of the analyser was not specified.")
        return
    if os.path.exists(cmdline.temp_dir) and os.path.isfile(cmdline.temp_dir):
        print("ERROR: Temp dir of the analyser is an existing regular file: " + cmdline.temp_dir)
        return
    if cmdline.results_dir is None:
        print("ERROR: Results dir for the analysis was not specified.")
        return
    if os.path.exists(cmdline.results_dir) and os.path.isfile(cmdline.results_dir):
        print("ERROR: Results dir for the analysis is an existing regular file: " + cmdline.results_dir)
        return

    bench_name = os.path.basename(cmdline.sources_dir)
    print("Starting analysis of Java web application '" + bench_name + "'.")

    overall_perf = {}

    if cmdline.rebuild is not None:
        if os.path.exists(cmdline.temp_dir):
            print("Deleting " + cmdline.temp_dir)
            shutil.rmtree(cmdline.temp_dir)
        if os.path.exists(cmdline.results_dir):
            print("Deleting " + cmdline.results_dir)
            shutil.rmtree(cmdline.results_dir)

    if not scripts.analyser.exists_java_script():
        print("Building parser of Java class files.")
        scripts.analyser.build_java_script()

    if not scripts.analyser.exists_goto_analyser():
        print("Building goto analyser")
        scripts.analyser.build_goto_analyser()

    if not scripts.mkbench.exists_jars_configuration(cmdline.temp_dir):
        print("Building configuration of JAR files to analyse:")
        scripts.mkbench.build_jars_configuration(cmdline.binaries_dir,cmdline.temp_dir)

    print("Starting 'goto-analyser' on TODO!")


    print("Saving results into directory: " + cmdline.results_dir)
    if not os.path.exists(cmdline.results_dir):
        os.makedirs(cmdline.results_dir)

    overall_perf_fname = os.path.abspath(os.path.join(cmdline.results_dir,"overall_performance.json"))
    print("  Saving overall performance statistics to: " + overall_perf_fname)
    overall_perf_file = open(overall_perf_fname,"w")
    overall_perf_file.write(json.dumps(overall_perf,sort_keys=True,indent=4))
    overall_perf_file.close()

    print("Done.")


if __name__ == "__main__":
    __main()
