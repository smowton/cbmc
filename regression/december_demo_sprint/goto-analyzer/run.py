import scripts.mkbench
import scripts.analyser
import argparse
import os
import shutil
import json
import time


def __get_my_dir(): return os.path.dirname(os.path.realpath(__file__))


def parse_cmd_line():
    parser = argparse.ArgumentParser(
        description="This is the root script for running goto-analyser on a Java web application. "
                    "The typical usage in terminal is 'python ./run.py -E \"../<benchmark-name>\"', "
                    "where '<benchmark-name>' is one of the benchmark directories in the root directory of the "
                    "evaluation framework, like Sakai, Openolet, etc.")
    parser.add_argument("-V","--version", action="store_true",
                        help="Prints a version string.")
    parser.add_argument("-E", "--evaluation-dirs", type=str, nargs='*',
                         help="A list of evaluation directories, each of defined structure and containing a Java web "
                              "application and its binaries in standard sub-directories. This option will automatically "
                              "set all those options from { -C, -S, -B, -T, -R } which were not specified, for each "
                              "directory in the list.")
    parser.add_argument("-C", "--spec-dir", type=str,
                         help="A directory containing all specification files for the analyser (like 'taint.json') "
                              "which should be used for the analysed Java web application.")
    parser.add_argument("-S", "--sources-dir", type=str,
                         help="A root directory of source code of the analysed Java web application.")
    parser.add_argument("-B", "--binaries-dir", type=str,
                         help="A root directory of built binaries (WAR/JAR/CLASS files) of the analysed Java web "
                              "application.")
    parser.add_argument("-T", "--temp-dir", type=str,
                         help="A directory which the analyser may use for creating, deleting, writing, and reading "
                              "temporary files.")
    parser.add_argument("-R", "--results-dir", type=str,
                         help="A directory into which all results from the analysis will be stored.")
    parser.add_argument("--rebuild", action="store_true",
                        help="When specified, the directories -T and -R are deleted at the beginning of the analysis. "
                             "This has an effect to running the analysis from scratch without reuse of any data "
                             "computed in the previous run of the analyser of the specified benchmark.")
    parser.add_argument("--timeout", type=int, default=300,
                         help="A timeout in seconds for the goto-analyser. It means that it is NOT a timeout for "
                              "whole the analysis. Namely, it does not include preprocessing steps of WAR/JAR file "
                              "for goto-analyses nor saving results from the analysis. Also, since goto-analyser "
                              "might be executed several times per one benchmark (once per each root function), "
                              "the timeout applies to each of this executions independently (i.e. it is NOT a "
                              "summary timeout for all executions).")
    parser.add_argument("--dump-html-summaries", action="store_true",
                        help="If specified, then the analyser will save function summaries in HTML format together "
                             "with in JSON format (which is always saved).")
    parser.add_argument("--dump-html-statistics", action="store_true",
                        help="If specified, then the analyser will save statistics in HTML format together "
                             "with in JSON format (which is always saved).")
    parser.add_argument("--dump-html-traces", action="store_true",
                        help="If specified, then the analyser will save error traces in HTML format together "
                             "with in JSON format (which is always saved).")
    return parser.parse_args()


def  evaluate_one_directory(cmdline):
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

    prof = { "duration": time.time() }

    if cmdline.rebuild:
        if os.path.exists(cmdline.temp_dir):
            print("Deleting " + cmdline.temp_dir)
            shutil.rmtree(cmdline.temp_dir)
        if os.path.exists(cmdline.results_dir):
            print("Deleting " + cmdline.results_dir)
            shutil.rmtree(cmdline.results_dir)

    if not scripts.analyser.exists_java_script():
        print("Building parser of Java class files.")
        prof["build_java_script"] = scripts.analyser.build_java_script()

    if not scripts.analyser.exists_goto_analyser():
        print("Building goto analyser")
        prof["build_goto_analyser"] = scripts.analyser.build_goto_analyser()

    if not scripts.mkbench.exists_jars_configuration(cmdline.temp_dir):
        print("Building configuration of JAR files to analyse:")
        prof["build_jars_cfg"] = scripts.mkbench.build_jars_configuration(cmdline.binaries_dir,cmdline.temp_dir)

    prof["loading_jars_cfg"] = { "duration": time.time() }
    jars_cfg_fname = os.path.abspath(os.path.join(cmdline.temp_dir,"jars.json"))
    print("Loading config file " + jars_cfg_fname)
    jars_cfg_file = open(jars_cfg_fname, "r")
    jars_cfg = json.load(jars_cfg_file)
    jars_cfg_file.close()
    prof["loading_jars_cfg"]["duration"] = time.time() - prof["loading_jars_cfg"]["duration"]

    prof["loading_root_functions"] = { "duration": time.time() }
    roots_cfg_fname = os.path.abspath(os.path.join(cmdline.spec_dir,"roots.json"))
    if not os.path.exists(roots_cfg_fname):
        print("ERROR: The root-functions config file does not exist: " + roots_cfg_fname)
        print("Analysis was stopped.")
        return
    print("Loading root-functions config file " + roots_cfg_fname)
    roots_cfg_file = open(roots_cfg_fname, "r")
    roots_fn_list = json.load(roots_cfg_file)
    roots_cfg_file.close()
    prof["loading_root_functions"]["duration"] = time.time() - prof["loading_root_functions"]["duration"]

    taint_json_fname = os.path.abspath(os.path.join(cmdline.spec_dir,"taint.json"))
    dirs_counter = 0
    for root_fn in roots_fn_list:
        root_jar,prof["find_jar"] = scripts.analyser.find_jar_containing_root_function(root_fn,jars_cfg["wars"])
        if len(root_jar) == 0:
            print("ERROR: The search for JAR file containing root function '" + root_fn + "' has FAILED."
                  "Skipping this configuration.")
        else:
            results_dir = os.path.abspath(os.path.join(cmdline.results_dir,
                                                       root_fn + "." + str(dirs_counter) + ".RESULTS.dir"))
            prof["run_analyser"] = scripts.analyser.run_goto_analyser(
                                            root_fn,
                                            root_jar,
                                            jars_cfg,
                                            taint_json_fname,
                                            cmdline.timeout,
                                            cmdline.dump_html_summaries,
                                            cmdline.dump_html_statistics,
                                            cmdline.dump_html_traces,
                                            results_dir
                                            )

    print("Saving results into directory: " + cmdline.results_dir)
    if not os.path.exists(cmdline.results_dir):
        os.makedirs(cmdline.results_dir)

    overall_perf_fname = os.path.abspath(os.path.join(cmdline.results_dir,"overall_performance.json"))
    print("  Saving overall performance statistics to: " + overall_perf_fname)
    overall_perf_file = open(overall_perf_fname,"w")
    prof["duration"] = time.time() - prof["duration"]
    overall_perf_file.write(json.dumps(prof,sort_keys=True,indent=4))
    overall_perf_file.close()
    print("Done. [Time=" + str(prof["duration"]) + "s]")


def __main():
    cmdline = parse_cmd_line()

    if cmdline.version:
        print("This is goto-analyzer version 0.1.0.")
        return

    if len(cmdline.evaluation_dirs) > 0:
        set_sepc = cmdline.spec_dir is None
        set_sources = cmdline.sources_dir is None
        set_binaries = cmdline.binaries_dir is None
        set_temp = cmdline.temp_dir is None
        set_results = cmdline.results_dir is None
        for evaluation_dir in cmdline.evaluation_dirs:
            if set_sepc:
                cmdline.spec_dir = os.path.abspath(os.path.join(evaluation_dir,"APP"))
            if set_sources:
                cmdline.sources_dir = os.path.abspath(os.path.join(cmdline.spec_dir,os.path.basename(evaluation_dir)))
            if set_binaries:
                cmdline.binaries_dir = os.path.abspath(os.path.join(evaluation_dir,"BENCHMARK"))
            if set_temp:
                cmdline.temp_dir = os.path.abspath(os.path.join(evaluation_dir,"BENCHMARK_EXT"))
            if set_results:
                cmdline.results_dir = os.path.abspath(os.path.join(evaluation_dir, "RESULTS.aux"))
            evaluate_one_directory(cmdline)
    else:
        evaluate_one_directory(cmdline)


if __name__ == "__main__":
    __main()
