import scripts.mkbench
import scripts.analyser
import argparse
import os


def __get_my_dir(): return os.path.dirname(os.path.realpath(__file__))


def parse_cmd_line():
    parser = argparse.ArgumentParser(
        description="This is the root script for running goto-analyser on a Java web application.")
    parser.add_argument("-V","--version", action="store_true",
                        help="Prints a version string.")
    parser.add_argument("-S", "--sources-dir", type=str,
                         help="A root directory of source code of the analysed Java web application.")
    parser.add_argument("-B", "--binaries-dir", type=str,
                         help="A root directory of built binaries (WAR/JAR/CLASS files) of the analysed Java web application.")
    parser.add_argument("-T", "--temp-dir", type=str,
                         help="A directory which the analyser may use for creating, deleting, writing, and reading temporary files.")
    # parser.add_argument("-O", "--output-dir", type=str, default="./dump_taint_statistics_plots",
    #                     help="A directory where all plot files will be saved to.")
    # parser.add_argument("-M", "--summary", action="store_true", default=True,
    #                     help="When present, then there is also generates a text file containing summary "
    #                          "statistical info about the analysis.")
    # parser.add_argument("-S", "--build-svg", action="store_true", default=True,
    #                     help="When present, then generated gnuplot source files are used for the "
    #                          "generation also of the corresponding graphical SVG files by calling GNUPLOT tool "
    #                          "with passed source plot files. NOTE: This option goes in pair with "
    #                          "the option '--gnuplot'.")
    # parser.add_argument("-G", "--gnuplot", type=str, default="gnuplot",
    #                     help="A path and name of an executable of the GNUPLOT tool.")
    return parser.parse_args()


def __main():
    cmdline = parse_cmd_line()

    if cmdline.version:
        print("This is goto-analyzer version 0.1.0.")
        return

    if cmdline.sources_dir is None:
        print("ERROR: Sources dir of the analysed Java web application was not specified.")
        return
    if not os.path.exists(cmdline.sources_dir) or os.path.isfile(cmdline.sources_dir):
        print("ERROR: Sources dir of the analysed Java web application does not exists.")
        return
    if cmdline.binaries_dir is None:
        print("ERROR: Binaries dir of the analysed Java web application was not specified.")
        return
    if not os.path.exists(cmdline.binaries_dir) or os.path.isfile(cmdline.binaries_dir):
        print("ERROR: Binaries dir of the analysed Java web application does not exists.")
        return
    if cmdline.temp_dir is None:
        print("ERROR: Temp dir of the analyser was not specified.")
        return
    if os.path.exists(cmdline.temp_dir) and os.path.isfile(cmdline.temp_dir):
        print("ERROR: Temp dir of the analyser is an existing regular file.")
        return

    if not scripts.analyser.exists_java_script():
        print("*** Building parser of Java class files ***")
        scripts.analyser.build_java_script()

    if not scripts.analyser.exists_goto_analyser():
        print("\n*** Building goto analyser ***")
        scripts.analyser.build_goto_analyser()

    if not scripts.mkbench.exists_jars_configuration(cmdline.temp_dir):
        print("\n*** Building configuration of JAR files to analyse ***")
        scripts.mkbench.build_jars_configuration(cmdline.binaries_dir,cmdline.temp_dir)


if __name__ == "__main__":
    __main()
