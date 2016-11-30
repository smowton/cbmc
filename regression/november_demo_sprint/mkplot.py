import argparse
import os
import re
import json


def load_input_JSON(filename):
    file = open(filename,"r")
    stats = json.load(file)
    file.close()
    return stats


def build_data_file(stats,output_file_name):
    file = open(output_file_name,"w")
    num_functions = 0
    num_locations = 0
    time = 0.0
    num_functions_per_second = 0
    num_locations_per_second = 0
    for file_stats in stats["table-files"]:
        for fn_stats in file_stats["functions"]:
            delta_time = fn_stats["LVSA-duration"] + fn_stats["TA-duration"]
            #if delta_time > 1.0:
            #    print("TIME[" + str(delta_time) + "]: " + fn_stats["function-name"])
            #    continue
            time = time + delta_time 
            num_functions = num_functions + 1
            num_locations = num_locations + fn_stats["num-locations"]
            if time > 0.0001:
                num_functions_per_second =  num_functions / time
                num_locations_per_second =  num_locations / time
            file.write(str(time) + "    " + \
                       str(num_functions)  + "    " + \
                       str(num_locations)  + "    " + \
                       str(num_functions_per_second) + "    " + \
                       str(num_locations_per_second) + "\n")  
    file.close()
    

def build_functions_speed_plot_file(plot_file_name,data_file_name):
    file = open(plot_file_name,"w")
    file.write(
            "set title \"Number of analysed functions per second.\"\n"
            "set terminal svg font 'Roman,20' size 550,480\n"
            "set output './" + os.path.splitext(os.path.basename(plot_file_name))[0] + ".svg'\n"
            "set xtic auto\n"
            "set ytic auto\n"
            "set xlabel \"Time (sec)\"\n"
            "set ylabel \"Speed (funcs/sec)\"\n"
            "set grid\n"
            "set style data lines\n"
            "unset key\n"
            "plot \"./" + os.path.basename(data_file_name) + "\" using 1:4 lt -1 lw 2\n"
            )
    file.close()


def build_locations_speed_plot_file(plot_file_name,data_file_name):
    file = open(plot_file_name,"w")
    file.write(
            "set title \"Number of analysed lines per second.\"\n"
            "set terminal svg font 'Roman,20' size 550,480\n"
            "set output './" + os.path.splitext(os.path.basename(plot_file_name))[0] + ".svg'\n"
            "set xtic auto\n"
            "set ytic auto\n"
            "set xlabel \"Time (sec)\"\n"
            "set ylabel \"Speed (lines/sec)\"\n"
            "set style data lines\n"
            "set grid\n"
            "unset key\n"
            "plot \"./" + os.path.basename(data_file_name) + "\" using 1:5 lt -1 lw 2\n"
            )
    file.close()


def build_functions_progress_plot_file(plot_file_name,data_file_name):
    file = open(plot_file_name,"w")
    file.write(
            "set title \"Number of analysed functions in time.\"\n"
            "set terminal svg font 'Roman,20' size 550,480\n"
            "set output './" + os.path.splitext(os.path.basename(plot_file_name))[0] + ".svg'\n"
            "set xtic auto\n"
            "set ytic auto\n"
            "set xlabel \"Time (sec)\"\n"
            "set ylabel \"Functions (#)\"\n"
            "set style data lines\n"
            "set grid\n"
            "unset key\n"
            "plot \"./" + os.path.basename(data_file_name) + "\" using 1:2 lt -1 lw 2\n"
            )
    file.close()
    

def build_locations_progress_plot_file(plot_file_name,data_file_name):
    file = open(plot_file_name,"w")
    file.write(
            "set title \"Number of analysed lines in time.\"\n"
            "set terminal svg font 'Roman,20' size 550,480\n"
            "set output './" + os.path.splitext(os.path.basename(plot_file_name))[0] + ".svg'\n"
            "set xtic auto\n"
            "set ytic auto\n"
            "set xlabel \"Time (sec)\"\n"
            "set ylabel \"Lines (#)\"\n"
            "set style data lines\n"
            "set grid\n"
            "unset key\n"
            "plot \"./" + os.path.basename(data_file_name) + "\" using 1:3 lt -1 lw 2\n"
            )
    file.close()


def build_general_stats_text_file(stats,output_file_path_name):
    num_functions = 0
    num_locations = 0
    analysis_duration = 0.0
    for file_stats in stats["table-files"]:
        for fn_stats in file_stats["functions"]:
            analysis_duration = analysis_duration + fn_stats["LVSA-duration"] + fn_stats["TA-duration"]
            num_functions = num_functions + 1
            num_locations = num_locations + fn_stats["num-locations"]
    num_files = len(stats["table-files"])
    program_building_duration = stats["table-phases"]["goto-program-building"]

    file = open(output_file_path_name,"w")
    file.write("number of files = " + str(num_files) + "\n")
    file.write("number of functions = " + str(num_functions) + "\n")
    file.write("number of locations = " + str(num_locations) + "\n")
    file.write("program parsing duration = " + str(program_building_duration) + "\n")
    if num_files > 0: file.write("average parsing duration per file = " + str(program_building_duration / num_files) + "\n")
    if num_functions > 0: file.write("average parsing duration per function = " + str(program_building_duration / num_functions) + "\n")
    if num_locations > 0: file.write("average parsing duration per location = " + str(program_building_duration / num_locations) + "\n")
    file.write("analysis duration = " + str(analysis_duration) + "\n")
    if num_files > 0: file.write("average analysis duration per file = " + str(analysis_duration / num_files) + "\n")
    if num_functions > 0: file.write("average analysis duration per function = " + str(analysis_duration / num_functions) + "\n")
    if num_locations > 0: file.write("average analysis duration per location = " + str(analysis_duration / num_locations) + "\n")
    file.close()


def parse_cmd_line():
    parser = argparse.ArgumentParser(
        description="It produces plots from statistical data collected during run of taint anaylsis.")
    parser.add_argument("-V","--version", type=str, default="0.01",
                        help="Prints a version string of this utility.")
    parser.add_argument("-I", "--input-json", type=str, default="./dump_taint_statistics_JSON/taint_statistics.json",
                        help="A path-name of a JSON file containing statistics from a run of taint analysis.")
    parser.add_argument("-O", "--output-dir", type=str, default="./dump_taint_statistics_plots",
                        help="A directory where all plot files will be saved to.")
    parser.add_argument("-M", "--summary", action="store_true", default=True,
                        help="When present, then there is also generates a text file containing summary "
                             "statistical info about the analysis.")
    parser.add_argument("-S", "--build-svg", action="store_true", default=True,
                        help="When present, then generated gnuplot source files are used for the "
                             "generation also of the corresponding graphical SVG files by calling GNUPLOT tool "
                             "with passed source plot files. NOTE: This option goes in pair with "
                             "the option '--gnuplot'.")
    parser.add_argument("-G", "--gnuplot", type=str, default="gnuplot",
                        help="A path and name of an executable of the GNUPLOT tool.")
    args = parser.parse_args()
    return args


def script_main():
    args = parse_cmd_line()

    if not os.path.exists(args.input_json):
        print("Input JSON file " + args.input_json + " does not exist.")
        return
    if os.path.isdir(args.input_json):
        print("Input path-name " + args.input_json + " references a directory.")
        return
    if not os.path.exists(args.output_dir):
        os.mkdir(args.output_dir)

    print("*** Loading JSON file \"" + args.input_json + "\".")
    stats = load_input_JSON(args.input_json)

    data_file = os.path.join(args.output_dir,"analysis_data.dat")
    print("*** Building plot data file \""  + data_file +  "\".")
    build_data_file(stats,data_file)

    plot_file_func_speed = os.path.join(args.output_dir,"analysis_speed_functions.plt")
    print("*** Building function-speed plot script \""  + plot_file_func_speed +  "\".")
    build_functions_speed_plot_file(plot_file_func_speed,data_file)

    plot_file_loc_speed = os.path.join(args.output_dir,"analysis_speed_locations.plt")
    print("*** Building location-speed plot script \""  + plot_file_loc_speed +  "\".")
    build_locations_speed_plot_file(plot_file_loc_speed,data_file)

    plot_file_func_progress = os.path.join(args.output_dir,"analysis_progress_functions.plt")
    print("*** Building function-progress plot script \""  + plot_file_func_progress +  "\".")
    build_functions_progress_plot_file(plot_file_func_progress,data_file)

    plot_file_loc_progress = os.path.join(args.output_dir,"analysis_progress_locations.plt")
    print("*** Building locations-progress plot script \""  + plot_file_loc_progress +  "\".")
    build_locations_progress_plot_file(plot_file_loc_progress,data_file)

    if args.summary:
        summary_stats_file = os.path.join(args.output_dir,"analysis_summary_stats.txt")
        print("*** Building summary statistics file \""  + summary_stats_file +  "\".")
        build_general_stats_text_file(stats,summary_stats_file)

    if args.build_svg:
        cwd = os.getcwd()
        os.chdir(os.path.dirname(data_file))

        svg_file = os.path.join(args.output_dir,"analysis_speed_functions.svg")
        print("*** Building SVG file \""  + svg_file +  "\".")
        command = args.gnuplot + " \"./" + os.path.basename(plot_file_func_speed) + "\""
        os.system(command)

        svg_file = os.path.join(args.output_dir,"analysis_speed_locations.svg")
        print("*** Building SVG file \""  + svg_file +  "\".")
        command = args.gnuplot + " \"./" + os.path.basename(plot_file_loc_speed) + "\""
        os.system(command)

        svg_file = os.path.join(args.output_dir,"analysis_progress_functions.svg")
        print("*** Building SVG file \""  + svg_file +  "\".")
        command = args.gnuplot + " \"./" + os.path.basename(plot_file_func_progress) + "\""
        os.system(command)

        svg_file = os.path.join(args.output_dir,"analysis_progress_locations.svg")
        print("*** Building SVG file \""  + svg_file +  "\".")
        command = args.gnuplot + " \"./" + os.path.basename(plot_file_loc_progress) + "\""
        os.system(command)

        os.chdir(cwd)


    print("*** Done.")


if __name__ == "__main__":
    script_main()
