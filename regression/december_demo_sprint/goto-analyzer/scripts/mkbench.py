import os
import fnmatch
import filecmp
import shutil
import json
import time


def __get_my_dir(): return os.path.dirname(os.path.realpath(__file__))


def collect_files(app_build_dir,extension_text,dict_to_update):
    prof = { "duration": time.time() }
    for root, dirnames, filenames in os.walk(app_build_dir):
        for filename in fnmatch.filter(filenames, "*." + extension_text):
            if filename in dict_to_update:
                new_version = True
                for fdir in dict_to_update[filename]:
                    if filecmp.cmp(os.path.join(root, filename), os.path.join(fdir, filename)):
                        new_version = False
                        break
                if new_version:
                    dict_to_update[filename].append(root)
            else:
                dict_to_update[filename] = [root]
    prof["duration"] = time.time() - prof["duration"]
    return prof

def collect_war_files(app_build_dir,dict_to_update): return collect_files(app_build_dir,"war",dict_to_update)
def collect_jar_files(app_build_dir,dict_to_update): return collect_files(app_build_dir,"jar",dict_to_update)
def collect_class_files(app_build_dir,dict_to_update): return collect_files(app_build_dir,"class",dict_to_update)


def unpack_war_file(war_file,unpack_dir):
    prof = { "duration": time.time() }
    if not os.path.exists(unpack_dir):
        os.makedirs(unpack_dir)
    old_cwd = os.getcwd()
    os.chdir(unpack_dir)
    os.system(
        "jar "
        "xf " +
        war_file
        )
    os.chdir(old_cwd)
    prof["duration"] = time.time() - prof["duration"]
    return prof


def unpack_jar_file(war_file,unpack_dir): return unpack_war_file(war_file,unpack_dir)


def build_class_files_hierarchy(app_build_dir,out_root_dir,temp_dir):
    prof = { "duration": time.time(), "classes": [] }
    if not os.path.exists(out_root_dir):
        os.makedirs(out_root_dir)
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    shutil.copyfile(os.path.join(__get_my_dir(),"__diffblue_full_class_name_parser__.class"),
                    os.path.join(temp_dir,"__diffblue_full_class_name_parser__.class"))
    old_cwd = os.getcwd()
    os.chdir(temp_dir)
    clss = {}
    prof["collect_classes"] = collect_class_files(app_build_dir,clss)
    class_counter = 1
    num_classes = 0
    for fname in clss.keys():
        num_classes = num_classes + len(clss[fname])
    for fname in clss.keys():
        for fdir in clss[fname]:
            print("      [" + str(class_counter) + "/" + str(num_classes) + "] "
                  + os.path.relpath(os.path.abspath(os.path.join(fdir,fname)),app_build_dir) )
            class_counter = class_counter + 1
            clss_prof = { "file": os.path.relpath(os.path.abspath(os.path.join(fdir,fname)),app_build_dir) }
            #clss_prof["copy_src_class"] = { "duration": time.time() }
            shutil.copyfile(os.path.join(fdir,fname),os.path.join(temp_dir,fname))
            #clss_prof["copy_src_class"]["duration"] = time.time() - clss_prof["copy_src_class"]["duration"]
            clss_prof["calling_java"] = { "duration": time.time() }
            os.system(
                "java "
                "__diffblue_full_class_name_parser__ '"
                + os.path.splitext(fname)[0] + "'  './"
                + os.path.splitext(fname)[0] + ".CLASSNAME.txt'"
                )
            clss_prof["calling_java"]["duration"] = time.time() - clss_prof["calling_java"]["duration"]
            class_packages_path = ""
            if os.path.exists(os.path.splitext(fname)[0] + ".CLASSNAME.txt"):
                with open(os.path.splitext(fname)[0] + ".CLASSNAME.txt", "r") as full_name_file:
                    class_packages_path = full_name_file.read().replace('\n', '')
            if len(class_packages_path) == 0:
                print("      FAIL: " + os.path.relpath(os.path.abspath(os.path.join(fdir,fname)),app_build_dir))
            else:
                last_slash_pos = max(class_packages_path.rfind("/"),class_packages_path.rfind("\\"))
                if last_slash_pos == -1:
                    last_slash_pos = 0
                pure_packages_path = class_packages_path[:last_slash_pos]
                class_dst_dir = os.path.abspath(os.path.join(out_root_dir,pure_packages_path))
                if not os.path.exists(class_dst_dir):
                    os.makedirs(class_dst_dir)
                #clss_prof["copy_dst_class"] = {"duration": time.time()}
                shutil.copyfile(os.path.join(fdir,fname),os.path.join(class_dst_dir,fname))
                #clss_prof["copy_dst_class"]["duration"] = time.time() - clss_prof["copy_dst_class"]["duration"]
            prof["classes"].append(clss_prof)
    os.chdir(old_cwd)
    prof["duration"] = time.time() - prof["duration"]
    return prof


def pack_classes_to_jar(classes_dir,dst_file):
    prof = { "duration": time.time() }
    if not os.path.exists(os.path.dirname(dst_file)):
        os.makedirs(os.path.dirname(dst_file))
    old_cwd = os.getcwd()
    os.chdir(classes_dir)
    os.system(
        "jar cf \""
        + dst_file + "\" ."
        )
    os.chdir(old_cwd)
    prof["duration"] = time.time() - prof["duration"]
    return prof


def exists_jars_configuration(temp_dir):
    config_file_pathname = os.path.abspath(os.path.join(temp_dir,"jars.json"))
    if os.path.exists(config_file_pathname):
        return True
    return False


def build_jars_configuration(binaries_dir,temp_dir):
    prof = { "war": [], "duration": time.time() }
    temp_dirs_counter = 0
    root_jars = {}
    jars = {}
    wars = {}
    prof["collect_wars"] = collect_war_files(binaries_dir,wars)
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    for fname in wars.keys():
        for fdir in wars[fname]:
            war_file = os.path.join(fdir,fname)

            war_prof = { "file": war_file }

            war_tmp_root = os.path.join(temp_dir,fname + "." + str(temp_dirs_counter))
            temp_dirs_counter = temp_dirs_counter + 1

            print("  Processing WAR file: " + war_file)
            print("    Unpacking...")
            unpack_dir = war_tmp_root + ".UNPACK.dir"
            war_prof["unpack_war"] = unpack_war_file(war_file,unpack_dir)

            print("    Collecting JARs...")
            war_prof["collect_jars"] = collect_jar_files(unpack_dir, jars)

            print("    Copying classes...")
            class_dir = war_tmp_root + ".CLASSES.dir"
            class_temp_dir = war_tmp_root + ".TEMP.dir"
            war_prof["copy_classes"] = build_class_files_hierarchy(unpack_dir,class_dir,class_temp_dir)

            root_jar_fname = war_tmp_root + ".PACK.dir/" + os.path.splitext(fname)[0] + ".jar"
            print("    Packing classes: " + root_jar_fname)
            war_prof["pack_classes"] = pack_classes_to_jar(class_dir,root_jar_fname)
            root_jars[root_jar_fname] = class_dir

            prof["war"].append(war_prof)

    prof["collect_jars"] = collect_jar_files(binaries_dir,jars)

    print("  Saving config file 'jars.json'.")
    prof["saving_cfg"] = time.time()
    config = { "wars": root_jars, "jars": [] }
    for fname in jars.keys():
        for fdir in jars[fname]:
            config["jars"].append(os.path.abspath(os.path.join(fdir,fname)))
    config["jars"] = sorted(config["jars"])
    config_file_pathname = os.path.abspath(os.path.join(temp_dir,"jars.json"))
    config_file = open(config_file_pathname, "w")
    config_file.write(json.dumps(config,sort_keys=True,indent=4))
    config_file.close()
    prof["saving_cfg"] = time.time() - prof["saving_cfg"]
    prof["duration"] = time.time() - prof["duration"]
    return prof


def find_jar_containing_root_function_ex(relative_class_file_name, jars_cfg,temp_dir):
    prof = { "duration": time.time(), "processed": [] }
    unpack_root_dir = os.path.abspath(os.path.join(temp_dir,"__diffblue__.find_jar_containing_root_function_ex.dir"))
    dir_counter = 0
    result_jar_fname = ""
    for jar_file in jars_cfg:
        jar_prof = { "file": jar_file }
        unpack_dir = os.path.abspath(os.path.join(unpack_root_dir,
                                                  os.path.basename(jar_file) + "." + str(dir_counter) + ".UNPACK.dir"))
        if not os.path.exists(unpack_dir):
            os.makedirs(unpack_dir)
            jar_prof["unpack"] = unpack_jar_file(jar_file, unpack_dir)
        full_class_file_name = os.path.abspath(os.path.join(unpack_dir,relative_class_file_name))
        prof["processed"].append(jar_prof)
        if os.path.exists(full_class_file_name):
            result_jar_fname = jar_file
            break
    prof["duration"] = time.time() - prof["duration"]
    return result_jar_fname,prof


def find_jar_containing_root_function(root_fn, wars_jars_cfg,temp_dir):
    prof = { "duration": time.time() }
    jars_cfg = wars_jars_cfg["wars"]
    print("Searching for JAR file containing root function: " + root_fn)
    last_dot_index = root_fn.rfind(".")
    if last_dot_index < 1:
        print("ERROR: Cannot extract class name from function name in the root function specifier: " + root_fn)
        prof["duration"] = time.time() - prof["duration"]
        return "",prof
    relative_class_file_name = root_fn[:last_dot_index].replace('.', '/') + ".class"
    for jar_pathname in jars_cfg.keys():
        classes_root_dir = jars_cfg[jar_pathname]
        if os.path.exists(os.path.join(classes_root_dir,relative_class_file_name)):
            prof["duration"] = time.time() - prof["duration"]
            return jar_pathname,prof
    result_jar,prof_ex = find_jar_containing_root_function_ex(relative_class_file_name, wars_jars_cfg["jars"],temp_dir)
    prof["find_jar_ex"] = prof_ex
    prof["duration"] = time.time() - prof["duration"]
    return result_jar,prof


def __dbg_test_collect_files(app_build_dir):
    print("TEST: scripts.mkbench.__dbg_test_collect_files(" + app_build_dir + ")")
    print("--- WARs ---")
    wars = {}
    collect_war_files(app_build_dir,wars)
    for fname in wars.keys():
        for fdir in wars[fname]:
            print(os.path.join(fdir, fname))
    print("--- JARs ---")
    jars = {}
    collect_jar_files(app_build_dir,jars)
    for fname in jars.keys():
        for fdir in jars[fname]:
            print(os.path.join(fdir, fname))
    print("--- CLASSes ---")
    clss = {}
    collect_class_files(app_build_dir,clss)
    for fname in clss.keys():
        for fdir in clss[fname]:
            print(os.path.join(fdir, fname))
    print("--- DONE ---")


def __dbg_test_repack_war_files(app_build_dir,analyser_temp_dir):
    print("TEST: scripts.mkbench.__dbg_test_unpack_war_file(" + app_build_dir + ")")
    wars = {}
    collect_war_files(app_build_dir,wars)
    if len(wars) == 0:
        print("The benchmarks does not have any WAR files.")
        return
    for fname in wars.keys():
        for fdir in wars[fname]:
            print("--- Unpacking WAR ---")
            war_file = os.path.join(fdir,fname)
            unpack_dir = analyser_temp_dir + "/" + fname + ".UNPACK.dir"
            print("WAR file  : " + war_file)
            print("Unpack dir: " + unpack_dir)
            unpack_war_file(war_file,unpack_dir)
            print("--- Copying CLASSes ---")
            class_dir = analyser_temp_dir + "/" + fname + ".CLASSES.dir"
            print("Classes dir: " + class_dir)
            temp_dir = analyser_temp_dir + "/" + fname + ".TEMP.dir"
            print("Temp dir   : " + temp_dir)
            build_class_files_hierarchy(unpack_dir,class_dir,temp_dir)
            print("--- Packing classes to JAR ---")
            packed_jar_file = analyser_temp_dir + "/" + fname + ".PACK.dir/" + os.path.splitext(fname)[0] + ".jar"
            print("JAR file   : " + packed_jar_file)
            pack_classes_to_jar(class_dir,packed_jar_file)
            print("--- DONE ---")
            return
    print("--- DONE ---")


if __name__ == "__main__":
    app_name = "Sakai"  # Sakai Openolat
    mydir = os.path.dirname(os.path.realpath(__file__))
    eval_root_dir = os.path.abspath(mydir + "/../..")
    app_build_dir = os.path.abspath(eval_root_dir + "/" + app_name + "/BENCHMARK")
    analyser_temp_dir = os.path.abspath(mydir + "/../temp/dbg_mkbench/" + app_name)

    #__dbg_test_collect_files(app_build_dir)
    __dbg_test_repack_war_files(app_build_dir,analyser_temp_dir)
