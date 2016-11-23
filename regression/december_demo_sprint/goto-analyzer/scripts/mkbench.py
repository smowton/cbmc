import os
import fnmatch
import filecmp
import shutil
import json


def __get_my_dir(): return os.path.dirname(os.path.realpath(__file__))


def collect_files(app_build_dir,extension_text,dict_to_update):
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
    return dict_to_update

def collect_war_files(app_build_dir,dict_to_update): collect_files(app_build_dir,"war",dict_to_update)
def collect_jar_files(app_build_dir,dict_to_update): collect_files(app_build_dir,"jar",dict_to_update)
def collect_class_files(app_build_dir,dict_to_update): collect_files(app_build_dir,"class",dict_to_update)


def unpack_war_file(war_file,unpack_dir):
    if not os.path.exists(unpack_dir):
        os.makedirs(unpack_dir)
    old_cwd = os.getcwd()
    os.chdir(unpack_dir)
    os.system(
        "jar "
        "xvf " +
        war_file
        )
    os.chdir(old_cwd)


def build_class_files_hierarchy(app_build_dir,out_root_dir,temp_dir):
    if not os.path.exists(out_root_dir):
        os.makedirs(out_root_dir)
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    shutil.copyfile(os.path.join(__get_my_dir(),"__diffblue_full_class_name_parser__.class"),
                    os.path.join(temp_dir,"__diffblue_full_class_name_parser__.class"))
    old_cwd = os.getcwd()
    os.chdir(temp_dir)
    prefixes = []
    failed = []
    clss = {}
    collect_class_files(app_build_dir,clss)
    for fname in clss.keys():
        for fdir in clss[fname]:
            shutil.copyfile(os.path.join(fdir,fname),os.path.join(temp_dir,fname))
            os.system(
                "java "
                "__diffblue_full_class_name_parser__ '"
                + os.path.splitext(fname)[0] + "'  './"
                + os.path.splitext(fname)[0] + ".CLASSNAME.txt'"
                )
            class_packages_path = ""
            if os.path.exists(os.path.splitext(fname)[0] + ".CLASSNAME.txt"):
                with open(os.path.splitext(fname)[0] + ".CLASSNAME.txt", "r") as full_name_file:
                    class_packages_path = full_name_file.read().replace('\n', '')
            if len(class_packages_path) == 0:
                failed.append(os.path.abspath(os.path.join(fdir,fname)))
            else:
                prefixes.append(os.path.abspath(os.path.join(fdir,class_packages_path)))
                class_dst_dir = os.path.abspath(os.path.join(out_root_dir,class_packages_path))
                if not os.path.exists(class_dst_dir):
                    os.makedirs(class_dst_dir)
                shutil.copyfile(os.path.join(fdir,fname),os.path.join(class_dst_dir,fname))
    common_prefix = os.path.commonprefix(prefixes)
    for fail in failed:
        fail_common_prefix = os.path.commonprefix([fail,common_prefix])
        print("FAIL: " + fail)
        print("FAIL prefix: " + fail_common_prefix)
        fixed = os.path.abspath(os.path.join(out_root_dir,fail[len(fail_common_prefix):]))
        print("FIXED: " + fixed)
        shutil.copyfile(fail, fixed)
    os.chdir(old_cwd)


def pack_classes_to_jar(classes_dir,dst_file):
    if not os.path.exists(os.path.dirname(dst_file)):
        os.makedirs(os.path.dirname(dst_file))
    old_cwd = os.getcwd()
    os.chdir(classes_dir)
    os.system(
        "jar cvf \""
        + dst_file + "\" ."
        )
    os.chdir(old_cwd)


def exists_jars_configuration(temp_dir):
    config_file_pathname = os.path.abspath(os.path.join(temp_dir,"jars.json"))
    if os.path.exists(config_file_pathname):
        return True
    return False


def build_jars_configuration(binaries_dir,temp_dir):
    temp_dirs_counter = 0
    root_jars = []
    jars = {}
    wars = {}
    collect_war_files(binaries_dir,wars)
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    for fname in wars.keys():
        for fdir in wars[fname]:
            war_file = os.path.join(fdir,fname)

            war_tmp_root = os.path.join(temp_dir,fname + "." + str(temp_dirs_counter))
            temp_dirs_counter = temp_dirs_counter + 1

            print("Unpacking " + war_file)
            unpack_dir = war_tmp_root + ".UNPACK.dir"
            unpack_war_file(war_file,unpack_dir)

            print("Collecting JAR files...")
            collect_jar_files(unpack_dir, jars)

            print("Copying class files...")
            class_dir = war_tmp_root + ".CLASSES.dir"
            class_temp_dir = war_tmp_root + ".TEMP.dir"
            build_class_files_hierarchy(unpack_dir,class_dir,class_temp_dir)

            root_jar_fname = war_tmp_root + ".PACK.dir/" + os.path.splitext(fname)[0] + ".jar"
            print("Packing classes to JAR file " + root_jar_fname)
            pack_classes_to_jar(class_dir,root_jar_fname)
            root_jars.append(root_jar_fname)
    collect_jar_files(binaries_dir,jars)

    print("Saving config file 'jars.json'...")
    config = { "wars": root_jars, "jars": [] }
    for fname in jars.keys():
        for fdir in jars[fname]:
            config["jars"].append(os.path.abspath(os.path.join(fdir,fname)))

    config_file_pathname = os.path.abspath(os.path.join(temp_dir,"jars.json"))
    config_file = open(config_file_pathname, "w")
    config_file.write(json.dumps(config,sort_keys=True,indent=4))
    config_file.close()


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
