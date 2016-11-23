import os


def __get_my_dir(): return os.path.dirname(os.path.realpath(__file__))


def get_binary_dir():
    return os.path.abspath(__get_my_dir() + "/../../../../src/goto-analyzer")


def get_binary_file():
    return os.path.abspath(get_binary_dir() + "/goto-analyzer")


def __get_make_dir():
    return os.path.abspath(get_binary_dir() + "/..")


# print("my dir  : " + __get_my_dir())
# print("bin dir : " + get_binary_dir())
# print("bin file: " + get_binary_file())
# print("make dir: " + __get_make_dir())


def exists_java_script():
    return os.path.exists(os.path.join(__get_my_dir(),"__diffblue_full_class_name_parser__.class"))


def build_java_script():
    old_cwd = os.getcwd()
    os.chdir(__get_my_dir() + "/scripts")
    os.system("ant")
    os.chdir(old_cwd)


def exists_goto_analyser():
    return os.path.exists(get_binary_file())


def build_goto_analyser():
    old_current_dir = os.getcwd()
    os.chdir(__get_make_dir())
    os.system("make all")
    os.chdir(old_current_dir)


def run_binary_file():
    pass

