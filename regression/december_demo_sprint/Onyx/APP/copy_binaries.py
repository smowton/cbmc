import os
import shutil


def __get_my_dir(): return os.path.dirname(os.path.realpath(__file__))
def root_src_dir(): return os.path.abspath(os.path.join(__get_my_dir(),"Onyx"))
def root_dst_dir(): return os.path.abspath(os.path.join(__get_my_dir(),"..","BENCHMARK"))


def build_list_of_dirs():
    result = []
    for root, dirnames, filenames in os.walk(root_src_dir()):
        if os.path.basename(root) == "target":
            result.append(root)
    return result
    
dirs_list = build_list_of_dirs()
for src_dir in dirs_list:
    dst_dir = os.path.abspath(os.path.join(root_dst_dir(),os.path.relpath(src_dir,root_src_dir())))
    if os.path.exists(dst_dir):
        print("Deleting directory '" + dst_dir + "'")
        shutil.rmtree(dst_dir)
    print("Copying directory '" + src_dir + "' to '" + dst_dir + "'")
    shutil.copytree(src_dir,dst_dir)
