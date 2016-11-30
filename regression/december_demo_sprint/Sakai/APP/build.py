import os
import shutil

root_dir = os.path.dirname(os.path.realpath(__file__))
repo_dir = root_dir + "/Sakai"
build_dir = root_dir + "/../BENCHMARK"

os.makedirs(build_dir)
os.chdir(repo_dir)
os.system(
    "mvn "
    "install "
    "sakai:deploy "
    "-Dmaven.tomcat.home=" + build_dir + " "
    "-DskipTests "
    "-Dmaven.test.skip=true"
    )
os.chdir(root_dir)
