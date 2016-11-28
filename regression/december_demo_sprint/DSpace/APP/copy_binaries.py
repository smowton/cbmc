import os
import shutil

my_dir = os.path.dirname(os.path.realpath(__file__))

dir_names = [
    "dspace",
    "dspace-api",
    "dspace-jspui",
    "dspace-oai",
    "dspace-rdf",
    "dspace-rest",
    "dspace-services",
    "dspace-solr",
    "dspace-sword",
    "dspace-swordv2",
    "dspace-xmlui",
    "dspace-xmlui-mirage2"
]

for dir_name in dir_names:
    src_dir = os.path.abspath(os.path.join(my_dir,"DSpace",dir_name,"target"))
    dst_dir = os.path.abspath(os.path.join(my_dir,"..","BENCHMARK",dir_name,"target"))
    if os.path.exists(dst_dir):
        shutil.rmtree(dst_dir)
    shutil.copytree(src_dir,dst_dir)
