#! /usr/bin/env python
"""
Version 3.0~ of Hashmarker (CSSA)
Author: Seulbae Kim (seulbae@korea.ac.kr)
http://github.com/squizz617/discovuler-advanced/hmark
"""


# import Tkinter
# import ttk
import argparse
import multiprocessing
import subprocess
import parseutility2 as pu
import logging,config
import urllib3
import platform
import sys
import os, subprocess
import time
import webbrowser
import hashlib
from distutils.version import LooseVersion
from re import compile, findall
from collections import defaultdict
logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='myapp3.log',
                filemode='w')
#################################################################################################
#定义一个StreamHandler，将INFO级别或更高的日志信息打印到标准错误，并将其添加到当前的日志处理对象#
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)
#################################################################################################


""" GLOBALS """
localVersion = "3.1.0"


def parsefile_shallow_multi(f):
    func_infos = pu.parseFile_shallow(f)
    return f, func_infos


def parsefile_deep_multi(f):
    func_infos = pu.parseFile_deep(f)
    return f, func_infos


def generate_cli(targetPath):
    directory = targetPath.rstrip('/').rstrip("\\")
    absLevel = 4
    proj = directory.replace('\\', '/').split('/')[-1]
    logging.info("PROJ:%s" % proj)
    logging.info("Loading source files... This may take a few minutes.")
    input_files = pu.loadSource(directory)
    if len(input_files) == 0:
        logging.error("Failed loading source files.")
        logging.error("Check if you selected proper directory, or if your project contains .c or .cpp files.")
        sys.exit(1)
    else:
        logging.info("Load complete. Generating hashmark...")
        function_info_list = defaultdict(list)
        for file in input_files:
            logging.info("[%d/%d]\t%s"%(input_files.index(file), len(input_files), file))
            file, func_infos = parsefile_deep_multi(file)
            for index in range(len(func_infos["funcBody"])):
                absBody = pu.abstract(func_infos, index, absLevel)[1]
                absBody = pu.normalize(absBody)
                funcLen = len(absBody)
                if funcLen > config.function_char_length:
                    logging.info(absBody)
                    m = hashlib.md5()
                    m.update(absBody.encode('utf-8'))
                    hashValue = m.hexdigest()
                    function_info_list["function_hash"].append(hashValue)
                    function_info_list["function_name"].append(func_infos["name"][index])
                    function_info_list["function_code"].append(func_infos["funcBody"][index])
                    function_info_list["CVE_infos"].append(file.split('/')[-1].split('_')[1])
                    function_info_list["proj_name"].append(file.split('/')[-1].split('_')[0])
        logging.info("finished hashmark...")
    return function_info_list
