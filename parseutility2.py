#! /usr/bin/env python
"""
Parser utility.
Author: Seulbae Kim
Created: August 03, 2016
"""

import os
import sys
import subprocess
import re,logging
from collections import defaultdict
import config
logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='myapp21.log',
                filemode='w')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)


class function:
    parentFile = None  # Absolute file which has the function
    parentNumLoc = None  # Number of LoC of the parent file
    name = None  # Name of the function
    lines = None  # Tuple (lineFrom, lineTo) that indicates the LoC of function
    funcId = None  # n, indicating n-th function in the file
    parameterList = []  # list of parameter variables
    variableList = []  # list of local variables
    dataTypeList = []  # list of data types, including user-defined types
    funcCalleeList = []  # list of called functions' names
    funcBody = None

    def __init__(self, fileName):
        self.parentFile = fileName
        self.parameterList = []
        self.variableList = []
        self.dataTypeList = []
        self.funcCalleeList = []

    def removeListDup(self):
        self.parameterList = list(set(self.parameterList))
        self.variableList = list(set(self.variableList))
        self.dataTypeList = list(set(self.dataTypeList))
        self.funcCalleeList = list(set(self.funcCalleeList))


def loadSource(rootDirectory):
    maxFileSizeInBytes = None
    maxFileSizeInBytes = 2*1024*1024
    walkList = os.walk(rootDirectory)
    srcFileList = []
    for path, dirs, files in walkList:
        for fileName in files:
            ext = fileName.lower()
            if ext.endswith('.c') or ext.endswith('.cpp') or ext.endswith('.cc') or ext.endswith('.c++') or ext.endswith('.cxx'):
                absPathWithFileName = path.replace('\\', '/') + '/' + fileName
                if maxFileSizeInBytes is not None:
                    if os.path.getsize(absPathWithFileName) < maxFileSizeInBytes:
                        srcFileList.append(absPathWithFileName)
                else:
                    srcFileList.append(absPathWithFileName)
    return srcFileList


def loadVul(rootDirectory):
    maxFileSizeInBytes = None
    walkList = os.walk(rootDirectory)
    srcFileList = []
    for path, dirs, files in walkList:
        for fileName in files:
            if fileName.endswith('OLD.vul'):
                absPathWithFileName = path.replace('\\', '/') + '/' + fileName
                if maxFileSizeInBytes is not None:
                    if os.path.getsize(absPathWithFileName) < maxFileSizeInBytes:
                        srcFileList.append(absPathWithFileName)
                else:
                    srcFileList.append(absPathWithFileName)
    return srcFileList


def removeComment(string):
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])


def normalize(string):
    return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
        ' ')).lower()


def abstract(func_infos, index, level):
    originalFunctionBody = func_infos["funcBody"][index]
    originalFunctionBody = removeComment(originalFunctionBody)
    if int(level) >= 0:  # No abstraction.
        abstractBody = originalFunctionBody
    if int(level) >= 1:  # PARAM
        parameterList = func_infos["parameterList"]
        for param in parameterList:
            if len(param) == 0:
                continue
            try:
                paramPattern = re.compile("(^|\W)" + param + "(\W)")
                abstractBody = paramPattern.sub("\g<1>FPARAM\g<2>", abstractBody)
            except:
                pass
    if int(level) >= 2:  # DTYPE
        dataTypeList = func_infos["dataTypeList"]
        for dtype in dataTypeList:
            if len(dtype) == 0:
                continue
            try:
                dtypePattern = re.compile("(^|\W)" + dtype + "(\W)")
                abstractBody = dtypePattern.sub("\g<1>DTYPE\g<2>", abstractBody)
            except:
                pass
    if int(level) >= 3:  # LVAR
        variableList = func_infos["variableList"]
        for lvar in variableList:
            if len(lvar) == 0:
                continue
            try:
                lvarPattern = re.compile("(^|\W)" + lvar + "(\W)")
                abstractBody = lvarPattern.sub("\g<1>LVAR\g<2>", abstractBody)
            except:
                pass
    if int(level) >= 4:  # FUNCCALL
        funcCalleeList = func_infos["funcCalleeList"]
        for fcall in funcCalleeList:
            if len(fcall) == 0:
                continue
            try:
                fcallPattern = re.compile("(^|\W)" + fcall + "(\W)")
                abstractBody = fcallPattern.sub("\g<1>FUNCCALL\g<2>", abstractBody)
            except:
                pass
    return originalFunctionBody, abstractBody


def parseFile_shallow(srcFileName):
    javaCallCommand = "java -Xmx1024m -jar %s %s" % (config.opt_jar, srcFileName)
    logging.info(srcFileName)
    try:
        astString = subprocess.check_output(javaCallCommand, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        logging.error("Parser Error: %s" % str(e))
        astString = ""
    delimiter = "\r\0?\r?\0\r"
    funcList = astString.split(delimiter.encode('utf-8'))
    logging.info(funcList)
    func_infos = defaultdict(list)
    for func in funcList[1:]:
        elemsList = func.split('\n')[1:-1]
        if len(elemsList) > 9:
            func_infos["parentNumLoc"].append(int(elemsList[1]))
            func_infos["name"].append(elemsList[2])
            func_infos["lines"].append([int(elemsList[3].split('\t')[0]), int(elemsList[3].split('\t')[1])])
            func_infos["funcId"].append(int(elemsList[4]))
            func_infos["funcBody"].append('\n'.join(elemsList[9:]))
    logging.info(func_infos)
    return func_infosList


def parseFile_deep(srcFileName):
    javaCallCommand = "java -Xmx1024m -jar %s %s" % (config.opt_jar, srcFileName)
    try:
        astString = subprocess.check_output(javaCallCommand, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        logging.error("Parser Error: %s" % str(e))
        astString = ""
    delimiter = "\r\0?\r?\0\r"
    funcList = astString.split(delimiter.encode('utf-8'))
    func_infos = defaultdict(list)
    for func in funcList[1:]:
        elemsList = func.decode(encoding='utf-8').split('\n')[1:-1]
        if len(elemsList) > 9:
            func_infos["parentNumLoc"].append(int(elemsList[1]))
            func_infos["name"].append(elemsList[2])
            func_infos["lines"].append([int(elemsList[3].split('\t')[0]), int(elemsList[3].split('\t')[1])])
            func_infos["funcId"].append(elemsList[4])
            func_infos["parameterList"].append(elemsList[5].rstrip().split('\t'))
            func_infos["variableList"].append(elemsList[6].rstrip().split('\t'))
            func_infos["dataTypeList"].append(elemsList[7].rstrip().split('\t'))
            func_infos["funcCalleeList"].append(elemsList[8].rstrip().split('\t'))
            func_infos["funcBody"].append('\n'.join(elemsList[9:]))
    return func_infos
