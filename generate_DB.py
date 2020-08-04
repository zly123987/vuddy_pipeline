import os
import subprocess
import config, mongodb, sys, re, csv
from unidiff import PatchSet
from collections import defaultdict
import logging
import linecache
import hashlib,time
logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='myapp3.log',
                filemode='w')
#################################################################################################
#定义一个StreamHandler，将INFO级别或更高的日志信息打印到标准错误，并将其添加到当前的日志处理对象#
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)


def clean_generate_folder(path):
    if os.path.exists(path):
        os.system("rm -r %s"%path)
        os.makedirs(path)
    else:
        os.makedirs(path)

def loadSource(input_folder):
    maxFileSizeInBytes = 2*1024*1024
    srcFileList = []
    for path, dirs, files in os.walk(input_folder):
        for fileName in files:
            ext = fileName.lower()
            if ext.endswith('.c') or ext.endswith('.cpp') or ext.endswith('.cc') or ext.endswith('.c++') or ext.endswith('.cxx'):
                filepath = os.path.join(path, fileName)
                if maxFileSizeInBytes is not None:
                    if os.path.getsize(filepath) < maxFileSizeInBytes:
                        srcFileList.append(filepath)
                else:
                    srcFileList.append(filepath)
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
    return abstractBody


def parsefile_deep_multi(srcFileName):
    javaCallCommand = "java -Xmx1024m -jar %s %s" % (config.opt_jar, srcFileName)
    try:
        astString = subprocess.check_output(javaCallCommand, stderr=subprocess.STDOUT, shell=True)
        astString = astString.decode('utf-8')
    except subprocess.CalledProcessError as e:
        logging.error("Parser Error: %s" % str(e))
        astString = ""
    delimiter = "\r\0?\r?\0\r"
    funcList = astString.split(delimiter)
    func_infos = defaultdict(list)
    for func in funcList[1:]:
        elemsList = func.split('\n')[1:-1]
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


def generate_cli(targetPath):
    absLevel = 4
    logging.info("PROJ:%s" % targetPath)
    logging.info("Loading source files... This may take a few minutes.")
    input_files = loadSource(targetPath)
    function_info_list = defaultdict(list)
    if len(input_files) == 0:
        logging.error("Failed loading source files.")
        logging.error("Check if you selected proper directory, or if your project contains .c or .cpp files.")
    else:
        logging.info("Load complete. Generating hashmark...")
        for file in input_files:
            logging.info("[%d/%d]\t%s" % (input_files.index(file), len(input_files), file))
            func_infos = parsefile_deep_multi(file)
            for index in range(len(func_infos["funcBody"])):
                absBody = abstract(func_infos, index, absLevel)
                absBody = removeComment(absBody)
                absBody = normalize(absBody)
                funcLen = len(absBody)
                if funcLen > config.function_char_length:
                    m = hashlib.md5()
                    m.update(absBody.encode('utf-8'))
                    hashValue = m.hexdigest()
                    function_info_list["function_hash"].append(hashValue)
                    function_info_list["function_name"].append(func_infos["name"][index])
                    function_info_list["function_code"].append(func_infos["funcBody"][index])
                    function_info_list["function_location"].append(func_infos["lines"])
        logging.info("finished hashmark...")
    return function_info_list


def parse_diff(path_to_patch, patch_temp_path):
    _, ext = os.path.splitext(path_to_patch)
    filename_info = {}
    tmp_file = os.path.join(patch_temp_path, 'tmp' + ext)
    with open(tmp_file, 'w+') as w:
        with open(path_to_patch, encoding='utf-8', errors='ignore') as r:
            w.write(r.read())
    patches = PatchSet.from_filename(tmp_file)
    for patch in patches:
        filename = '/'.join(patch.source_file.split('/')[1:])
        if filename[-2:] != '.c' and filename[-4:] != '.cpp' and filename[-4:] != '.cxx':
            continue
        patch_info_commit = patch.patch_info[-1]
        patch_info_processed = patch_info_commit[6:]
        ori_commit = patch_info_processed.split('..')[0]
        fix_commit = patch_info_processed.split('..')[1].split(' ')[0]
        filename_info[filename] = [ori_commit, fix_commit]
    return filename_info


def generate_file(filename_info, repo_path, ori_temp_path, fix_temp_path, CVE_id, proj_name):
    for filename, commits in filename_info.items():
        ori_commit = commits[0]
        fix_commit = commits[1]
        try:
            fix_cmd = 'cd %s && git show %s' % (repo_path, fix_commit)
            fix_output = subprocess.check_output(fix_cmd, shell=True, encoding='utf-8', errors='ignore')
            fix_filename = os.path.join(fix_temp_path, proj_name + '_' + CVE_id + '_' + '%s.c' % fix_commit)
            with open(fix_filename, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(fix_output.rstrip())
        except Exception as e:
            logging.info("fix commit cannot find in repo: %s" % str(e))
            continue
        try:
            ori_cmd = 'cd %s && git show %s' % (repo_path, ori_commit)
            ori_output = subprocess.check_output(ori_cmd, shell=True, encoding='utf-8', errors='ignore')
            ori_filename = os.path.join(ori_temp_path, proj_name + '_' + CVE_id+ '_' + '%s.c' % ori_commit)
            with open(ori_filename, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(ori_output.rstrip())
        except Exception as e:
            logging.info("ori commit cannot find in repo: %s" % str(e))
            continue


def generate_ori_fix_files_by_patchinfo(patch_file, git_repo, CVE_id, proj_name):
    ori_temp_path = os.path.join(config.temp_path, 'ori_files')
    fix_temp_path = os.path.join(config.temp_path, 'fix_files')
    patch_temp_path = os.path.join(config.temp_path, "patch_file")
    clean_generate_folder(ori_temp_path)
    clean_generate_folder(fix_temp_path)
    clean_generate_folder(patch_temp_path)
    time.sleep(1)
    try:
        filename_info = parse_diff(patch_file, patch_temp_path)
        logging.info(filename_info)
        if len(filename_info) == 0:
            logging.error("parse diff error")
            return [], []
        generate_file(filename_info, git_repo, ori_temp_path, fix_temp_path, CVE_id, proj_name)
    except Exception as e:
        logging.error(str(e))
    return ori_temp_path, fix_temp_path


def generate_code(location, filename, file_base_dir):
    filepath = os.path.join(file_base_dir, filename)
    start_line = int(location[0])
    end_line = int(location[1])
    return open(filepath).readlines()[start_line:end_line]


def main(patch_file, input_repo, CVE_id, library_id, proj_name):
    logging.info("generate ori fix files from patch infos")
    ori_file_path, fix_file_path = generate_ori_fix_files_by_patchinfo(patch_file, input_repo, cve, name)
    if len(ori_file_path) == 0 or len(fix_file_path) == 0:
        return 0
    ori_files = os.listdir(ori_file_path)
    fix_files = os.listdir(fix_file_path)
    if len(ori_files) == 0 or len(fix_files) == 0:
        return 0
    logging.info("using hmark to parse ori fix source files")
    logging.info("ori file ....")
    ori_document_list = generate_cli(ori_file_path)
    logging.info("fix file ....")
    fix_document_list = generate_cli(fix_file_path)
    if len(ori_document_list) == 0 or len(fix_document_list) == 0:
        return 0
    #save result to db
    logging.info("VUL FEATURES")
    for index in range(len(ori_document_list["function_hash"])):
        if ori_document_list["function_hash"][index] not in fix_document_list["function_hash"]:
            vul_document = {}
            vul_document["function_hash"] = ori_document_list["function_hash"][index]
            vul_document["function_name"] = ori_document_list["function_name"][index]
            vul_document["function_code"] = ori_document_list["function_code"][index]
            vul_document["CVE_infos"] = CVE_id
            vul_document["proj_name"] = proj_name
            vul_document["library_id"] = library_id
            if ori_collection.collection.find({"function_hash": vul_document["function_hash"],
                                               "CVE_infos": CVE_id}).count() != 0:
                logging.info("exist in DB..........................................")
            else:
                ori_collection.collection.insert_one(vul_document)
                logging.info("add to DB*********************************************")

    logging.info("PATCH FEATURES")
    for index in range(len(fix_document_list["function_hash"])):
        if fix_document_list["function_hash"][index] not in ori_document_list["function_hash"]:
            patch_document = {}
            patch_document["function_hash"] = fix_document_list["function_hash"][index]
            patch_document["function_name"] = fix_document_list["function_name"][index]
            patch_document["function_code"] = fix_document_list["function_code"][index]
            patch_document["CVE_infos"] = CVE_id
            patch_document["proj_name"] = proj_name
            patch_document["library_id"] = library_id
            if fix_collection.collection.find({"function_hash": patch_document["function_hash"],
                                               "CVE_infos": CVE_id}).count() != 0:
                logging.info("exist in DB..........................................")
            else:
                fix_collection.collection.insert_one(patch_document)
                logging.info("add to DB*********************************************")


ori_collection = mongodb.mongodb_synic(host=config.db_host,
                                           port=config.db_port,
                                           db_name=config.db_name,
                                           collection_name=config.db_vul_collection,
                                           user=config.db_user,
                                           password=config.db_password,
                                           auth=config.db_auth)
fix_collection = mongodb.mongodb_synic(host=config.db_host,
                                           port=config.db_port,
                                           db_name=config.db_name,
                                           collection_name=config.db_patch_collection,
                                           user=config.db_user,
                                           password=config.db_password,
                                           auth=config.db_auth)


if __name__ == '__main__':
    with open('cve_repo_patch.csv') as f:
        csvs = csv.reader(f)
        for i, line in enumerate(csvs):
            if i == 0:
                continue
            if line[-1] and line[-2] and line[-3]:
                library_id = line[1]
                name = line[2]
                cve = line[5]
                path = line[7]
                patch = line[8]
                main(patch, path, cve, library_id, name)
        
	         

def old_entry():
    CVE_library_id_dict = {}
    with open(config.CVE_id_library_id, 'r') as csvfile:
        reader = csv.reader(csvfile)
        cnt = 0
        for row in reader:
            cnt += 1
            if cnt > 1 and len(row[8]) > 0:
                CVE_library_id_dict[row[5]] = row[1]
    patch_folder = config.input_patch
    repo_folder = config.input_git_repo
    patch_files = []
    ids = os.listdir(config.input_git_repo)
    patch_files = []
    with open(config.decode_error, 'r') as decode_read:
        reader = csv.reader(decode_read)
        cnt = 0
        for row in reader:
            cnt += 1
            if cnt > 1:
                patchfile = os.path.join(patch_folder, row[0])
                if os.path.exists(patchfile):
                    patch_files.append(patchfile)
    logging.info(patch_files)

    for file in patch_files:
        library_id = file.split('/')[-2]
        input_repo = os.path.join(repo_folder, library_id)
        proj_name = file.split('/')[-1].split('_CVE')[0]
        CVE_id = file.split('/')[-1].split(proj_name)[-1].split('_')[1]
        if os.path.exists(input_repo) and CVE_id in CVE_library_id_dict.keys() \
                and CVE_id not in ori_collection.collection.distinct("CVE_infos"):
            logging.info("[%d/%d] %s | %s | %s | %s" % (patch_files.index(file), len(patch_files), CVE_id, library_id, proj_name, file))
            main(file, input_repo, CVE_id, library_id, proj_name)
        else:
            continue
