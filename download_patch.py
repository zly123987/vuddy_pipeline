#encoding:utf-8
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session, join
from sqlalchemy import create_engine
import csv
import pandas as pd
import numpy as np
import fuzzywuzzy
from fuzzywuzzy import fuzz
from sqlalchemy import func
import json
from math import isnan
import os
Base = automap_base()

user = pwd = 'cvetriage_ro'
host = 'cvetriage.cqy3hiulpjht.ap-southeast-1.rds.amazonaws.com'
db = 'cvetriage'

# host = 'cvetriage.cqy3hiulpjht.ap-southeast-1.rds.amazonaws.com'
# db = 'cvetriage'
# user = 'codeanalysis'
# pwd = '2drTy7lk$'

# Create engine, session
engine = create_engine(f'postgresql+psycopg2://{user}:{pwd}@{host}:5432/{db}',client_encoding='utf-8')
session = Session(engine)


# Reflect the tables
Base.prepare(engine, reflect=True)
# Test connection
print('Test Connection...')

# Mapped classes are now created with names by default
# matching that of the table name.
l = Base.classes.scantist_library
lvi = Base.classes.scantist_libraryversionissue
sv = Base.classes['1_scantist_vulnerability']
sp = Base.classes['1_scantist_patch']
sps = Base.classes['1_scantist_patchsource']
# vulner_library= Base.classes['1_scantist_vulnerability_library']
si = Base.classes.scantist_securityissue
data = pd.read_csv('lib_cve_path.csv')
patch = []
for i in range(len(data)):
    file_path_name = ''
    id_obj = (session
              .query(sps.patch_hash)
              .filter(sps.vulnerability_id == int(data['vulnerability_id'][i]))
              .filter(sps.confidence == int(0))
              .filter(sps.patch_hash != None)
              .distinct())
    id_list = [p for p in id_obj]
    hash_list = []
    if len(id_list) > 0:
        for s in id_list:
            if s[0] not in hash_list:
                hash_list.append(s[0])
        j = 0
        for hash in hash_list:
            patch_obj = (session
                      .query(sp.raw)
                      .filter(sp.vulnerability_id == int(data['vulnerability_id'][i]))
                      .filter(sp.patch_hash == hash)
                      .filter(sp.is_valid == True)
                      .distinct())
            patch_obj_list = [p for p in patch_obj]
            if len(patch_obj_list)>0:
                file_path = "patch/" + str(data["library_id"][i]) + '/' + str(data["name"][i])
                if not os.path.exists(file_path):
                    os.makedirs(file_path)
                file_name = data['public_id'][i] + '____' + str(j)
                file_path_name = file_path + '/' + file_name
                try:
                    f = open(file_path_name, 'wb')
                    f.write(patch_obj_list[0][0])
                    f.close()
                    j = j + 1
                    patch[i]
                except Exception as e:
                    print(data[i], str(e))
    else:
        patch_table_obj = (session
                          .query(sp.raw)
                          .filter(sp.vulnerability_id == int(data['vulnerability_id'][i]))
                          .filter(sp.is_valid == True)
                          .distinct())
        patch_table_list = [p for p in patch_table_obj]
        if len(patch_table_list)>0 and len(patch_table_list) < 10:
            file_path = "patch/" + str(data["library_id"][i]) + '/' + str(data["name"][i])
            if not os.path.exists(file_path):
                os.makedirs(file_path)
            for j in range(len(patch_table_list)):
                file_name = data['public_id'][i] + '____' + str(j)
                file_path_name = file_path+'/'+file_name
                try:
                    f = open(file_path_name, 'wb')
                    f.write(patch_table_list[j][0])
                    f.close()
                except Exception as e:
                    print(data[i], str(e))
    patch.append(file_path_name)
if len(patch) == len(data):
    data['patch'] = patch
    data.to_csv('cve_repo_patch.csv',index = False, header=True)
    print('Added patch paths to csv')
else:
    print('lengths do not match')
    exit(1)
