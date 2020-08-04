import config
import pymongo
import pandas as pd
import datetime
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session, join
from sqlalchemy import create_engine
if __name__ == '__main__':
    Base = automap_base()
    c = pymongo.MongoClient(host=config.db_host,port=config.db_port)
    time_col = c[config.db_name]['update_meta']
    doc = time_col.find_one({'key':'last_timestamp'})
    if not doc:
        timestamp = datetime.datetime(2020, 5, 30)
        time_col.insert({'key': 'last_timestamp',
                         'timestamp': timestamp})
    else:
        timestamp = doc['timestamp']


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
    print(Base.metadata.tables.keys())

    # Mapped classes are now created with names by default
    # matching that of the table name.
    l = Base.classes.scantist_library
    lvi = Base.classes.scantist_libraryversionissue
    sv = Base.classes['1_scantist_vulnerability']
    svl = Base.classes['1_scantist_vulnerability_library']
    lru = Base.classes['2_scantist_libraryrepourl']
    rl = Base.classes['2_scantist_repolist']
    si = Base.classes.scantist_securityissue
    data = pd.DataFrame()
    res_obj = (session
                  .query(l.id, l.name, l.vendor, sv.id, sv.public_id)
                  .filter(sv.id == svl.vulnerability_id)
                  .filter(svl.library_id == l.id)
                  .filter(l.is_valid == True)
                  .filter(svl.is_valid == True)
                  .filter(sv.is_valid == True)
                  .filter(sv.created > timestamp)
                  .filter(l.platform == 'NOT_SPECIFIED')
                  .filter((l.language != 'Ruby') | (l.language.is_(None)))
                  .order_by(l.id.asc())
                  .distinct())
    res_list = [p for p in res_obj]
    data['library_id'] = [seq[0] for seq in res_list]
    data['name'] = [seq[1] for seq in res_list]
    data['vendor'] = [seq[2] for seq in res_list]
    data['vulnerability_id'] = [seq[3] for seq in res_list]
    data['public_id'] = [seq[4] for seq in res_list]
    repo_url_list = []
    local_path_list = []
    for i in range(len(data)):
        if i > 0 and data['library_id'][i] == data['library_id'][i-1]:
            repo_url_list.append(repo_url_list[-1])
            local_path_list.append(local_path_list[-1])
        else:
            repo_index = (session
                    .query(rl.repo_url, rl.local_path)
                    .filter(rl.id == lru.repolist_id)
                    .filter(lru.library_id == int(data['library_id'][i]))
                    .filter(lru.is_valid == True)
                    .distinct())
            repo_index_list = [p for p in repo_index]
            if len(repo_index_list) > 0:
                repo_url_list.append(repo_index_list[0][0])
                local_path_list.append(repo_index_list[0][1])
            else:
                repo_url_list.append('null')
                local_path_list.append('null')
    data['repo_url'] = repo_url_list
    data['local_path'] = local_path_list
    data.to_csv('lib_cve_path.csv')


