#!/usr/bin/python
# coding:utf-8

from kafka import KafkaConsumer
import json
import requests
import os
import yara
from multiprocessing import Pool,Value
import datetime

def mycallback(data):
  print data
  return yara.CALLBACK_CONTINUE

# 获取目录内的yara规则文件
# 将yara规则编译
def getRules(path_name):
    filepath = {}
    g = os.walk(path_name)
    for path, d, filelist in g:
        for filename in filelist:
            rupath = os.path.join(path, filename)
            filepath[filename] = rupath
    yararule = yara.compile(filepaths=filepath)  # 编译
    return yararule

counter = Value('i', 0)
rulepath = "/home/yara/rule_yara/"  # yara规则目录
yararule = getRules(rulepath)
def kafka_run():
    consumer = KafkaConsumer('PREPROCESS_RESULT_QUEUE',group_id='group_kafka',bootstrap_servers=['10.255.65.3:9092'],)
    for message in consumer:
        try:
            data = json.loads(message.value)
            url = data[u'data'][u'download_url']
            file_name = url.split('/')[-1]
            counter.value += 1
            r = requests.get(url)
        except Exception, e:
            continue
        if r.status_code != 200:
            continue
        matches = yararule.match(data=r.content, callback=mycallback, which_callbacks=yara.CALLBACK_MATCHES,timeout=60)
        if len(matches) > 0:
            today = datetime.date.today()
            list = []
            for ele in matches:
                if ele.tags == []:
                    list.append(str(ele))
                else:
                    yara_data = "|".join(ele.tags)
                    list.append(str(ele) + "|" + yara_data)
            with open("/home/yara/logs/log%s"%today,"ab") as data:
                print >> data,file_name,list

if __name__ == '__main__':
    kafka_run()
    # p = Pool()
    # for i in range(20):
    #     p.apply_async(kafka_run)
    # p.close()
    # p.join()