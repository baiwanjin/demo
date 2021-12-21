import configparser
import pickle
from typing import Optional

import select
import paramiko
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from requests.auth import HTTPDigestAuth
from xml.etree import ElementTree
import threading
import time
import re
import requests
import json
import eventlet
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from urllib.parse import quote
import base64
from Crypto.Cipher import AES
from multiprocessing import Process
import nacos
import os
import socket
import mmap
import contextlib

######################替代部分
import logging.handlers
import datetime

logger = logging.getLogger('updatelog')
logger.setLevel(logging.DEBUG)
rf_handler = logging.handlers.TimedRotatingFileHandler('logs/upgrade_cvm.log', when='midnight', interval=1, backupCount=7, atTime=datetime.time(0, 0, 0, 0))
rf_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
f_handler = logging.FileHandler('logs/error.log')
f_handler.setLevel(logging.ERROR)
f_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s[:%(lineno)d] - %(message)s"))
logger.addHandler(rf_handler)
logger.addHandler(f_handler)
##########################

########################配置文件
CONFIG_NAME_MAPPER = {
    'development': 'py_config_Development.json',
    'production': 'py_config_Production.json',
    'staging': 'py_config_Staging.json',
}
NACOS_CONFIG_NAME_MAPPER = {
    'development': 'Nacos_config_Development.json',
    'production': 'Nacos_config_Production.json',
    'staging': 'Nacos_config_Staging.json',
}
config_name = os.environ.get('ENV_CONFIG', 'Staging').lower()  # 设置环境变量为dev
PY_CONFIG = config_name.capitalize()
#读取配置文件
class GlobalConf:

    def get_Nacos_config(self):
        # 读取配置文件，
        real_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), NACOS_CONFIG_NAME_MAPPER.get(config_name))
        with open(real_path, 'r', encoding='utf8')as data:
            return json.load(data)
    def get_config(self):
        # 读取配置文件，
        real_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONFIG_NAME_MAPPER.get(config_name))
        with open(real_path, 'r', encoding='utf8')as data:
            return json.load(data)
#加密解密算法
class ENCRYPT:
    def pkcs7padding(self,text):
        bs = AES.block_size
        length = len(text)
        bytes_length = len(bytes(text, encoding="utf-8"))
        padding_size = length if (bytes_length == length) else bytes_length
        padding = bs - padding_size % bs
        padding_text = chr(padding) * padding
        return text + padding_text

    def pkcs7unpadding(self,text):
        try:
            length = len(text)
            unpadding = ord(text[length - 1])
            return text[0 : length - unpadding]
        except Exception as e:
            pass

    def aes_encode(self,key, content):
        key_bytes = bytes(key, encoding="utf-8")
        iv = key_bytes
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        # 处理明文
        content_padding = ENCRYPT().pkcs7padding(content)
        # 加密
        aes_encode_bytes = cipher.encrypt(bytes(content_padding, encoding="utf-8"))
        # 重新编码
        result = str(base64.b64encode(aes_encode_bytes), encoding="utf-8")
        return result

    def aes_decode(self,key, content):
        try:
            key_bytes = bytes(key, encoding="utf-8")
            iv = key_bytes
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            # base64解码
            aes_encode_bytes = base64.b64decode(content)
            # 解密
            aes_decode_bytes = cipher.decrypt(aes_encode_bytes)
            # 重新编码
            result = str(aes_decode_bytes, encoding="utf-8")
            # 去除填充内容
            result = ENCRYPT().pkcs7unpadding(result)
        except Exception as e:
            pass
        if result == None:
            return ""
        else:
            return result

#所有的配置信息


key = "acsdkiuygw865dab"
ICMP_ECHO_REQUEST = 8 # Platform specific
DEFAULT_TIMEOUT = 0.1
DEFAULT_COUNT = 4
NACOS_CONFIG = GlobalConf().get_Nacos_config()
SERVER_ADDRESSES = NACOS_CONFIG["NacosServer"]
NAMESPACE = ENCRYPT().aes_decode(key, NACOS_CONFIG["NAMESPACE"])
NacosUser = ENCRYPT().aes_decode(key, NACOS_CONFIG["NacosUser"])
NacosPasswd = ENCRYPT().aes_decode(key, NACOS_CONFIG["NacosPasswd"])
NacosServer = NACOS_CONFIG["NacosServer"]
NacosServiceName = NACOS_CONFIG["NacosServiceName"]
NacosPort = NACOS_CONFIG["NacosPort"]
NAMESPACE = NACOS_CONFIG["NAMESPACE"]
try:
    client = nacos.NacosClient(SERVER_ADDRESSES, namespace=NAMESPACE, username=NacosUser, password=NacosPasswd)
    CONFIG = GlobalConf().get_config()
    if client.get_config("py_config_%s.json" % (PY_CONFIG), PY_CONFIG, 60) == None:
        client.publish_config("py_config_%s.json" % (PY_CONFIG), PY_CONFIG, json.dumps(CONFIG), timeout=60,
                              config_type="json")
    content = client.get_config("py_config_%s.json" % (PY_CONFIG), PY_CONFIG, 60)
    CONFIG = json.loads(content)
    # 数据文件服务器
    data_host_ip = CONFIG["data_host_ip"]
    # 数据文件服务器密码
    data_host_passwd = ENCRYPT().aes_decode(key, CONFIG["data_host_passwd"])
    VDI_admin = ENCRYPT().aes_decode(key, CONFIG["VDI_admin"])
    VDI_admin_passwd = ENCRYPT().aes_decode(key, CONFIG["VDI_admin_passwd"])
    # cvk根目录最小值(G)
    host_Avail_min = CONFIG["host_Avail_min"]
    # winC盘最小空间(G)
    win_Avail_min = CONFIG["win_Avail_min"]
    # Linux根目录(G)
    linux_Avail_min = CONFIG["linux_Avail_min"]
    # 回调接口参数
    AppKey = ENCRYPT().aes_decode(key, CONFIG["AppKey"])
    UserId = ENCRYPT().aes_decode(key, CONFIG["UserId"])
    UserName = ENCRYPT().aes_decode(key, CONFIG["UserName"])
except:
    CONFIG = GlobalConf().get_config()
    # 数据文件服务器
    data_host_ip = CONFIG["data_host_ip"]
    # 数据文件服务器密码
    data_host_passwd = ENCRYPT().aes_decode(key, CONFIG["data_host_passwd"])
    VDI_admin = ENCRYPT().aes_decode(key, CONFIG["VDI_admin"])
    VDI_admin_passwd = ENCRYPT().aes_decode(key, CONFIG["VDI_admin_passwd"])
    # cvk根目录最小值(G)
    host_Avail_min = CONFIG["host_Avail_min"]
    # winC盘最小空间(G)
    win_Avail_min = CONFIG["win_Avail_min"]
    # Linux根目录(G)
    linux_Avail_min = CONFIG["linux_Avail_min"]
    # 回调接口参数
    AppKey = ENCRYPT().aes_decode(key, CONFIG["AppKey"])
    UserId = ENCRYPT().aes_decode(key, CONFIG["UserId"])
    UserName = ENCRYPT().aes_decode(key, CONFIG["UserName"])


# #ping方法，检测服务器是否启动，只用于CVK检测
# class Pinger(object):
#     """ Pings to a host -- the Pythonic way"""
#
#     def __init__(self, target_host, count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT):
#         self.target_host = target_host
#         self.count = count
#         self.timeout = timeout
#
#
#     def do_checksum(self, source_string):
#         """  Verify the packet integritity """
#         sum = 0
#         max_count = (len(source_string)/2)*2
#         count = 0
#         while count < max_count:
#
#             val = source_string[count + 1]*256 + source_string[count]
#             sum = sum + val
#             sum = sum & 0xffffffff
#             count = count + 2
#
#         if max_count<len(source_string):
#             sum = sum + ord(source_string[len(source_string) - 1])
#             sum = sum & 0xffffffff
#
#         sum = (sum >> 16)  +  (sum & 0xffff)
#         sum = sum + (sum >> 16)
#         answer = ~sum
#         answer = answer & 0xffff
#         answer = answer >> 8 | (answer << 8 & 0xff00)
#         return answer
#
#     def receive_pong(self, sock, ID, timeout):
#         """
#         Receive ping from the socket.
#         """
#         time_remaining = timeout
#         while True:
#             start_time = time.time()
#             time_spent = (time.time() - start_time)
#             time_received = time.time()
#             recv_packet, addr = sock.recvfrom(1024)
#             icmp_header = recv_packet[20:28]
#             type, code, checksum, packet_ID, sequence = struct.unpack(
#        "bbHHh", icmp_header
#     )
#             if packet_ID == ID:
#                 bytes_In_double = struct.calcsize("d")
#                 time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
#                 return time_received - time_sent
#
#             time_remaining = time_remaining - time_spent
#             if time_remaining <= 0:
#                 return
#
#
#     def send_ping(self, sock,  ID):
#         """
#         Send ping to the target host
#         """
#         target_addr  =  socket.gethostbyname(self.target_host)
#
#         my_checksum = 0
#
#         # Create a dummy heder with a 0 checksum.
#         header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
#         bytes_In_double = struct.calcsize("d")
#         data = (192 - bytes_In_double) * "Q"
#         data = struct.pack("d", time.time()) + bytes(data.encode('utf-8'))
#
#         # Get the checksum on the data and the dummy header.
#         my_checksum = self.do_checksum(header + data)
#         header = struct.pack(
#       "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
#     )
#         packet = header + data
#         sock.sendto(packet, (target_addr, 1))
#
#
#     def ping_once(self):
#         """
#         Returns the delay (in seconds) or none on timeout.
#         """
#         icmp = socket.getprotobyname("icmp")
#         try:
#             sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
#         except socket.error as e:
#             if e.errno == 1:
#                 # Not superuser, so operation not permitted
#                 e.msg +=  "ICMP messages can only be sent from root user processes"
#                 raise socket.error(e.msg)
#         except Exception as e:
#             print("Exception: %s" %(e))
#
#         my_ID = os.getpid() & 0xFFFF
#
#         self.send_ping(sock, my_ID)
#         delay = self.receive_pong(sock, my_ID, self.timeout)
#         sock.close()
#         return delay
#
#
#     def ping(self):
#         """
#         Run the ping process
#         """
#         for i in range(self.count):
#             print ("Ping to %s..." % self.target_host,)
#             try:
#                 delay  =  self.ping_once()
#             except socket.gaierror as e:
#                 print ("Ping failed. (socket error: '%s')" % e[1])
#                 break
#
#             if delay  ==  None:
#                 print ("Ping failed. (timeout within %ssec.)" % self.timeout)
#             else:
#                 delay = delay * 1000
#                 print("Get pong in %0.4fms" % delay)

# terrace属性
class TERRACE:
    terrace_name = ""
    vip = ""
    system_version = ""
    terrace_version = ""
    terrace_type = ""
    admin_user = ""
    admin_password = ""
    root_password = ""
    ssh_port = 22
    admin_status = 0
    task_status = 0

    def __init__(
        self,
        terrace_name,
        vip,
        system_version,
        terrace_version,
        terrace_type,
        admin_user,
        admin_password,
        root_password,
        ssh_port,
        admin_status,
        task_status,
    ):
        self.terrace_name = terrace_name
        self.vip = vip
        self.system_version = system_version
        self.terrace_version = terrace_version
        self.terrace_type = terrace_type
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.root_password = root_password
        self.ssh_port = ssh_port
        self.admin_status = admin_status
        self.task_status = task_status

# 主机
class HOSTS:
    id = 0
    name = ""
    status = 0

    def __init__(self, id, name, status):
        self.id = id
        self.name = name
        self.status = status

    # 获取主机列表及属性
    def createHosts(args):
        for i in range(len(args)):
            if i == 0 or i % 3 == 0:
                # 创建主机对象
                args[i + 1] = HOSTS(int(args[i]), args[i + 1], int(args[i + 2]))
        return args[1::3]

# Terminal与主机交互
class TERMINAL:
    # 检测ssh是否正常，即检测ssh的22端口是否正常
    def check_ssh(self,ip, port):
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(1)
        try:
            sk.connect((ip, port))
            logger.debug("主机:%sSSH登录校验通过"%(ip))
            return True
        except Exception:
            logger.error("主机:%sSSH登录校验异常"%(ip))
            return False
        finally:
            sk.close()
        logger.error("主机:%sSSH登录校验失败"%(ip))
        return False
    # 检测密码登录是否正确
    def check_passwd(self,ip, port, passwd):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=ip, port=port, username="root", password=passwd)
            client.close()
            logger.debug("通过密码:%s登录主机:%s成功"%(passwd,ip))
            return True
        except Exception:
            logger.error("通过密码:%s登录主机:%异常" % (passwd, ip))
            return False
        logger.error("通过密码:%s登录主机:%s失败" % (passwd, ip))
        return False

    # 登录主机执行一个指定并返回结果
    def run_cmd(self,ip, port, passwd, cmd):
        # 实例化SSHClient
        client = paramiko.SSHClient()
        # 自动添加策略，保存服务器的主机名和密钥信息，如果不添加，那么不再本地know_hosts文件中记录的主机将无法连接
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # 连接SSH服务端，以用户名和密码进行认证
        client.connect(hostname=ip, port=port, username="root", password=passwd)
        # 打开一个Channel并执行命令
        logger.debug("开始执行命令(%s)"%(cmd))
        stdin, stdout, stderr = client.exec_command(cmd)
        # 打印执行结果
        display = stdout.read().decode("utf-8")
        # 关闭SSHClient
        client.close()
        return display

#VDI和CAS共用属性
class VDIorCAS:
    header = {
        "Content-Type": "application/json",
        "AppKey": AppKey,
        "UserId": UserId,
        "UserName": UserName,
        "UserRoles": "['Admin']",

    }
    class URL:
        GET_CAS_VERSION = "http://%s:8083/vdi/rest/workspace/about/releaseVersion"
        VDI_LOGIN = "http://%s:8083"
        CAS_LOGIN = "http://%s:8080"
        NACOS_login_URL = "%s/nacos/v1/auth/login?username=%s&password=%s"
        NACOS_register_URL = "%s/nacos/v1/ns/instance?accessToken=%s&ip=%s&port=%s&namespaceId=public&serviceName="+NacosServiceName+"&enabled=true&namespaceId=&metadata=%%7B%%22preserved.register.source%%22%%3A %%22Python%%22%%7D"
        Send_Health_Beat_URL = "%s/nacos/v1/ns/instance/beat?accessToken=%s&serviceName="+NacosServiceName+"&beat=%s"
        NACOS_NS_MESSAGE="%s/nacos/v1/ns/instance/list?accessToken=%s&serviceName=CloudOps"
        CALLBACK_FUN="http://%s:%s/api/cloudops/upgrade/task/status/update"
        CALLBACK_CHECK_FUN="http://%s:%s/api/cloudops/upgrade/detection/progress/update"
    class CMD:
        SCP_GATEWAY_FILE="scp -r %s:%s /root/"
        SCP_FILE = "scp -r %s:%s /root/ && md5sum /root/%s |awk '{print $1}'"
        GET_Master_IP = "cat /etc/hosts|grep `hostname`|awk '{print $1}'"
        GET_KEY = "cat ~/.ssh/id_rsa.pub"
        ECHO_AUTHORIZED = "echo '%s' >> /root/.ssh/authorized_keys"
        GET_CAS_VERSION = "head -1 /etc/cas_cvm-version|awk '{print $2 $3}'"
        GET_LOG_FILE="sed -n '$p' /var/log/upgrade/%s"
        GET_LOG_NAME="ls -l /var/log/upgrade/|grep `date +%Y%m%d`|grep cvk-upgrade_|awk '{print $9}'|tail -1"
        GET_DATE="date +%Y%m%d%H%M%S"
        TAR_UPDATEFILE="tar -xvf %s|awk 'NR==1'"
        CVM_CHECK="cd %s && echo \'#!/usr/bin/expect \nset timeout 7200 \nspawn ./upgrade.sh precheck \nexpect \"*CVM|CVK*\" {\nsend \"CVM\\n\"\n}\ninteract\' > check_cvm.sh && chmod +x check_cvm.sh && ./check_cvm.sh"
        # CVK_CHECK = "cd %s && echo \'#!/usr/bin/expect \nset timeout 7200 \nspawn ./upgrade.sh precheck \nexpect \"*CVM|CVK*\" {\nsend \"CVK\\n\"\n}\ninteract\' > check_cvm.sh && chmod +x check_cvm.sh && ./check_cvm.sh"
        TAR_COPY="cd %s && echo \'#!/usr/bin/expect \nset timeout 7200 \nspawn  ./upgrade.sh copy \nexpect \"*yes/no*\" {\nsend \"yes\\n\"\n}\ninteract\' > copy.sh && chmod +x copy.sh && ./copy.sh"
        RM_UPDATEFILE="rm -rf $PWD/%s"

    def get_cvk_log(self,VIP,host_time,Master_IP, port, passwd,type,taskid):

        try:
            time.sleep(20)
            log_lock = "这是一把锁"
            log_name=TERMINAL().run_cmd(Master_IP, port, passwd, VDIorCAS().CMD().GET_LOG_NAME).rstrip("\n")
            if log_name=="" or int(host_time) > int(log_name.split('_')[-1].split('.log')[0]):
                VDIorCAS().get_cvk_log(VIP,host_time,Master_IP, port, passwd, type, taskid)
            eventlet.monkey_patch()
            with eventlet.Timeout(800, False):
                while True:
                    log = TERMINAL().run_cmd(Master_IP, port, passwd, VDIorCAS().CMD().GET_LOG_FILE % (log_name))
                    log = re.sub(r'-.{11}', r'', log)
                    logger.debug(log)
                    VDIorCAS().callback_function(VIP, 200, type, taskid, msg=log)
                    if log == log_lock:
                        if "Log time:" in log:
                            return True
                        if log =="":
                            return True
                    log_lock = log
                    time.sleep(2)

        except:
            with eventlet.Timeout(800, False):
                VDIorCAS().get_cvk_log(VIP,host_time,Master_IP, port, passwd,type,taskid)


    def update_detection_callback_check(self,Master_IP,Upgrade_FileNams,result,statusCode,msg,vip,platformType,detection_Progress ):
        data = {
            "result": result,
            "statusCode": statusCode,
            "msg": msg,
            "vip":vip,
            "platformType": platformType,
            "data": {
                "Detection_Progress": detection_Progress,
                "Master_IP": Master_IP,
                "Upgrade_FileNams": Upgrade_FileNams
            }
        }
        Token = VDIorCAS().get_nacos_token(NacosServer, NacosUser, NacosPasswd)
        Nacos_Message = VDIorCAS().get_nacos_message(NacosServer, Token).json()["hosts"][0]
        r=requests.put(VDIorCAS().URL.CALLBACK_CHECK_FUN%(Nacos_Message["ip"],Nacos_Message["port"]),data=json.dumps(data),
                           headers=VDIorCAS().header)
        return r


    def Tar_Updatefile_To_Check(self,Master_IP,ssh_port,root_passwd,Upgrade_file):
        update_file=TERMINAL().run_cmd(Master_IP,ssh_port,root_passwd,
            VDIorCAS().CMD.TAR_UPDATEFILE % (Upgrade_file),
        ).rstrip("\n")
        checl_log=TERMINAL().run_cmd(Master_IP, ssh_port, root_passwd,
                           VDIorCAS().CMD.CVM_CHECK % (update_file),
                           )
        if "[ERROR] Pre-check has not pass! The ERROR must be resolved!" in checl_log:
            VDIorCAS().callback_function(Master_IP, 1000, "VDI", 0, finished=True, msg=checl_log)
            print("执行./upgrade.sh precheck 出现[ERROR]")
            return False
        # checl_CVK_log = TERMINAL().run_cmd(Master_IP, ssh_port, root_passwd,
        #                                VDIorCAS().CMD.CVK_CHECK % (update_file),
        #                                )
        # if "[ERROR] Pre-check has not pass! The ERROR must be resolved!" in checl_CVK_log:
        #     VDIorCAS().callback_function(Master_IP, 1000, "VDI", 0, finished=True,
        #                                  msg=checl_CVK_log)
        #     print("执行./upgrade.sh precheck 出现[ERROR]")
        #     return False
        TERMINAL().run_cmd(Master_IP, ssh_port, root_passwd,
                           VDIorCAS().CMD.TAR_COPY % (update_file),
                           )
        TERMINAL().run_cmd(Master_IP, ssh_port, root_passwd,
                           VDIorCAS().CMD.RM_UPDATEFILE % (update_file),
                           )
        return True


    def update_detection(
        self,
        vip,
        ssh_port,
        update_specification_list,
        system_version,
        admin_user,
        admin_password,
        root_passwd,
        admin_status,
        terrace_type="CAS",
        terrace_version="",

    ):

        # 验证主机任务状态
        VDIorCAS().callback_function(vip,200, terrace_type, 0, msg="开始平台检测")
        logger.debug("开始平台检测")
        VDIorCAS().update_detection_callback_check("", "", True, 200, "开始平台检测", vip,
                                                   terrace_type, 0)
        # 验证免密可登录性
        if not TERMINAL().check_passwd(vip, ssh_port, root_passwd):
            VDIorCAS().callback_function(vip,1007, terrace_type, 0)
            VDIorCAS().update_detection_callback_check("", "", False, 1000,
                                                       "验证免密可登录性", vip, "VDI", 0)
            return False
        VDIorCAS().callback_function(vip,200, terrace_type, 0, msg="设置免密登录成功")
        logger.debug("主机:%s设置免密登录数据服务器成功"%(vip))
        VDIorCAS().callback_function(vip,200, terrace_type, 0, msg="CVM主机状态正常")
        VDIorCAS().update_detection_callback_check("", "", True, 200, "CVM主机状态正常", vip,
                                                   terrace_type, 5)
        logger.debug("CVM:%s主机状态正常"%(vip))
        try:
            if terrace_type == "CAS":
                # CAS集群检测
                print("ss")
                Master_IP = VDIorCAS().get_maset_key(vip, ssh_port, root_passwd)
                VDIorCAS().callback_function(vip, 200, terrace_type, 0, msg="获取到管理节点IP" + Master_IP)
                logger.debug("%s:%s获取到管理节点IP:%s" % (terrace_type,vip, Master_IP))
                VDIorCAS().update_detection_callback_check(Master_IP, "", True, 200,
                                                           "%s:%s获取到管理节点IP:%s" % (terrace_type,vip, Master_IP), vip,
                                                           terrace_type, 30)

                VDIorCAS().callback_function(vip, 200, terrace_type, 0, msg="正在上传文件中，请稍后。。。。。。。")
                for update_specification in update_specification_list:
                    files = VDIorCAS().MD5SUN(
                        update_specification, Master_IP, ssh_port, root_passwd
                    )
                    if files[0]:
                        VDIorCAS().callback_function(vip, 200, terrace_type, 0, msg="文件上传成功，Md5检验通过")
                        logger.debug("%s:%s所有文件上传成功，Md5检验通过" % (terrace_type,vip))
                        Upgrade_FileNams = files[1]
                    else:
                        logger.error("%s:%s有文件上传失败或Md5检验未通过，请重试" % (terrace_type,vip))
                        return False
                VDIorCAS().callback_function(vip, 200, terrace_type, 0, msg="环境检测完成，开始定制升级任务")
                CAS().CAS_detection(vip, admin_user, admin_password,root_passwd)

                # 制定定时任务
                VDIorCAS().update_detection_callback_check(Master_IP, Upgrade_FileNams, True, 200, "环境检测完成，开始定制升级任务",
                                                         vip, terrace_type, 100)
                return {"Master_IP": Master_IP, "Upgrade_FileNams": Upgrade_FileNams}
            elif terrace_type == "VDI":

                vdi_login = VDI().VDI_login(
                    vip, admin_user, admin_password, terrace_version
                )

                try:
                    if vdi_login[0] == False:
                        VDIorCAS().callback_function(vip,1004, "VDI", 0)
                        logger.error("VDI:%s管理平台账号密码登录失败"%(vip))
                        VDIorCAS().update_detection_callback_check("", "", False, 1000,
                                                                   "VDI:%s管理平台账号密码登录失败"%(vip), vip, "VDI", 0)
                        return False
                    session = vdi_login[2]
                    header = vdi_login[1]
                    VDIorCAS().callback_function(vip,200, "VDI", 0, msg="平台管理账号检测通过")
                    logger.debug("VDI:%s管理平台账号密码登录通过" % (vip))
                    VDIorCAS().update_detection_callback_check("", "", True, 200, "VDI:%s管理平台账号密码登录通过" % (vip), vip,
                                                               "VDI", 10)
                except Exception as e:
                    VDIorCAS().callback_function(vip,1008, "VDI", 0)
                    logger.error("VDI:%s管理平台账号密码登录异常" % (vip))
                    VDIorCAS().update_detection_callback_check("", "", False, 1000,
                                                               "VDI:%s管理平台账号密码登录异常" % (vip), vip, "VDI",10)
                    return False
                # 检测存储异常不重启从E1007开始
                try:
                    if VDI().vdi_storage_reset(vip, session):
                        VDIorCAS().callback_function(vip,1009, "VDI", 0)
                        logger.error("VDI:%s检测存储异常设为不重启不通过，请前往设置"%(vip))
                        VDIorCAS().update_detection_callback_check("", "", False, 1000,
                                                                   "VDI:%s检测存储异常设为不重启不通过，请前往设置"%(vip), vip, "VDI", 10)

                        return False
                except Exception as e:
                    VDIorCAS().callback_function(vip,1010, "VDI", 0)
                    logger.error("VDI:%s检测存储异常设为不重启异常" % (vip))
                    VDIorCAS().update_detection_callback_check("", "", False, 1000,
                                                               "VDI:%s检测存储异常设为不重启异常" % (vip), vip, "VDI", 10)
                    return False
                VDIorCAS().callback_function(vip,200, "VDI", 0, msg="检测存储异常设为不重启通过")
                logger.debug("VDI:%s检测存储异常设为不重启通过" % (vip))
                VDIorCAS().update_detection_callback_check("", "", True, 200, "VDI:%s检测存储异常设为不重启通过" % (vip), vip,
                                                           "VDI", 20)
                # 获取主节点并上传检测文件MD5
                Master_IP = VDIorCAS().get_maset_key(vip, ssh_port, root_passwd)

                VDIorCAS().callback_function(vip, 200, "VDI", 0, msg="获取到管理节点IP" + Master_IP)
                logger.debug("VDI:%s获取到管理节点IP:%s" % (vip, Master_IP))
                VDIorCAS().update_detection_callback_check(Master_IP, "", True, 200,
                                                           "VDI:%s获取到管理节点IP:%s" % (vip, Master_IP), vip,
                                                           "VDI", 30)
                # 查询集群
                try:
                    logger.debug("VDI:%s正在查询集群信息" % (vip))
                    cluster_ID_list = VDI().get_cluster_message(vip, VDI_admin, VDI_admin_passwd)
                    print(cluster_ID_list)
                except Exception as e:
                    logger.error(e)
                    logger.error("VDI:%s集群信息查询异常" % (vip))
                    VDIorCAS().callback_function(vip, 1000, "VDI",0, finished=True, msg="集群信息查询异常")
                    VDIorCAS().update_detection_callback_check(Master_IP, "", False, 1000,
                                                               "集群信息查询异常", vip, "VDI", 30)
                    return False
                # 获取主机列表
                try:
                    logger.debug("VDI:%s获取主机列表" % (vip))
                    host_massage_list = VDI().get_host_message(vip, VDI_admin, VDI_admin_passwd)
                except Exception as e:
                    VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True, msg="主机列表获取异常")
                    VDIorCAS().update_detection_callback_check(Master_IP, "Upgrade_FileNams", False, 1000,
                                                               "主机列表获取异常", vip, "VDI", 0)
                    logger.error("VDI:%s主机列表获取异常" % (vip))
                    return False

                for cluster_ID in range(len(cluster_ID_list)):

                    if int(cluster_ID_list[cluster_ID]["enableHA"]) == 1:
                        VDI().stop_vdi_ha(
                            vip, int(cluster_ID_list[cluster_ID]["id"]), header, session
                        )
                    for host_massage in host_massage_list:
                        if cluster_ID_list[cluster_ID]["id"] == host_massage["clusterId"]:
                            # 检测主机根目录空间
                            try:
                                host_Avail = int(
                                    TERMINAL().run_cmd(
                                        vip,
                                        22,
                                        root_passwd,
                                        "ssh %s " % (str(host_massage["ip"])) + VDI().CMD.CHECK_ROOT_SIZE,
                                    ).rstrip()[:-1]
                                )
                                logger.debug("检测到主机：%s根目录为%sG" % (str(host_massage["ip"]), host_Avail))
                                if host_Avail <= host_Avail_min:
                                    VDIorCAS().callback_function(
                                        vip, 1015, "VDI", 0, finished=True, msg=str(host_massage["ip"])
                                    )
                                    logger.error("VDI:%s主机:%s根目录空间不足，请扩容" % (vip, str(host_massage["ip"])))
                                    VDIorCAS().update_detection_callback_check(Master_IP, "", True, 1000,
                                                                               "VDI:%s主机:%s根目录空间不足，请扩容" % (
                                                                               vip, str(host_massage["ip"])),
                                                                               vip,
                                                                               "VDI", 0)
                                    # return "主机" + str(host_massage["ip"]) + "根目录空间不足，请扩容"
                            except Exception as e:
                                VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True, msg="主机根目录检测异常")
                                logger.error("VDI:%s主机根目录检测异常" % (vip))
                                VDIorCAS().update_detection_callback_check(Master_IP, "", False, 1000,
                                                                           "VDI:%s主机根目录检测异常" % (vip), vip,
                                                                           "VDI", 0)
                                return False
                VDIorCAS().callback_function(vip,200, "VDI", 0, msg="正在上传文件中，请稍后。。。。。。。")
                for update_specification in update_specification_list:
                    files = VDIorCAS().MD5SUN(
                        update_specification, Master_IP, ssh_port, root_passwd
                    )
                    if files[0]:
                        VDIorCAS().callback_function(vip,200, "VDI", 0,msg= "文件上传成功，Md5检验通过")
                        logger.debug("VDI:%s所有文件上传成功，Md5检验通过" % (vip))
                        # Upgrade_FileNams_list.append(files[1])
                        Upgrade_FileNams=files[1]
                    else:
                        logger.error("VDI:%s有文件上传失败或Md5检验未通过，请重试" % (vip))
                        VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True, msg="VDI:%s有文件上传失败或Md5检验未通过，请重试" % (vip))
                        VDIorCAS().update_detection_callback_check(Master_IP, Upgrade_FileNams, False, 1000,
                                                                   "VDI:%s有文件上传失败或Md5检验未通过，请重试" % (vip), vip, "VDI", 0)
                        return False
                VDIorCAS().callback_function(vip, 200, "VDI", 0, msg="开始执行CVM_CHENCK脚本")
                if VDIorCAS().Tar_Updatefile_To_Check(Master_IP,ssh_port,root_passwd,Upgrade_FileNams) == False:
                    logger.error("VDI:CHECK未通过，请重试")
                    VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True,
                                                 msg="VDI:%sCHECK未通过，请重试"% (vip))
                    VDIorCAS().update_detection_callback_check(Master_IP, Upgrade_FileNams, False, 1000, "VDI:CHECK未通过，请重试", vip,
                                                               "VDI", 0)
                    return False
                VDIorCAS().callback_function(vip,200, "VDI", 0,finished=True,msg= "环境检测完成，开始定制升级任务")
                logger.debug("VDI:%s环境检测完成，开始定制升级任务"%(vip))
                VDIorCAS().update_detection_callback_check(Master_IP,Upgrade_FileNams,True,200,"环境检测完成，开始定制升级任务",vip,"VDI",100)
                return {"Master_IP": Master_IP,"Upgrade_FileNams": Upgrade_FileNams}
        except Exception as e:
            VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True, msg="平台检测异常")
            VDIorCAS().update_detection_callback_check(Master_IP, Upgrade_FileNams, False, 1000, "平台检测异常", vip,
                                                       "VDI", 0)
            logger.error("%s:%s平台检测异常a:%s"%(terrace_type,vip,e))
            return False
    # def update_detection(
    #     self,
    #     vip,
    #     ssh_port,
    #     update_specification_list,
    #     system_version,
    #     admin_user,
    #     admin_password,
    #     root_passwd,
    #     admin_status,
    #     terrace_type="CAS",
    #     terrace_version="",
    #
    # ):
    #
    #     # 验证主机任务状态
    #     VDIorCAS().callback_function(vip,200, terrace_type, 0, msg="开始平台检测")
    #     logger.debug("开始平台检测")
    #     VDIorCAS().update_detection_callback_check("", "", True, 200, "开始平台检测", vip,
    #                                                terrace_type, 0)
    #     # 验证免密可登录性
    #     if not TERMINAL().check_passwd(vip, ssh_port, root_passwd):
    #         VDIorCAS().callback_function(vip,1007, terrace_type, 0)
    #         return False
    #     VDIorCAS().callback_function(vip,200, terrace_type, 0, msg="设置免密登录成功")
    #     logger.debug("主机:%s设置免密登录数据服务器成功"%(vip))
    #     VDIorCAS().callback_function(vip,200, terrace_type, 0, msg="CVM主机状态正常")
    #     VDIorCAS().update_detection_callback_check("", "", True, 200, "CVM主机状态正常", vip,
    #                                                terrace_type, 5)
    #     logger.debug("CVM:%s主机状态正常"%(vip))
    #     try:
    #         if terrace_type == "CAS":
    #             # CAS集群检测
    #             print("ss")
    #             Master_IP = VDIorCAS().get_maset_key(vip, ssh_port, root_passwd)
    #             VDIorCAS().callback_function(vip, 200, terrace_type, 0, msg="获取到管理节点IP" + Master_IP)
    #             logger.debug("%s:%s获取到管理节点IP:%s" % (terrace_type,vip, Master_IP))
    #             VDIorCAS().update_detection_callback_check(Master_IP, "", True, 200,
    #                                                        "%s:%s获取到管理节点IP:%s" % (terrace_type,vip, Master_IP), vip,
    #                                                        terrace_type, 30)
    #
    #             VDIorCAS().callback_function(vip, 200, terrace_type, 0, msg="正在上传文件中，请稍后。。。。。。。")
    #             for update_specification in update_specification_list:
    #                 files = VDIorCAS().MD5SUN(
    #                     update_specification, Master_IP, ssh_port, root_passwd
    #                 )
    #                 if files[0]:
    #                     VDIorCAS().callback_function(vip, 200, terrace_type, 0, msg="文件上传成功，Md5检验通过")
    #                     logger.debug("%s:%s所有文件上传成功，Md5检验通过" % (terrace_type,vip))
    #                     Upgrade_FileNams = files[1]
    #                 else:
    #                     logger.error("%s:%s有文件上传失败或Md5检验未通过，请重试" % (terrace_type,vip))
    #                     return False
    #             VDIorCAS().callback_function(vip, 200, terrace_type, 0, msg="环境检测完成，开始定制升级任务")
    #             CAS().CAS_detection(vip, admin_user, admin_password,root_passwd)
    #
    #             # 制定定时任务
    #             VDIorCAS().update_detection_callback_check(Master_IP, Upgrade_FileNams, True, 200, "环境检测完成，开始定制升级任务",
    #                                                      vip, terrace_type, 100)
    #             return {"Master_IP": Master_IP, "Upgrade_FileNams": Upgrade_FileNams}
    #         elif terrace_type == "VDI":
    #
    #             vdi_login = VDI().VDI_login(
    #                 vip, admin_user, admin_password, terrace_version
    #             )
    #
    #             try:
    #                 if vdi_login[0] == False:
    #                     VDIorCAS().callback_function(vip,1004, "VDI", 0)
    #                     logger.error("VDI:%s管理平台账号密码登录失败"%(vip))
    #                     return False
    #                 session = vdi_login[2]
    #                 header = vdi_login[1]
    #                 VDIorCAS().callback_function(vip,200, "VDI", 0, msg="平台管理账号检测通过")
    #                 logger.debug("VDI:%s管理平台账号密码登录通过" % (vip))
    #                 VDIorCAS().update_detection_callback_check("", "", True, 200, "VDI:%s管理平台账号密码登录通过" % (vip), vip,
    #                                                            "VDI", 10)
    #             except Exception as e:
    #                 VDIorCAS().callback_function(vip,1008, "VDI", 0)
    #                 logger.error("VDI:%s管理平台账号密码登录异常" % (vip))
    #                 return False
    #             # 检测存储异常不重启从E1007开始
    #             try:
    #                 if VDI().vdi_storage_reset(vip, session):
    #                     VDIorCAS().callback_function(vip,1009, "VDI", 0)
    #                     logger.error("VDI:%s检测存储异常设为不重启不通过，请前往设置"%(vip))
    #                     return False
    #             except Exception as e:
    #                 VDIorCAS().callback_function(vip,1010, "VDI", 0)
    #                 logger.error("VDI:%s检测存储异常设为不重启异常" % (vip))
    #                 return False
    #             VDIorCAS().callback_function(vip,200, "VDI", 0, msg="检测存储异常设为不重启通过")
    #             logger.debug("VDI:%s检测存储异常设为不重启通过" % (vip))
    #             VDIorCAS().update_detection_callback_check("", "", True, 200, "VDI:%s检测存储异常设为不重启通过" % (vip), vip,
    #                                                        "VDI", 20)
    #             # 环境检测
    #             VDIorCAS().callback_function(vip,200, "VDI", 0, msg="开始升级前主机环境检测")
    #             logger.debug("VDI:%s开始升级前主机环境检测"%(vip))
    #             VDI().VDI_detection(vip, VDI_admin, VDI_admin_passwd, root_passwd)
    #             logger.debug("VDI:%s主机环境检测完成" % (vip))
    #             # 获取主节点并上传检测文件MD5
    #
    #             Master_IP = VDIorCAS().get_maset_key(vip, ssh_port, root_passwd)
    #
    #             VDIorCAS().callback_function(vip,200, "VDI", 0, msg="获取到管理节点IP" + Master_IP)
    #             logger.debug("VDI:%s获取到管理节点IP:%s" % (vip,Master_IP))
    #             VDIorCAS().update_detection_callback_check(Master_IP, "", True, 200, "VDI:%s获取到管理节点IP:%s" % (vip,Master_IP), vip,
    #                                                        "VDI", 30)
    #             print("sdasjdh")
    #             cluster_ID_list = session.get("http://%s:8083/cas/casrs/cluster/clusters" % (vip),headers=header).json()["cluster"]
    #             print(cluster_ID_list)
    #             quit()
    #
    #
    #             # 查询集群
    #             try:
    #                 logger.debug("VDI:%s正在查询集群信息" % (vip))
    #                 # cluster_ID_list=session.get("http://%s:8083/cas/casrs/cluster/clusters" % (vip),headers=header).json()["cluster"]
    #                 cluster_ID_list = VDI().get_cluster_message(vip, VDI_admin, VDI_admin_passwd)
    #             except Exception as e:
    #                 logger.error(e)
    #                 logger.error("VDI:%s集群信息查询异常" % (vip))
    #                 VDIorCAS().callback_function(vip, 1000, "VDI",0, finished=True, msg="集群信息查询异常")
    #                 return False
    #             # 获取主机列表
    #             try:
    #                 logger.debug("VDI:%s获取主机列表" % (vip))
    #                 host_massage_list = VDI().get_host_message(vip, VDI_admin, VDI_admin_passwd)
    #             except Exception as e:
    #                 VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True, msg="主机列表获取异常")
    #                 logger.error("VDI:%s主机列表获取异常" % (vip))
    #                 return False
    #
    #             for cluster_ID in range(len(cluster_ID_list)):
    #
    #                 if int(cluster_ID_list[cluster_ID]["enableHA"])==1:
    #                     VDI().stop_vdi_ha(
    #                         vip, int(cluster_ID_list[cluster_ID]["id"]), header, session
    #                     )
    #                 for host_massage in host_massage_list:
    #                     if cluster_ID_list[cluster_ID]["id"] == host_massage["clusterId"]:
    #                         # 检测主机根目录空间
    #                         try:
    #                             host_Avail = int(
    #                                 TERMINAL().run_cmd(
    #                                     host_massage["ip"],
    #                                     22,
    #                                     root_passwd,
    #                                     VDI().CMD.CHECK_ROOT_SIZE,
    #                                 ).rstrip()[:-1]
    #                             )
    #                             if host_Avail <= host_Avail_min:
    #                                 VDIorCAS().callback_function(
    #                                     vip, 1015, "VDI", 0, finished=True, msg=str(host_massage["ip"])
    #                                 )
    #                                 logger.error("VDI:%s主机:%s根目录空间不足，请扩容" % (vip, str(host_massage["ip"])))
    #
    #                                 return "主机" + str(host_massage["ip"]) + "根目录空间不足，请扩容"
    #                         except Exception as e:
    #                             VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True, msg="主机根目录检测异常")
    #                             logger.error("VDI:%s主机根目录检测异常" % (vip))
    #                             return False
    #             VDIorCAS().callback_function(vip,200, "VDI", 0, msg="正在上传文件中，请稍后。。。。。。。")
    #             for update_specification in update_specification_list:
    #                 files = VDIorCAS().MD5SUN(
    #                     update_specification, Master_IP, ssh_port, root_passwd
    #                 )
    #                 if files[0]:
    #                     VDIorCAS().callback_function(vip,200, "VDI", 0,msg= "文件上传成功，Md5检验通过")
    #                     logger.debug("VDI:%s所有文件上传成功，Md5检验通过" % (vip))
    #                     # Upgrade_FileNams_list.append(files[1])
    #                     Upgrade_FileNams=files[1]
    #                 else:
    #                     logger.error("VDI:%s有文件上传失败或Md5检验未通过，请重试" % (vip))
    #                     VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True, msg="VDI:%s有文件上传失败或Md5检验未通过，请重试" % (vip))
    #                     return False
    #             if VDIorCAS().Tar_Updatefile_To_Check(Master_IP,ssh_port,root_passwd,Upgrade_FileNams) == False:
    #                 logger.error("VDI:CHECK未通过，请重试")
    #                 VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True,
    #                                              msg="VDI:CHECK未通过，请重试"% (vip))
    #                 return False
    #             VDIorCAS().callback_function(vip,200, "VDI", 0,msg= "环境检测完成，开始定制升级任务")
    #             logger.debug("VDI:%s环境检测完成，开始定制升级任务"%(vip))
    #             VDIorCAS().update_detection_callback_check(Master_IP,Upgrade_FileNams,True,200,"环境检测完成，开始定制升级任务",vip,"VDI",100)
    #             return {"Master_IP": Master_IP,"Upgrade_FileNams": Upgrade_FileNams}
    #     except Exception as e:
    #         VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True, msg="平台检测异常")
    #         logger.error("%s:%s平台检测异常a:%s"%(terrace_type,vip,e))
    #         return False

    def create_terraces(
        self,
        terrace_name,
        vip,
        system_version,
        admin_user,
        admin_password,
        root_password,
        ssh_port,
        terrace_type="CAS"
    ):
        # 点击确认后验证平台状态
        VDIorCAS().callback_function(vip,200, terrace_type, 0, msg="开始验证平台")
        logger.debug("开始验证平台:"+vip)
        try:

            if TERMINAL().check_passwd(
                    vip, ssh_port, root_password
            ):
                VDIorCAS().callback_function(vip, 200, terrace_type, 0,msg= "平台密码验证通过")
                logger.debug("平台:%s密码验证通过" % (vip))
                if terrace_type == "CAS":
                    VDIorCAS().callback_function(vip, 200, "CAS", 0, msg="开始获取平台版本")
                    terrace_version = TERMINAL().run_cmd(
                        vip, ssh_port, root_password, VDIorCAS().CMD.GET_CAS_VERSION
                    ).rstrip("\n")
                    print(terrace_version)
                    VDIorCAS().callback_function(vip, 200, "CAS", 0, msg="获取平台版本成功" + terrace_version)
                    logger.debug("成功获取平台:%s版本号:%s" % (vip, terrace_version))
                    if CAS().CAS_login(vip, admin_user, admin_password):
                        VDIorCAS().callback_function(vip, 200, "CAS", 0, msg="管理平台密码验证通过")
                        logger.debug("CAS:%s管理平台密码验证通过" % (vip))
                        return {"Platform_Version": terrace_version}
                    VDIorCAS().callback_function(vip, 1002, "CAS", 0)
                    logger.error("VDI:%s管理平台密码验证失败，账号:%s;密码:%s" % (vip, admin_user, admin_password))
                    return False
                elif terrace_type == "VDI":
                    VDIorCAS().callback_function(vip, 200, "VDI", 0, msg="开始获取平台版本")
                    terrace_version = VDI().VDI_request_get(
                        VDIorCAS().URL.GET_CAS_VERSION % (vip), VDI_admin, VDI_admin_passwd
                    )["data"]["outVersion"]
                    VDIorCAS().callback_function(vip, 200, "VDI", 0, msg="获取平台版本成功" + terrace_version)
                    logger.debug("成功获取平台:%s版本号:%s" % (vip, terrace_version))
                    if VDI().VDI_login(vip, admin_user, admin_password, terrace_version)[0]:
                        VDIorCAS().callback_function(vip, 200, "VDI", 0, msg="管理平台密码验证通过")
                        logger.debug("VDI:%s管理平台密码验证通过" % (vip))
                        return {"Platform_Version": terrace_version}
                    VDIorCAS().callback_function(vip, 1002, "VDI", 0)
                    logger.error("VDI:%s管理平台密码验证失败，账号:%s;密码:%s" % (vip, admin_user, admin_password))
                    return False
                return False
        except Exception as e:
            VDIorCAS().callback_function(vip,1001, "VDI", 0)
            logger.error("VDI:%s检验未完成，请确认账号密码是否正确" % (vip))
            return False

    # 文件上传和MD5校验
    def MD5SUN(self,update_massase, Master_IP, port, passwd):
        # 获取文件地址和MD5
        try:
            update_path = update_massase["Upgrade_Path"]
            update_file = update_path.split("/")[-1]
            update_md5 = update_massase["Upgrade_MD5"]

            # 上传文件到目标机器
            logger.debug("正在上传文件:%s到%s,请稍后。。。。。。" % (update_file,Master_IP))
            file_md5 = TERMINAL().run_cmd(
                Master_IP,
                port,
                passwd,
                VDIorCAS().CMD.SCP_FILE % (data_host_ip, update_path, update_file),
            ).rstrip("\n")

            if update_md5 == file_md5:
                return True, update_file

            VDIorCAS().callback_function(Master_IP,1005, "VDI", 0)
            logger.error("上传文件%s到%s失败"%(update_file,Master_IP))
            return False
        except Exception as e:
            VDIorCAS().callback_function(Master_IP,1005, "VDI", 0)
            logger.error("上传文件%s到%s异常" % (update_file, Master_IP))
            return False
        # 获取master节点并设置密钥

    def get_maset_key(self,vip, port, root_passwd):
        try:
            # 获取主节点
            Master_IP = TERMINAL().run_cmd(
                vip, port, root_passwd, VDIorCAS().CMD.GET_Master_IP
            ).rstrip("\n")
            logger.debug("获取到主节点")
            # 获取主节点密钥
            ssh_key = TERMINAL().run_cmd(
                Master_IP, port, root_passwd, VDIorCAS().CMD.GET_KEY
            )
            logger.debug("获取到密钥")
            # 设置免密登录
            eventlet.monkey_patch()
            with eventlet.Timeout(10, False):
                TERMINAL().run_cmd(
                    data_host_ip,
                    22,
                    data_host_passwd,
                    VDIorCAS().CMD.ECHO_AUTHORIZED % (ssh_key),
                )
                logger.debug("设置密钥登录:%s成功" % (data_host_ip))
                return Master_IP
            logger.debug("设置密钥登录:%s超时，请检测网络联通性" % (data_host_ip))
            return False

        except Exception as e:
            VDIorCAS().callback_function(Master_IP,1006, "VDI", 0)
            logger.error("设置密钥登录异常")
            return True



    def get_host_ip(self):
        """
        查询本机ip地址
        :return:
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()

        return ip


#获取NAcos服务TOKEN
    def get_nacos_token(self,ip, username, password):
        r = requests.post(VDIorCAS().URL.NACOS_login_URL % (ip, username, password))
        if r.status_code == 200:
            return r.json()["accessToken"]
        logger.error("获取NacsoToken失败")
        return False

    def get_nacos_message(self,NACOS_ip,Token):
        return requests.get(VDIorCAS().URL.NACOS_NS_MESSAGE%(NACOS_ip,Token))
#注册服务
    def register_nacos_instance(self,NACOS_ip, accessToken, register_ip, register_port):
        r = requests.post(
            VDIorCAS().URL.NACOS_register_URL
            % (NACOS_ip, accessToken, register_ip, register_port)
        )
        if r.status_code == 200:
            logger.debug("成功注册Nacos服务")
            return r
        return False
#发送心跳包
    def Send_Health_Beat(self):
        NacosIp = VDIorCAS().get_host_ip()
        client = nacos.NacosClient(SERVER_ADDRESSES, namespace=NAMESPACE, username=NacosUser, password=NacosPasswd)
        client.add_naming_instance(NacosServiceName, NacosIp, NacosPort, "", 1, {}, True, True)
        while True:
            try:
                client.send_heartbeat(NacosServiceName, NacosIp, NacosPort, "", 1, {})
            except Exception as e:
                logger.error("心跳异常")
#回调方法
    def callback_function(self,vip,status_code, type, id, finished=False,msg="ok",New_Workspace_Version="",New_CVK_Version=""):
        print(msg)
        return_dicts = {
            200: {"result": 200, "data": {"msg": msg, "ip": VDIorCAS().get_host_ip()}},
            1000: {
                "result": 1000,
                "data": {"msg": msg, "ip": VDIorCAS().get_host_ip()},
            },
            1001: {
                "result": 1001,
                "data": {"msg": "平台检测未通过，请检查root账号密码！", "ip": VDIorCAS().get_host_ip()},
            },
            1002: {
                "result": 1002,
                "data": {"msg": "VDI管理账号错误，请检查！", "ip": VDIorCAS().get_host_ip()},
            },
            1003: {
                "result": 1003,
                "data": {"msg": "平台账号检测有误，请确认", "ip": VDIorCAS().get_host_ip()},
            },
            1004: {
                "result": 1004,
                "data": {
                    "msg": "VDI管理账号错误，请检查，或超过可登录最大用户数！",
                    "ip": VDIorCAS().get_host_ip(),
                },
            },
            1005: {
                "result": 1005,
                "data": {"msg": "MD5校验未通过，请重新上传！", "ip": VDIorCAS().get_host_ip()},
            },
            1006: {
                "result": 1006,
                "data": {"msg": "master节点获取失败，请检查！", "ip": VDIorCAS().get_host_ip()},
            },
            1007: {
                "result": 1007,
                "data": {"msg": "CVM主机状态异常！", "ip": VDIorCAS().get_host_ip()},
            },
            1008: {
                "result": 1008,
                "data": {
                    "msg": "获取管理节点session失败，检测被迫终止！",
                    "ip": VDIorCAS().get_host_ip(),
                },
            },
            1009: {
                "result": 1009,
                "data": {
                    "msg": "请前往设置存储异常为不重启，检测被迫终止！",
                    "ip": VDIorCAS().get_host_ip(),
                },
            },
            1010: {
                "result": 1010,
                "data": {
                    "msg": "获取设置存储异常为不重启异常，检测被迫终止！",
                    "ip": VDIorCAS().get_host_ip(),
                },
            },
            1011: {
                "result": 1011,
                "data": {"msg": "升级检测异常，请重新检测！", "ip": VDIorCAS().get_host_ip()},
            },
            1012: {
                "result": 1012,
                "data": {"msg": "虚机关闭异常！", "ip": VDIorCAS().get_host_ip()},
            },
            1013: {
                "result": 1013,
                "data": {
                    "msg": "部分虚机关机失败，请手动关闭以下虚机" + msg,
                    "ip": VDIorCAS().get_host_ip(),
                },
            },
            1014: {
                "result": 1014,
                "data": {"msg": "部分存储暂停失败请重试", "ip": VDIorCAS().get_host_ip()},
            },
            1015: {
                "result": 1015,
                "data": {"msg": msg + "主机根目录空间不足，请扩容", "ip": VDIorCAS().get_host_ip()},
            },
            1016: {
                "result": 1016,
                "data": {"msg": "暂停镜像存储失败", "ip": VDIorCAS().get_host_ip()},
            },
            1017: {
                "result": 1017,
                "data": {"msg": "升级中有异常告警请检查" + msg, "ip": VDIorCAS().get_host_ip()},
            },
            1018: {
                "result": 1018,
                "data": {"msg": "CVM连接超时", "ip": VDIorCAS().get_host_ip()},
            },
            1019: {
                "result": 1019,
                "data": {"msg": "主机连接异常，请检测" + msg, "ip": VDIorCAS().get_host_ip()},
            },
        }
        data = {
            "vip": vip,
            "result": status_code == 200,
            "platformType": type,
            "statusCode": status_code,
            "msg": return_dicts[status_code]["data"]["msg"],
            "data": {
                "stepId": id,
                "isFinished": bool(finished),
                "execHostIp": VDIorCAS().get_host_ip(),
                "New_Workspace_Version": New_Workspace_Version,
                "New_CVK_Version": New_CVK_Version
            }
        }
        logger.debug(msg+"data:"+json.dumps(data))
        Token = VDIorCAS().get_nacos_token(NacosServer, NacosUser, NacosPasswd)
        Nacos_Message = VDIorCAS().get_nacos_message(NacosServer, Token).json()["hosts"][0]

        r=requests.put(VDIorCAS().URL.CALLBACK_FUN%(Nacos_Message["ip"],Nacos_Message["port"]), data=json.dumps(data),
                           headers=VDIorCAS().header)
        logger.debug(json.dumps(data)+":"+r.text)
        # print(json.dumps(data)+":"+r.text)
        # print(VDIorCAS().URL.CALLBACK_FUN%(Nacos_Message["ip"],Nacos_Message["port"]))
        # quit()

        return r

#VDI相关属性
class VDI:

    headers_put = {"Content-Type": "application/json"}

    body = ""

    class URL:
        STOP_VM = "http://%s:8083/vdi/rest/workspace/vms/stop/"
        STOP_VM_OFF = "http://%s:8083/vdi/rest/workspace/vms/poweroff/"
        START_VM = "http://%s:8083/vdi/rest/workspace/vms/start/"
        ALTER_HA = "http://%s:8083/cas/cluster/editHa"
        CHECK_STORAGE_REBOOT_HOST = (
            "http://%s:8083/cas/systemConfig/sysConfig?type=sys_conf"
        )
        GET_IMAGES_STORAGE = "http://%s:8083/cas/template/templateStorageList"
        STOP_IMAGES_STORAGE = "http://%s:8083/cas/template/pauseTemplateStorage"
        START_IMAGES_STORAGE = "http://%s:8083/cas/template/startTemplateStorage"
        GET_CLUSTERS_ALL = "http://%s:8083/vdi/rest/workspace/clusters"
        GET_HOSTS_ALL = "http://%s:8083/vdi/rest/workspace/hosts"
        GET_DESKTOPPOOLS_ALL = "http://%s:8083/vdi/rest/workspace/desktoppools"
        GET_STORAGES_ALL = "http://%s:8083/vdi/rest/workspace/storages/pool/"
        STOP_STORAGE = "http://%s:8083/cas/storage/host/%s/storagepool/%s/stop"
        REFRESH_STORAGE="http://%s:8083/cas/storage/host/%s/storagepool/%s/refresh"
        START_STORAGE = "http://%s:8083/cas/storage/host/%s/storagepool/%s/start"
        GET_VM_ALL = "http://%s:8083/vdi/rest/workspace/vms?desktoppoolid=%s"
        OLD_LOGIN = "http://%s:8083/vdi/login/doLogin?encrypt=true&name=%s&password=%s"
        NOW_LOGIN = "http://%s:8083/vdi/login/doLogin"
    class CMD:
        STOP_BT_SERVER = "/var/lib/vdi/Bittorrent/bttorrent.sh stop"
        TAR_FILR_TONAME = "tar -xvf %s|awk 'NR==1'"
        UPDATE_EXPECT = 'echo \'#!/usr/bin/expect \nset timeout 7200 \nspawn ./vdi_upgrade.sh.x -o -p cas \nexpect "*Yes/No*" {\nsend "Yes\\n"\n}\nexpect "*yes/no*" {\nsend "yes\\n"\n}\ninteract\' > %scapture.sh'
        START_UPDATE = "chmod 755 %scapture.sh && cd %s && ./capture.sh"
        UPDATE_LOG_FILE = "ls -l /var/log/upgrade/|grep `date +%Y%m%d`|grep postcheck-report|awk '{print $9}'|tail -1"
        CAT_ERROR = "cat /var/log/upgrade/%s|grep ERROR"
        CAT_CVM_VERSION = "cat /etc/cas_cvm-version"
        MV_LOGFILE = "mkdir -p /var/log/upgrade/update && mv /var/log/upgrade/%s /var/log/upgrade/update/"
        CAT_WORKSPACE_VERSION = (
            "cat /etc/workspace-server.version |head -1|awk '{print $1}'"
        )
        CAT_CVK_VERSION = "cat /etc/cas_cvk-version|head -1"
        CHECK_ROOT_SIZE = "df -hl|grep /$|awk '{print $4}'"
        START_VM_EXPECT = 'echo \'#!/usr/bin/expect \nset timeout 7200 \nspawn ./domOP startall\nexpect "*yes/no*" {\nsend "yes\\n"\n}\ninteract\' > start_vm.sh && chmod +x start_vm.sh && ./start_vm.sh'
        SCP_DOMOP = "scp -r %s:/data/domOP /root/ && chmod +x /root/domOP"
        STOP_VM_EXPECT = 'echo \'#!/usr/bin/expect \nset timeout 7200 \nspawn ./domOP shutall\nexpect "*yes/no*" {\nsend "yes\\n"\n}\ninteract\' > shutdown_vm.sh && chmod +x shutdown_vm.sh && ./shutdown_vm.sh'
        HOST_SHUTDOWN = "shutdown -r now"
        CVK_UPTIME="uptime -p|awk '{print $2,$3}'"


    # VDI request
    def VDI_request_get(self,url, login_name, password):
        try:
            millis = int(round(time.time() * 1000))

            if "?" in url:
                url = url + "&random=" + str(millis)

            else:
                url = url + "?random=" + str(millis)

            r = requests.get(url, auth=HTTPDigestAuth(login_name, password)).json()
            return r
        except Exception as e:
            logger.error(e)
            return False
    #获取主机池
    def get_host_pond(self,vip,admin_user, admin_password):
        return VDI().VDI_request_get(
        VDI().URL.GET_DESKTOPPOOLS_ALL % (vip), admin_user, admin_password)["data"]
    #获取主机池下所有虚机
    def get_host_pond_vm(self,vip,host_pond_id,admin_user,admin_password):
        return VDI().VDI_request_get(
                    VDI().URL.GET_VM_ALL % (vip, host_pond_id),admin_user,admin_password, )["data"]
    #查询集群
    def get_cluster_message(self,vip, admin_user, admin_password):

        return requests.get(VDI().URL.GET_CLUSTERS_ALL % (vip), auth=HTTPDigestAuth(admin_user, admin_password)).json()["data"]
    #获取主机列表
    def get_host_message(self,vip, admin_user, admin_password):
        return VDI().VDI_request_get(
                VDI().URL.GET_HOSTS_ALL % (vip), admin_user, admin_password
            )["data"]
    #根据主机ID获取存储
    def get_host_storage(self,vip,host_id,admin_user,admin_password):
        print()
        return VDI().VDI_request_get(VDI().URL.GET_STORAGES_ALL % (vip) + host_id, admin_user, admin_password)
    # 安全关闭VDI虚机
    def stop_vdi_vm(self,vm_ID, vip, admin_user, admin_passwd):
        r = requests.put(
            VDI().URL.STOP_VM % (vip) + str(vm_ID),
            data=VDI().body,
            headers=VDI().headers_put,
            auth=HTTPDigestAuth(admin_user, admin_passwd),
        )
        return r
    # 强制关闭VDI虚机
    def stop_vdi_vm_off(self,vm_ID, vip, admin_user, admin_passwd):
        r = requests.put(
            VDI().URL().STOP_VM_OFF % (vip) + str(vm_ID),
            data=VDI().body,
            headers=VDI().headers_put,
            auth=HTTPDigestAuth(admin_user, admin_passwd),
        )
        return r
    # 开启VDI虚机
    def start_vdi_vm(self,vm_ID, vip, admin_user, admin_passwd):

        return requests.put(
            VDI().URL.START_VM % (vip) + str(vm_ID),
            data=VDI().body,
            headers=VDI().headers_put,
            auth=HTTPDigestAuth(admin_user, admin_passwd),
        )
    # 关闭VDIHA
    def stop_vdi_ha(self,vip, cluster_ID, header, session=None):

        data = {
            "id": int(cluster_ID),
            "priority": 1,
            "triggerAction": 1,
            "enableBusinessHA": 0,
            "enableHA": 0,
            "enableStorageHA": 0,
        }
        data = json.dumps(data)
        if session == None:
            r = requests.put(VDI().URL.ALTER_HA % (vip), data=data, headers=header)
        else:
            r = session.put(VDI().URL.ALTER_HA % (vip), data=data, headers=header)
        return r
    # 关闭VDIstorage
    def stop_vdi_storage(self,vip, host_id, storage_name, header, session=None):
        # //10.165.9.76:8083/cas/storage/host/2/storagepool/storage01/stop

        if session == None:

            return requests.put(
                VDI().URL.STOP_STORAGE % (vip, host_id, storage_name),
                data="",
                headers=header,
            )
        return session.put(
            VDI().URL.STOP_STORAGE % (vip, host_id, storage_name), data="", headers=header
        )
    #刷新VDIstorage
    def refresh_vdi_storage(self,vip, host_id, storage_name, header, session=None):
        # //10.165.9.76:8083/cas/storage/host/2/storagepool/storage01/stop
        if session == None:
            return requests.put(
                VDI().URL.REFRESH_STORAGE % (vip, host_id, storage_name),
                data="",
                headers=header,
            )
        return session.put(
            VDI().URL.REFRESH_STORAGE % (vip, host_id, storage_name), data="", headers=header
        )
    #VDI升级前环境检测
    def check_vdi_update(self,vip,admin_user,admin_password,host_root_passwd,port,header,session):
        # VDI升级前环境检测
        # 设置存储异常为不重启检测
        try:
            if VDI().vdi_storage_reset(vip, session):
                VDIorCAS().callback_function(vip, 1009, "VDI", 0)
                return False
        except Exception as e:
            VDIorCAS().callback_function(vip, 1010, "VDI", 0)
        VDIorCAS().callback_function(vip, 200, "VDI", 0, msg="检测存储异常设为不重启通过")
        # 虚机状态的检测
        hosts_pond = VDI().get_host_pond(vip,admin_user, admin_password)
        for host_pond in hosts_pond:
            vm_list = VDI().get_host_pond_vm(vip,str(host_pond["id"]),admin_user,admin_password)
            vm_nostop_list = []
            VDIorCAS().callback_function(vip, 200, "VDI", 0, msg="查询是否存在未关闭虚机")
            for vm in vm_list:
                if int(vm["status"]) != 3:
                    vm_nostop_list.append(vm["name"])
            if len(vm_nostop_list) == 0:
                VDIorCAS().callback_function(vip, 200, "VDI", 0,msg= "虚机已全部关闭")
            else:
                VDIorCAS().callback_function(vip, 1000, "VDI", 0, msg="虚机"+vm_nostop_list+"未关闭")
        # HA的检测#存储状态的检测#检测根目录
        VDIorCAS().callback_function(vip, 200, "VDI", 0, msg="开始检测集群HA")
        try:
            cluster_ID_list = VDI().get_cluster_message(vip, admin_user, admin_password)
        except Exception as e:
            VDIorCAS().callback_function(vip, 1000, "VDI", 0, finished=True,msg="集群信息查询异常")
            return False
        # 获取主机列表
        try:
            host_massage_list = VDI().get_host_message(vip, admin_user, admin_password)

        except Exception as e:
            VDIorCAS().callback_function(vip, 1000, "VDI", 0,msg= "主机列表获取异常")
            return False
        for cluster_ID in range(len(cluster_ID_list)):
            # 获取集群HA状态
            if int(cluster_ID_list[cluster_ID]["enableHA"]) == 1:
                VDIorCAS().callback_function(vip, 1000, "VDI", 0, msg="集群HA未关闭")
                return False
            for host_massage in host_massage_list:
                # 获取指定集群下主机
                if cluster_ID_list[cluster_ID]["id"] == host_massage["clusterId"]:
                    # 根据主机ID获取主机存储池状态
                    try:
                        host_storage = VDI().VDI_request_get(
                            VDI().URL.GET_STORAGES_ALL % (vip) + str(host_massage["id"]),
                            admin_user,
                            admin_password,
                        )["data"]
                    except Exception as e:
                        VDIorCAS().callback_function(vip, 1000, "VDI", 0, msg="获取主机存储状态异常，升级被迫终止")
                        return False
                    storage_list=[]
                    for storage in host_storage:
                        print(host_massage["ip"],storage["status"])
                        if storage["type"] != "dir" and storage["status"] == 1:
                            storage_list.append(host_massage["ip"]+":"+storage['name'])
                    # 检测主机根目录空间
                    try:
                        logger.debug("获取%s的根目录空间"%(host_massage["ip"]))
                        host_Avail = int(
                            TERMINAL().run_cmd(
                                host_massage["ip"],
                                port,
                                host_root_passwd,
                                VDI().CMD.CHECK_ROOT_SIZE,
                            ).rstrip()[:-1]
                        )
                        logger.debug("获取到%s的根目录空间：%s"%(host_massage["ip"],host_Avail ))
                        if host_Avail <= host_Avail_min:
                            VDIorCAS().callback_function(
                                vip, 1015, "VDI", 0, msg=str(host_massage["ip"])
                            )
                            return False
                    except Exception as e:
                        VDIorCAS().callback_function(vip, 1000, "VDI", 0, msg="主机根目录检测异常")
                        return False

        if len(storage_list)!=0:
            VDIorCAS().callback_function(vip, 1000, "VDI", 0, msg="检测以下主机存储未关闭"+str(storage_list))
            return False
        VDIorCAS().callback_function(vip, 200, "VDI", 0, msg="校验成功开始执行升级脚本")
        return True
    # 开启VDIstorage
    def start_vdi_storage(self,vip, host_id, storage_name, header, session=None):
        if session == None:
            return requests.put(
                VDI().URL.START_STORAGE % (vip, host_id, storage_name),
                data="",
                headers=header,
            )
        return session.put(
            VDI().URL.START_STORAGE % (vip, host_id, storage_name),
            data="",
            headers=header,
        )
    # 检测VDI存储异常异常不重启检测
    def vdi_storage_reset(self,vip, session):
        try:
            if (
                int(
                    session.get(VDI().URL.CHECK_STORAGE_REBOOT_HOST % (vip)).json()[
                        "data"
                    ]["storage.fault.isolation"]
                )
                != 1
            ):
                return True
            return False
        except Exception as e:
            return False
    # 获取镜像存储
    def get_stop_images_storage(self,vip, session):
        r = session.get(VDI().URL.GET_IMAGES_STORAGE % (vip))
        return r
    # 暂停镜像存储
    def stop_images_storage(self,
        vip,
        session,
        header,
        available,
        capacity,
        id,
        index,
        ip,
        ip2,
        login,
        naa,
        passwd,
        sourcePath,
        status,
        targetPath,
        type,
        useType,
    ):
        data = {
            "available": available,
            "capacity": capacity,
            "id": id,
            "index": index,
            "ip": ip,
            "ip2": ip2,
            "login": login,
            "naa": naa,
            "passwd": passwd,
            "sourcePath": sourcePath,
            "status": status,
            "targetPath": targetPath,
            "type": type,
            "useType": useType,
        }
        data = json.dumps(data)
        r = session.put(VDI().URL.STOP_IMAGES_STORAGE % (vip), data=data, headers=header)
        return r

    # 开启镜像存储
    def start_images_storage(self,
        vip,
        session,
        header,
        available,
        capacity,
        id,
        index,
        ip,
        ip2,
        login,
        naa,
        passwd,
        sourcePath,
        status,
        targetPath,
        type,
        useType,
    ):
        data = {
            "available": available,
            "capacity": capacity,
            "id": id,
            "index": index,
            "ip": ip,
            "ip2": ip2,
            "login": login,
            "naa": naa,
            "passwd": passwd,
            "sourcePath": sourcePath,
            "status": status,
            "targetPath": targetPath,
            "type": type,
            "useType": useType,
        }
        data = json.dumps(data)
        r = session.put(VDI().URL.START_IMAGES_STORAGE % (vip), data=data, headers=header)
        return r

    # 开启VDIHA
    def start_vdi_ha(self,vip, cluster_ID, haminHost, header, session=None):
        data = {
            "id": int(cluster_ID),
            "priority": 1,
            "triggerAction": 1,
            "enableBusinessHA": 0,
            "enableHA": 1,
            "enableStorageHA": 0,
            "haControlStrategy": 0,
            "haMinHost": int(haminHost),
        }
        data = json.dumps(data)
        if session == None:
            return requests.put(VDI().URL.ALTER_HA % (vip), data=data, headers=header)
        return session.put(VDI().URL.ALTER_HA % (vip), data=data, headers=header)

    # VDI进入升级
    def VDI_update_cmd(self,Master_IP, port, passwd, update_file_tar,VIP,header,session):

        # if VDI().check_vdi_update(VIP, VDI_admin, VDI_admin_passwd,
        #                           passwd, port, header, session):
        # 解压文件
        try:
            update_file = update_file_tar.split("/")[-1]
            VDIorCAS().callback_function(VIP, 200, "VDI", 5, msg="开始解压升级文件" + update_file)
            logger.debug("VDI:%s开始解压文件%s" % (VIP, update_file))
            tar_url = TERMINAL().run_cmd(
                Master_IP, port, passwd, VDI().CMD.TAR_FILR_TONAME % (update_file)
            ).rstrip("\n")
            VDIorCAS().callback_function(VIP, 200, "VDI", 5, msg="解压完成，开始写入自动交互脚本")
            TERMINAL().run_cmd(Master_IP, port, passwd, VDI().CMD.UPDATE_EXPECT % (tar_url))
            VDIorCAS().callback_function(VIP, 200, "VDI", 5, msg="执行升级脚本")
            VDIorCAS().callback_function(VIP, 200, "VDI", 5, msg="正在进行升级请稍后......")
            logger.debug("VDI:%s正在进行升级请稍后....." % (VIP))
            host_time = TERMINAL().run_cmd(Master_IP, port, passwd, VDIorCAS().CMD().GET_DATE).rstrip("\n")
            p3 = Process(target=VDIorCAS().get_cvk_log, args=(VIP,
                                                              host_time,
                                                              Master_IP,
                                                              port,
                                                              passwd,
                                                              "VDI",
                                                              5,
                                                              ))
            p3.start()

            TERMINAL().run_cmd(
                Master_IP, port, passwd, VDI().CMD.START_UPDATE % (tar_url, tar_url)
            )
            if tar_url != "":
                TERMINAL().run_cmd(
                    Master_IP, port, passwd, VDIorCAS().CMD.RM_UPDATEFILE % (tar_url)
                )
            if update_file != "":
                TERMINAL().run_cmd(
                    Master_IP, port, passwd, VDIorCAS().CMD.RM_UPDATEFILE % (update_file)
                )
            VDIorCAS().callback_function(VIP, 200, "VDI", 5, finished=True, msg="升级完成请验收")

            return True
        except Exception as e:
            VDIorCAS().callback_function(VIP, 1000, "VDI", 5, finished=True, msg="升级脚本执行异常")
            return False
        # VDIorCAS().callback_function(VIP, 1000, "VDI", 5, finished=True, msg="VDI:%s执行升级脚本前环境检测失败"%(VIP))
        # logger.error("VDI:%s执行升级脚本前环境检测失败"%(VIP))
        # return False

    # VDI资源准备和校验
    def VDI_upcate_check(self,vip, port, root_passwd, update_specification_name):
        update_specification = (
            []
        )  # mysql_correlation.select_IT_update_specification(update_specification_name)[0]
        print(update_specification)
        if update_specification:
            Master_IP = VDIorCAS().get_maset_key(vip, port, root_passwd)
        for update_version in update_specification:
            print(update_version)
            VDI().VDI_update_main(Master_IP, port, root_passwd, update_version)

    # VDI进入升级验收
    def VDI_update_acceptance(self,VIP,Master_IP, port, passwd):
        # VIP = TERMINAL().run_cmd(Master_IP, port, passwd,
        #                          "ip addr show vswitch0 |grep secondary|awk 'END{print $2}'|awk -F '/' '{print $1}'").rstrip("\n")
        # if VIP=="":
        #     VIP=Master_IP
        try:
            update_logfile = ""
            VDIorCAS().callback_function(VIP,200, "VDI", 6, msg="正在等待升级完成，请稍后......")
            logger.debug("VDI:%s正在等待升级完成，请稍后......"%(VIP))
            while update_logfile == "":
                time.sleep(60)
                update_logfile = TERMINAL().run_cmd(
                    Master_IP, port, passwd, VDI().CMD.UPDATE_LOG_FILE
                )

            SUCCESS = TERMINAL().run_cmd(
                Master_IP, port, passwd, VDI().CMD.CAT_ERROR % (update_logfile)
            )
            VDIorCAS().callback_function(VIP,200, "VDI", 6, msg="获取到升级完成信息")

            if SUCCESS != "":
                New_Workspace_Version=TERMINAL().run_cmd(
                    Master_IP, port, passwd, VDI().CMD.CAT_WORKSPACE_VERSION
                ).rstrip("\n")
                New_CVK_Version=TERMINAL().run_cmd(
                    Master_IP, port, passwd, VDI().CMD.CAT_CVK_VERSION
                ).rstrip("\n")
                logger.debug("New_Workspace_Version:%s;New_CVK_Version:%s"%(New_Workspace_Version,New_CVK_Version ))
                VDIorCAS().callback_function(VIP,
                    200,
                    "VDI",
                    6,
                    finished=True,
                    msg="成功升级", New_Workspace_Version=New_Workspace_Version,New_CVK_Version=New_CVK_Version

                )

                # TERMINAL().run_cmd(
                #     Master_IP, port, passwd, VDI().CMD.MV_LOGFILE % (update_logfile.rstrip("\n"))
                # )
                return {"New_Workspace_Version": New_Workspace_Version,
                    "New_CVK_Version": New_CVK_Version
                }
            else:
                VDIorCAS().callback_function(VIP,1017, "VDI", 6,finished=True, msg=update_logfile.rstrip("\n"))
                return False
            return False
        except Exception as e:
            VDIorCAS().callback_function(VIP,1000, "VDI", 6, finished=True,msg="升级验收异常终止")
            return False

    # VDI主机检测
    def VDI_detection(self,vip, admin_user, admin_password, host_root_passwd):

        # 查询集群
        try:
            cluster_ID_list = VDI().get_cluster_message(vip, admin_user, admin_password)
        except Exception as e:
            return False
        # 获取主机列表
        try:
            host_massage_list = VDI().get_host_message(vip, admin_user, admin_password)
        except Exception as e:
            return False
        for cluster_ID in range(len(cluster_ID_list)):
            for host_massage in host_massage_list:
                # 获取指定集群下主机
                if cluster_ID_list[cluster_ID]["id"] == host_massage["clusterId"]:
                    if host_massage["status"] != 1:
                        print(host_massage["name"] + "主机异常")
                    # 检测主机根目录空间
                host_Avail = int(
                    TERMINAL().run_cmd(
                        host_massage["ip"],
                        22,
                        host_root_passwd,
                        VDI().CMD.CHECK_ROOT_SIZE,
                    ).rstrip()[:-1]
                )
                if host_Avail <= host_Avail_min:
                    return False

        return True

    # 开启VDI虚机
    def VDI_start_vm(self,vip, admin_user, admin_password, Master_IP, port, passwd):

        TERMINAL().run_cmd(Master_IP, port, passwd, VDI().CMD.START_VM_EXPECT)
        VDIorCAS().callback_function(vip,200, "VDI", 10, msg="正在执行虚拟机开机脚本，请稍后........")
        time.sleep(120)
        try:
            hosts_pond = VDI().get_host_pond(vip,admin_user, admin_password)
            for host_pond in hosts_pond:
                # 获取主机池下所有虚机
                vm_list = VDI().VDI_request_get(
                    VDI().URL.GET_VM_ALL % (vip, str(host_pond["id"])),
                    admin_user,
                    admin_password,
                )["data"]
                for vm in vm_list:
                    if int(vm["status"]) == 3:
                        VDIorCAS().callback_function(vip,
                            200, "VDI", 10, msg="虚机%s正在开启" % (vm["title"])
                        )
                        VDI().start_vdi_vm(vm["uuid"], vip, admin_user, admin_password)
            time.sleep(1)
            VDIorCAS().callback_function(vip,200, "VDI", 10,finished=True ,msg="虚拟机开机完毕")
            return True
        except Exception as e:
            VDIorCAS().callback_function(vip,1000, "VDI", 10,finished=True,msg="虚机开机异常，升级被迫终止")
            return False

    # 关闭VDI虚拟机
    def VDI_stop_vm(self,vip, admin_user, admin_password, Master_IP, port, passwd):
        # 准备工作
        # 正常关闭所有虚拟机
        try:
            TERMINAL().run_cmd(
                Master_IP, port, passwd, VDI().CMD.SCP_DOMOP % (data_host_ip)
            )
            TERMINAL().run_cmd(Master_IP, port, passwd, VDI().CMD.STOP_VM_EXPECT)
            VDIorCAS().callback_function(vip,200, "VDI", 1, msg="正在执行关闭虚拟机脚本，请稍后.......")
            logger.debug("VDI:%s正在执行关闭虚拟机脚本，请稍后......."%(vip))
            # 在执行一遍
            time.sleep(60)
            TERMINAL().run_cmd(
                Master_IP, port, passwd, VDI().CMD.SCP_DOMOP % (data_host_ip)
            )
            TERMINAL().run_cmd(Master_IP, port, passwd, VDI().CMD.STOP_VM_EXPECT)
            VDIorCAS().callback_function(vip, 200, "VDI", 1, msg="正在执行关闭虚拟机脚本，请稍后.......")
            logger.debug("VDI:%s正在执行关闭虚拟机脚本，请稍后......." % (vip))
            # 在执行一遍
            time.sleep(60)
        except Exception as e:
            VDIorCAS().callback_function(vip,1000, "VDI", 1,True,msg="虚机执行关机脚本异常，请查看")
            logger.error("VDI:%s执行关机脚本异常，请查看"%(vip))
            return False
        # 获取所有主机池下主机
        try:
            logger.debug("开始获取主机池")
            hosts_pond =VDI().get_host_pond(vip, admin_user, admin_password)
            logger.debug("已经获取到主机池")
            for host_pond in hosts_pond:
                # 获取主机池下所有虚机
                logger.debug("获取主机池下所有虚机")
                vm_list = VDI().get_host_pond_vm(vip, str(host_pond["id"]),admin_user,admin_password)
                logger.debug("遍历查看虚机状态")
                vm_nostop_list = []
                for vm in vm_list:
                    logger.debug("虚机%s当前状态为：%s"%(vm["title"],vm["status"]))
                    if int(vm["status"]) != 3:
                        # 未关闭虚机
                        logger.debug("虚机%s未关闭" % (vm["title"]))
                        VDIorCAS().callback_function(vip, 200, "VDI", 1, msg="虚机%s未关闭" % (vm["title"]))
                        vm_nostop_list.append(vm)
                if len(vm_nostop_list) == 0:
                    VDIorCAS().callback_function(vip,200, "VDI", 1,finished=True,msg="虚机已全部关闭")
                    logger.debug("VDI:%s虚机已全部关闭"%(vip))
                    return True
            VDIorCAS().callback_function(vip, 1013, "VDI", 1, finished=True, msg="部分虚机未关闭")
            return {"vm_off_list": vm_nostop_list}
        except Exception as e:
            VDIorCAS().callback_function(vip,1000, "VDI", 1,finished=True,msg="虚机关机异常，请查看")
            logger.error("VDI:%s虚机关机异常，请查看"%(vip))
            return False

    #强制关闭虚机
    def VDI_vm_off(self,vip, admin_user, admin_password):
        # 获取所有主机池下主机
        try:
            logger.debug("开始获取主机池")
            hosts_pond =VDI().get_host_pond(vip, admin_user, admin_password)
            print(hosts_pond)
            logger.debug("已经获取到主机池")
            vm_nostop_list = []
            for host_pond in hosts_pond:
                # 获取主机池下所有虚机
                logger.debug("获取主机池下所有虚机")
                vm_list = VDI().get_host_pond_vm(vip, str(host_pond["id"]),admin_user,admin_password)
                logger.debug("遍历查看虚机状态")
                for vm in vm_list:
                    logger.debug("虚机%s当前状态为：%s"%(vm["title"],vm["status"]))
                    if int(vm["status"]) != 3:
                        # 强制关闭
                        logger.debug("虚机%s未关闭,正在强制关机" % (vm["title"]))
                        VDI().stop_vdi_vm_off(vm["uuid"],vip, admin_user, admin_password)
                        VDIorCAS().callback_function(
                            vip,200, "VDI", 1, msg="强制关闭虚机%s"%(str(vm["title"]))
                        )
                        logger.warning("VDI:%s正在强制关闭虚机%s"%(vip,vm["title"]))
                time.sleep(5)
                vm_list = VDI().get_host_pond_vm(vip, str(host_pond["id"]),admin_user,admin_password)

                VDIorCAS().callback_function(vip,200, "VDI", 1, msg="查询是否存在未关闭虚机")
                logger.debug("VDI:%s正在查询是否存在未关闭虚机"%(vip))
                for vm in vm_list:
                    if int(vm["status"]) != 3:
                        vm_nostop_list.append(vm)
            if len(vm_nostop_list) == 0:
                VDIorCAS().callback_function(vip, 200, "VDI", 1, finished=True, msg="虚机已全部关闭")
                logger.debug("VDI:%s虚机已全部关闭" % (vip))
                return True
            VDIorCAS().callback_function(vip, 1013, "VDI", 1, finished=True, msg=str(json.dumps(vm_nostop_list)))
            logger.error("VDI:%s虚机未完全关闭，请查看" % (vip) + str(vm_nostop_list))
            return {"vm_off_list": vm_nostop_list}
            VDIorCAS().callback_function(vip, 1000, "VDI", 1, finished=True, msg="没有检测到主机池")
        except Exception as e:
            VDIorCAS().callback_function(vip,1000, "VDI", 1,finished=True,msg="虚机关机异常，请查看")
            logger.error("VDI:%s虚机关机异常，请查看"%(vip))
            return False

    # VDI主机关闭HA和共享存储
    def VDI_stop_host_storageorHA(
        self,vip, admin_user, admin_password, host_root_passwd, header, session
    ):
        ########################## # 关闭HA
        # 查询集群

        try:
            logger.debug("VDI:%s正在查询集群信息"%(vip))
            cluster_ID_list = VDI().get_cluster_message(vip, admin_user, admin_password)
        except Exception as e:
            logger.error("VDI:%s集群信息查询异常"%(vip))
            VDIorCAS().callback_function(vip,1000, "VDI", 2,finished=True, msg="集群信息查询异常")
            return False
        # 获取主机列表
        try:
            logger.debug("VDI:%s获取主机列表"%(vip))
            host_massage_list = VDI().get_host_message(vip, admin_user, admin_password)
        except Exception as e:
            VDIorCAS().callback_function(vip,1000, "VDI", 2,finished=True, msg="主机列表获取异常")
            logger.error("VDI:%s主机列表获取异常"%(vip))
            return False
        for cluster_ID in range(len(cluster_ID_list)):
            # 获取集群HA状态
            if int(cluster_ID_list[cluster_ID]["enableHA"]) == 1:
                VDIorCAS().callback_function(vip, 200, "VDI", 2, msg="开始关闭主机HA")
                logger.debug("VDI:%s开始关闭集群HA和存储" % (vip))
                VDI().stop_vdi_ha(
                    vip, int(cluster_ID_list[cluster_ID]["id"]), header, session
                )
            VDIorCAS().callback_function(vip,200, "VDI", 2, msg="开始关闭主机存储")
            logger.debug("VDI:%s开始关闭主机存储"%(vip))
            i = 0
            while i < 5:
                i = i + 1
                host_stop_sum = 0
                storage_sum = 0
                for host_massage in host_massage_list:
                # 获取指定集群下主机
                    if cluster_ID_list[cluster_ID]["id"] == host_massage["clusterId"]:
                        # 根据主机ID获取主机存储池状态
                        ###############################################################校验存储关闭方法
                        try:
                            print(vip,str(host_massage["id"]),admin_user,admin_password)
                            print(i)
                            host_storage = VDI().get_host_storage(vip,str(host_massage["id"]),admin_user,admin_password)["data"]

                        except Exception as e:
                            VDIorCAS().callback_function(vip, 1000, "VDI", 2, finished=True,msg="获取主机存储状态异常，升级被迫终止")
                            return False
                        for storage in host_storage:

                            # 关闭存储
                            if storage["type"] != "dir" :
                                storage_sum=storage_sum+1
                                if storage["status"] != 1:
                                   host_stop_sum=host_stop_sum+1
                                elif storage["status"] == 1:
                                    #刷新存储
                                    VDI().refresh_vdi_storage(
                                        vip,
                                        str(host_massage["id"]),
                                        storage["name"],
                                        header,
                                        session,
                                    )
                                    #关闭存储
                                    logger.debug("VDI:%s正在关闭主机:%s上的存储:%s" % (vip, host_massage["ip"], storage["name"]))
                                    VDI().stop_vdi_storage(
                                        vip,
                                        str(host_massage["id"]),
                                        storage["name"],
                                        header,
                                        session,
                                    )
                                    VDIorCAS().callback_function(vip,
                                                               200,
                                                               "VDI",
                                                               2,
                                                               msg="开始关闭主机" + host_massage["ip"] + "存储" + storage["name"],
                                                               )
                if len(host_massage_list) * host_stop_sum >= len(host_massage_list) * storage_sum:
                    break
                time.sleep(5)
                if i >= 5:
                    VDIorCAS().callback_function(vip, 1000, "VDI", 2, finished=True, msg="关闭主机存储失败")
                    return False
                    break
            ###检测存储HA
            VDIorCAS().callback_function(vip,200, "VDI", 2,finished=True, msg="关闭主机存储成功")
            logger.debug("VDI:%s关闭主机存储成功"%(vip))
            return True

    # # VDI开启镜像存储
    # def VDI_start_images_storage(self,vip, session, header):
    #     # 获取镜像存储列表
    #     images_storage_list = VDI().get_stop_images_storage(vip, session).json()["data"]
    #     for images_storage in images_storage_list:
    #         # type=2是fc存储
    #         if images_storage["type"] == 2:
    #             # 开启镜像存储
    #             VDI().start_images_storage(
    #                 vip,
    #                 session,
    #                 header,
    #                 images_storage["available"],
    #                 images_storage["capacity"],
    #                 images_storage["id"],
    #                 images_storage_list.index(images_storage),
    #                 images_storage["ip"],
    #                 images_storage["ip2"],
    #                 images_storage["login"],
    #                 images_storage["naa"],
    #                 images_storage["passwd"],
    #                 images_storage["sourcePath"],
    #                 images_storage["status"],
    #                 images_storage["targetPath"],
    #                 images_storage["type"],
    #                 images_storage["useType"],
    #             )
    #     time.sleep(10)

    # VDI主机开启HA和共享存储
    def VDI_start_host_storageorHA(
            self, vip, admin_user, admin_password, host_root_passwd, header, session
    ):
        try:
            VDIorCAS().callback_function(vip,200, "VDI", 9,msg= "正在准备开起存储和HA，请稍后......")
            logger.debug("VDI:%s正在准备开起存储和HA，请稍后......"%(vip))
            # 开启镜像存储
            VDI().VDI_start_images_storage(vip, header, session)
            cluster_ID_list = VDI().get_cluster_message(vip, admin_user, admin_password)
            # 获取主机列表
            host_massage_list = VDI().get_host_message(vip, admin_user, admin_password)
        except Exception as e:
            VDIorCAS().callback_function(vip,1000, "VDI", 9, finished=True,msg="获取主机列表异常")
            logger.debug("VDI:%s获取主机列表异常"%(vip))
            return False
        try:
            for cluster_ID in range(len(cluster_ID_list)):

                if int(cluster_ID_list[cluster_ID]["enableHA"]) == 0:
                    VDI().start_vdi_ha(
                        vip,
                        int(cluster_ID_list[cluster_ID]["id"]),
                        len(host_massage_list),
                        header,
                        session,
                    )
                    VDIorCAS().callback_function(vip,200, "VDI", 9, msg="开启HA")
                    logger.debug("VDI%s正在开启HA"%(vip))
                for host_massage in host_massage_list:
                    # 获取指定集群下主机

                    if cluster_ID_list[cluster_ID]["id"] == host_massage["clusterId"]:

                        # 根据主机ID获取主机存储池状态
                        host_storage = VDI().get_host_storage(vip,str(host_massage["id"]),admin_user,admin_password)["data"]

                        for storage in host_storage:
                            print(storage["status"])
                            if storage["type"] != "dir" and storage["status"] != 1:
                                # 开启存储
                                print("VDI:%s正在开起主机%s的存储%s" % (vip, str(host_massage["ip"]), storage["name"]))
                                logger.debug("VDI:%s正在开起主机%s的存储%s" % (vip, str(host_massage["ip"]), storage["name"]))

                                VDI().start_vdi_storage(
                                    vip,
                                    str(host_massage["id"]),
                                    storage["name"],
                                    header,
                                    session,
                                )
                                VDIorCAS().callback_function(
                                    vip,
                                    200,
                                    "VDI",
                                    9,
                                    msg="开启主机"
                                    + str(host_massage["ip"])
                                    + "的"
                                    + storage["name"],
                                )

                        VDIorCAS().callback_function(vip, 200, "VDI", 9,finished=True ,msg="存储和HA已经开启")
                        logger.debug("VDI:%s存储和HA已经开启"%(vip))
                        return True
        except Exception as e:
            VDIorCAS().callback_function(vip,1000, "VDI", 9,finished=True,msg= "关闭存储和HA异常")
            return False

    # VDI关闭BT服务
    def VDI_stop_BT(self,VIP,vip, port, host_root_passwd):
        # 暂停BT服务
        # VIP = TERMINAL().run_cmd(vip, port, host_root_passwd,
        #                          "ip addr show vswitch0 |grep secondary|awk 'END{print $2}'|awk -F '/' '{print $1}'").rstrip("\n")
        # if VIP=="":
        #     VIP=vip
        # print(VIP)
        try:
            VDIorCAS().callback_function(VIP,200, "VDI", 3, msg="正在关闭BT服务")
            TERMINAL().run_cmd(vip, port, host_root_passwd, VDI().CMD.STOP_BT_SERVER)
            logger.debug("VDI:%s已经关闭BT服务"%(VIP))
            VDIorCAS().callback_function(VIP, 200, "VDI", 3,finished=True,msg="已经关闭BT服务")
            return True
        except Exception as e:
            logger.error("VDI:%s暂停BT服务异常，升级被迫中断"%(VIP))
            VDIorCAS().callback_function(VIP,1000, "VDI", 3,finished=True,msg="暂停BT服务异常，升级被迫中断")
            return False

    # VDI暂停镜像存储
    def VDI_stop_images_storage(self,vip, header, session):
        # 获取镜像存储列表
        print(vip, header, session)
        try:
            images_storage_list = VDI().get_stop_images_storage(vip, session).json()[
                "data"
            ]
            print(images_storage_list)
            for images_storage in images_storage_list:
                # type=2是fc存储
                if images_storage["type"] == 2 or images_storage["type"] == 1:
                    # 暂停存储
                    VDI().stop_images_storage(
                        vip,
                        session,
                        header,
                        images_storage["available"],
                        images_storage["capacity"],
                        images_storage["id"],
                        images_storage_list.index(images_storage),
                        images_storage["ip"],
                        images_storage["ip2"],
                        images_storage["login"],
                        images_storage["naa"],
                        images_storage["passwd"],
                        images_storage["sourcePath"],
                        images_storage["status"],
                        images_storage["targetPath"],
                        images_storage["type"],
                        images_storage["useType"],
                    )
            VDIorCAS().callback_function(vip, 200, "VDI", 4, finished=True, msg="暂停镜像已经关闭")
            return True

        except Exception as e:
            VDIorCAS().callback_function(vip,1000, "VDI", 4, finished=True,msg="暂停镜像存储异常，升级被迫中断")

            return False

    def VDI_start_images_storage(self,vip, header, session):
        # 获取镜像存储列表
        print(vip, header, session)
        try:
            images_storage_list = VDI().get_stop_images_storage(vip, session).json()["data"]
            print(images_storage_list)
            for images_storage in images_storage_list:
                # type=2是fc存储
                if images_storage["type"] == 2 or images_storage["type"] == 1:
                    # 暂停存储
                    VDI().start_images_storage(
                        vip,
                        session,
                        header,
                        images_storage["available"],
                        images_storage["capacity"],
                        images_storage["id"],
                        images_storage_list.index(images_storage),
                        images_storage["ip"],
                        images_storage["ip2"],
                        images_storage["login"],
                        images_storage["naa"],
                        images_storage["passwd"],
                        images_storage["sourcePath"],
                        images_storage["status"],
                        images_storage["targetPath"],
                        images_storage["type"],
                        images_storage["useType"],
                    )
            VDIorCAS().callback_function(vip, 200, "VDI",9, msg="已经开启镜像存储")
        except Exception as e:
            VDIorCAS().callback_function(vip,1000, "VDI", 9, finished=True,msg="开启镜像存储异常，升级被迫中断")

            return False
    # VDI主机重启
    def VDI_shutdowm(
        self,vip, admin_user, admin_password, port, root_passwd, New_CVK_Version
    ):
        try:
            VDIorCAS().callback_function(vip,200, "VDI", 7, msg="正在准备重启主机，请稍后......")
            logger.debug("VDI:%s正在准备重启主机，请稍后......"%(vip))
            host_massage_list = VDI().get_host_message(vip, admin_user, admin_password)
            while len(host_massage_list) > 0:
                time.sleep(30)
                print(host_massage_list)
                for host_massage in host_massage_list:
                    if host_massage["status"] == 1:
                        if (
                            TERMINAL().run_cmd(
                                host_massage["ip"],
                                port,
                                root_passwd,
                                VDI().CMD.CAT_CVK_VERSION,
                            ).rstrip("\n")
                            == New_CVK_Version
                        ):
                            logger.debug("VDI:%s正在重启主机"%(vip) + host_massage["ip"])
                            TERMINAL().run_cmd(
                                host_massage["ip"],
                                port,
                                root_passwd,
                                VDI().CMD.HOST_SHUTDOWN,
                            )
                            VDIorCAS().callback_function(
                                vip,200, "VDI", 7, finished=True,msg="正在重启主机" + host_massage["ip"]
                            )

                            host_massage_list.remove(host_massage)
                    else:
                        host_massage_list.remove(host_massage)
                        VDIorCAS().callback_function(
                            vip, 1000, "VDI", 7, finished=True, msg="部分主机未重启"
                        )
            return True
        except Exception as e:
            VDIorCAS().callback_function(
                vip, 1000, "VDI", 7, finished=True, msg="部分主机未重启异常"
            )
            return False


    def VDI_CVK_uptime(self,CVK_ip,ssh_port,root_passwd):
        try:
            cvk_uptime=TERMINAL().run_cmd(CVK_ip,ssh_port,root_passwd,VDI().CMD.CVK_UPTIME).rstrip("\n").split(" ")
            if cvk_uptime[1] in 'minutes,' and int(cvk_uptime[0])>3:
                return True
            return False
        except Exception as e:
            return False
    # VDI重启是否正常
    def VDI_restart_status(self,vip, admin_user, admin_passwd,ssh_port,root_passwd):
        try:
            VDIorCAS().callback_function(vip,200, "VDI", 8, msg="正在等待CVM主机重启，请稍后......")
            logger.debug("VDI:%s正在等待CVM主机重启，请稍后......"%(vip))
            eventlet.monkey_patch()
            with eventlet.Timeout(1200, False):
                while True:
                    try:
                        hosts_status_list = VDI().VDI_request_get(
                            VDI().URL.GET_HOSTS_ALL % (vip), admin_user, admin_passwd
                        )["data"]
                        if len(hosts_status_list) != 0:
                            break
                    except Exception as e:
                        time.sleep(60)
        except Exception as e:
            VDIorCAS().callback_function(vip,1017, "VDI", 8,finished=True)
            return False
        VDIorCAS().callback_function(vip,200, "VDI", 8, msg="CVM启动完成等待其他节点主机启动完成，请稍后......")
        logger.debug("VDI:%sCVM启动完成等待其他节点主机启动完成，请稍后......"%(vip))
        try:
            eventlet.monkey_patch()
            with eventlet.Timeout(600, False):
                while True:
                    for host_prefix in hosts_status_list:
                        host=host_prefix["ip"]
                        if VDI().VDI_CVK_uptime(host,ssh_port,root_passwd)==True:
                            hosts_status_list.remove(host_prefix)
                    if len( hosts_status_list) == 0:
                        VDIorCAS().callback_function(vip, 200, "VDI", 8, finished=True, msg="CVK已经全部启动")
                        return True
                    time.sleep(5)
        except Exception as e:
            VDIorCAS().callback_function(vip,1018, "VDI", 8,finished=True,msg=str(json.dumps(hosts_status_list)))
            logger.error("VDI:%s部分主机连接超时"%(vip)+str(hosts_status_list))
            return {"hosts_status_off_list": hosts_status_list}

    # 管理平台账号加密
    def VDI_key(self,value):
        key = b"*yoiH&^%56_Ha!@#"  # 加密算法的key，产品给出 -- luyang 14721
        value = bytes(value, encoding="utf-8")
        # value = b'Huawei-3com' #  bytes类型
        iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # bytes类型
        crypt_sm4 = CryptSM4()

        crypt_sm4.set_key(key, SM4_ENCRYPT)
        encrypt_value = crypt_sm4.crypt_ecb(value)  # bytes类型
        # print(encrypt_value)
        # print(encrypt_value.hex())
        # print(base64.b64encode(encrypt_value))  # base64加密后可以用于传递
        crypt_sm4.set_key(key, SM4_DECRYPT)
        decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)  # bytes类型
        assert value == decrypt_value

        return str(base64.b64encode(encrypt_value), encoding="utf-8")

    # VDI登录
    def VDI_login(self,vip, admin_user, admin_passwd, terrace_version):
        try:
            if terrace_version == "E1004P04":
                payload = {
                    "encrypt": True,
                    "pwd": str(VDI().VDI_key(admin_passwd)),
                    "loginName": str(admin_user),
                }
                header = {
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json;charset=UTF-8",
                    "Origin": VDIorCAS().URL.VDI_LOGIN % (vip),
                    "Referer": VDIorCAS().URL.VDI_LOGIN % (vip) + "/workspace/",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                }
                cookie_jar = requests.post(
                    VDI().URL.OLD_LOGIN
                    % (
                        vip,
                        str(admin_user),
                        quote(str(VDI().VDI_key(admin_passwd))),
                        "utf-8",
                    ),
                    data=json.dumps(payload),
                    headers=header,
                )
                if cookie_jar.status_code == 200:
                    token = cookie_jar.cookies.get("AC_TOKEN")
                    cookie = "AC_TOKEN=" + token
                    header = {
                        "Cookie": cookie,
                        "Accept": "application/json, text/plain, */*",
                        "Content-Type": "application/json;charset=UTF-8",
                        "Origin": VDIorCAS().URL.VDI_LOGIN % (vip),
                        "Referer": VDIorCAS().URL.VDI_LOGIN % (vip) + "/workspace/",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                    }
                    session = None
                    return True, header, session
                return False
            else:
                payload = {
                    "pwd": str(VDI().VDI_key(admin_passwd)),
                    "loginName": str(VDI().VDI_key(admin_user)),
                }

                with requests.Session() as session:
                    header = {
                        "Accept": "application/json, text/plain, */*",
                        "Content-Type": "application/json;charset=UTF-8",
                        "Origin": VDIorCAS().URL.VDI_LOGIN % (vip),
                        "Referer": VDIorCAS().URL.VDI_LOGIN % (vip) + "/workspace/",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                    }

                    r = session.post(
                        VDI().URL.NOW_LOGIN % (vip),
                        data=json.dumps(payload),
                        headers=header,
                    )

                    if r.status_code == 200 and r.json()["sessionId"]!=None:

                        return True, header, session
                return False
        except Exception as e:
            print(e)
            return False

    #VDI升级主流程
    def VDI_update_main(self,VIP,Platform_Account,Platform_Pwd,Master_IP,SSH_Port,Root_Pwd,Platform_Version,To_Upgrade_Versions):
        for UpdateVersionMessage in To_Upgrade_Versions:
            try:

                vdi_login = VDI().VDI_login(
                    VIP,
                    Platform_Account,
                    Platform_Pwd,
                    Platform_Version,
                )
                try:
                    if vdi_login[0] == False:
                        quit()
                    session = vdi_login[2]

                    header = vdi_login[1]

                except Exception as e:
                    quit()

                # 关闭虚拟机
                if VDI().VDI_stop_vm(
                        VIP,
                        VDI_admin,
                        VDI_admin_passwd,
                        Master_IP,
                        SSH_Port,
                        Root_Pwd,
                ):
                    VDIorCAS().callback_function(VIP, 200, "VDI", 1,finished=True ,msg="已经关闭虚拟机")
                    # 关闭HA
                    if VDI().VDI_stop_host_storageorHA(
                            VIP,
                            VDI_admin,
                            VDI_admin_passwd,
                            Root_Pwd,
                            header,
                            session,
                    ):
                        VDIorCAS().callback_function(VIP, 200, "VDI",2, finished=True, msg="已经关闭HA和存储，并做完主机根目录空间检测")

                        # 关闭BT
                        if VDI().VDI_stop_BT(
                                Master_IP,
                                SSH_Port,
                                Root_Pwd,
                        ):
                            VDIorCAS().callback_function(VIP, 200, "VDI", 3,finished= True, msg="已经关闭ＢＴ服务")

                            # 暂停镜像存储
                            if VDI().VDI_stop_images_storage(VIP, header, session):
                                VDIorCAS().callback_function(VIP, 200, "VDI", 4, finished=True, msg="已经暂停镜像存储")
                                if VDI().check_vdi_update(VIP, VDI_admin, VDI_admin_passwd,
                                                        Root_Pwd, SSH_Port, header, session):
                                    VDI().VDI_update_cmd(
                                        Master_IP,
                                        SSH_Port,
                                        Root_Pwd,
                                        UpdateVersionMessage['Upgrade_Path'],
                                    )
                                VDIorCAS().callback_function(VIP, 200, "VDI", 5, finished=True, msg="已经完成平台升级，请检")

                return True
            except Exception as e:
                return False


    #VDI升级网关
    def VDI_update_Gateway(self,Gateway_IP,SSH_Port,Gateway_Passwd,Update_file):
        #验证网关地址联通性（服务器到网关，网关到数据文件服务器）
        if TERMINAL().check_ssh(Gateway_IP,SSH_Port):
            Gateway_key = TERMINAL().run_cmd(Gateway_IP, SSH_Port, Gateway_Passwd, VDIorCAS().CMD.GET_KEY)
            logger.debug("网关服务器链接成功")
            if TERMINAL().check_ssh(data_host_ip,SSH_Port):
                logger.debug("数据文件服务器链接成功")
                TERMINAL().run_cmd(data_host_ip, 22, data_host_passwd, VDIorCAS().CMD.ECHO_AUTHORIZED%(Gateway_key))
                eventlet.monkey_patch()
                with eventlet.Timeout(5, False):
                    status = TERMINAL().run_cmd(Gateway_IP, SSH_Port, Gateway_Passwd, "ssh root@%s hostname"%(data_host_ip)).rstrip("\n")
                try:
                    if status !=None and status!="":
                        logger.debug("链接到数据服器")
                        update_file=""
                        for file in Update_file[0]["Upgrade_Path"].split("/")[1:-1]:
                            update_file = update_file+"/"+file
                        update_file=update_file+"/Gateway/"
                        Gateway_file=TERMINAL().run_cmd(data_host_ip, 22, data_host_passwd,
                                           "ls %s"%(update_file)).rstrip("\n")
                        TERMINAL().run_cmd(Gateway_IP, SSH_Port, Gateway_Passwd, VDIorCAS().CMD.SCP_GATEWAY_FILE% (data_host_ip,update_file+Gateway_file))
                        tar_url=TERMINAL().run_cmd(Gateway_IP, SSH_Port, Gateway_Passwd,VDI().CMD.TAR_FILR_TONAME%(Gateway_file)).rstrip("\n")
                        TERMINAL().run_cmd(Gateway_IP, SSH_Port, Gateway_Passwd,"cd %s && ./install.sh –u"%(tar_url))
                        return True
                    logger.error("无法链接到数据服器")
                    return False
                except:
                    logger.error("无法链接到数据服器")
                    return False
        logger.debug("无法链接网关服务器")
        return False


    # agent状态检测与异常处理
    def VDI_agent_detection(self,admin_user, admin_password, vip, port, root_passwd):
        hosts_pond = VDI().VDI_request_get(
            VDI().URL.GET_DESKTOPPOOLS_ALL % (vip), admin_user, admin_password
        )["data"]
        for host_pond in hosts_pond:
            print(host_pond)
            # 获取主机池下所有虚机
            vm_list = VDI().VDI_request_get(
                "url_login"
                + "/vdi/rest/workspace/vms?desktoppoolid="
                + str(host_pond["id"]),
                admin_user,
                admin_password,
            )["data"]
            for vm in vm_list:
                print(vm)
                print(vm["uuid"], vm["status"])
                if int(vm["status"]) == 2:
                    # 磁盘检测
                    if "Windows" in vm["osDesc"]:
                        print("这是win")
                        # 获取C盘容量命令
                        cat_cmd = (
                            "virsh qemu-agent-command "
                            + vm["name"]
                            + " '"
                            + '{"execute":"guest-run-command","arguments":{"command":"fsutil volume diskfree c:"}}'
                            + "'|sed 's/\\\\n/\\n/g'|head -1"
                        )
                        print(cat_cmd)
                        # 获取C盘容量
                        win_Avail = float(
                            re.findall(
                                re.compile(r"[(](.*?)[)]", re.S),
                                TERMINAL().run_cmd(vip, port, root_passwd, cat_cmd),
                            )[0].replace(" ", "")[:-2]
                        )
                        if win_Avail >= win_Avail_min:
                            print("正常进行")
                        else:
                            print("请扩容C盘")
                        quit()
                    elif "Linux" in vm["osDesc"]:
                        print("这是linux")
                        select_cmd = (
                            "virsh qemu-agent-command "
                            + vm["name"]
                            + " '"
                            + '{"execute":"guest-run-command","arguments":{"command":"df -hl|grep /$"}}'
                            + "'|awk '{print $4}'"
                        )
                        print(select_cmd)
                        quit()
                        # 获取根目录容量
                        linux_Avail = int(
                            TERMINAL().run_cmd(
                                vip, port, root_passwd, select_cmd
                            ).rstrip()[:-1]
                        )
                        if linux_Avail >= linux_Avail_min:
                            print("正常进行")
                        else:
                            print("请扩容根目录")
                    else:
                        print("这是" + vm["osDesc"])
                else:
                    print(vm["title"] + "异常或未开机")

#CAS相关属性
class CAS:
    headers_put = {"Content-Type": "application/xml"}

    class URL:
        STOP_STORAGE = "http://%s:8080/cas/casrs/storage/stop?id=%s&poolName=%s&hostName=%s"
        STOP_LB = "http://%s:8080/cas/casrs/cluster/editLb"
        STOP_HA = "http://%s:8080/cas/casrs/cluster/editHa"
        STOP_VM = "http://%s:8080/cas/casrs/vm/stop/%s"
        STOP_VM_OFF = "http://%s:8080/cas/casrs/vm/powerOff/%s"
        GET_CLUSTERS_ALL = "http://%s:8080/cas/casrs/cluster/clusters"
        GET_HOSTS_ALL = (
            "http://%s:8080/cas/casrs/cluster/hosts?offset=0&limit=&sortField=id&clusterId=%s"
        )
        GET_HOST = "http://%s:8080/cas/casrs/host"
        GET_CLUSTER_MESSAGE = "http://%s:8080/cas/casrs/cluster/%s"
        GET_VM_ALL = (
            "http://%s:8080/cas/casrs/vm/vmList?hostId=%s&offset=&limit=&sortField=status&sortDir=Asc"
        )
        GET_STORAGE = "http://%s:8080/cas/casrs/storage/pool?hostId=%s"
        GET_LOGIN="http://%s:8080/cas/casrs/hostpool/all"

    class CMD:
        CHECK_ROOT_SIZE = "df -hl|grep /$|awk '{print $4}'"
        SCP_FILE = "scp -r %s:%s /root/ && md5sum /root/%s|awk '{print $1}'"
        TAR_UPDATE_FILE = "tar -xvf %s|awk 'NR==1'"
        WRITE_CAPTURE_PY = "echo '#!/usr/bin/env python \nimport subprocess \ncmd = subprocess.Popen(\"cd '%s' && ./upgrade.sh\", shell=True, stdout=subprocess.PIPE,stdin=subprocess.PIPE) \ncmd.communicate(\"yes\\n\")' > capture.py"
        START_CAPTURE_PY = "/usr/bin/python capture.py"
        UPDATE_LOG_FILE = "ls -l /var/log/upgrade/|grep `date +%Y%m%d`|grep postcheck-report|awk '{print $9}'|tail -1"
        CAT_ERROR = "cat /var/log/upgrade/%s|grep ERROR"
        CAT_CVM_VERSION = "cat /etc/cas_cvm-version|head -1"
        MV_LOGFILE = "madir -p /var/log/upgrade/update && mv /var/log/upgrade/%s /var/log/upgrade/update/"
        CAT_WORKSPACE_VERSION = (
            "cat /etc/workspace-server.version |head -1|awk '{print $1}'"
        )
        CAT_CVK_VERSION = "cat /etc/cas_cvk-version|head -1"

    # CAS获取接口XML文件，参数接口URl，返回获取指定url的xml文本
    def get_xml(self,url, admin_user, admin_passwd):
        millis = int(round(time.time() * 1000))
        if "?" in url:
            url = url + "&random=" + str(millis)
        else:
            url = url + "?random=" + str(millis)
        xml = ElementTree.fromstring(
            requests.get(url, auth=HTTPDigestAuth(admin_user, admin_passwd)).text
        ).iter()
        return xml

    # CAS对获取到的xml进行处理，参数处理的数据，需求标签，返回xml文本中指定标签提取的元素列表
    def get_KeyandVal(self,node, *args):
        list = []
        for i in node:
            if i.tag in args:
                list.append(i.text)
        return list

    def CAS_login(self,vip,admin_user,admin_passwd):
        r=requests.get(CAS().URL.GET_LOGIN%(vip), auth=HTTPDigestAuth(admin_user, admin_passwd))
        if r.status_code==200:
            return True
        return False
    # 关闭 CAS 存储
    def stop_storage(
        self,vip, host_message_id, poolName, hostName, admin_user, admin_passwd
    ):
        return CAS().get_KeyandVal(
            CAS().get_xml(CAS().URL.STOP_STORAGE % (vip,str(host_message_id), poolName, hostName),
                admin_user,
                admin_passwd,
            )
        )

    # 关闭CAS LB
    def stop_LB(self,cluster_ID, vip, admin_user, admin_passwd):
        body = (
            "<cluster>"
            "<id>" + cluster_ID + "</id>"
            "<name>clu</name>"
            "<enableLB>0</enableLB>"
            "<persistTime>0</persistTime>"
            "<checkInterval>0</checkInterval>"
            "<lbMonitorId>0</lbMonitorId>"
            "</cluster>"
        )
        r = requests.put(
            CAS().URL.STOP_LB%(vip),
            data=body,
            headers=CAS().headers_put,
            auth=HTTPDigestAuth(admin_user, admin_passwd),
        )
        return r

    # 关闭CAS HA
    def stop_HA(self,cluster_ID, vip, admin_user, admin_passwd):

        body = (
            "<cluster>"
            "<id>" + cluster_ID + "</id>"
            "<priority>0</priority>"
            "<HaMinHost>0</HaMinHost>"
            "</cluster>"
        )
        r = requests.put(
            CAS().URL.STOP_HA%(vip),
            data=body,
            headers=CAS().headers_put,
            auth=HTTPDigestAuth(admin_user, admin_passwd),
        )
        return r

    # 关闭CAS虚机
    def stop_vm(self,vm_ID, vip, admin_user, admin_passwd):

        body = ""
        r = requests.put(
            CAS().URL.STOP_VM % (vip,str(vm_ID)),
            data=body,
            headers=CAS().headers_put,
            auth=HTTPDigestAuth(admin_user, admin_passwd),
        )
        return r

    # 强制关闭CAS虚拟机
    def stop_vm_off(self,vm_ID, vip, admin_user, admin_passwd):
        body = ""
        r = requests.put(
            CAS().URL.STOP_VM_OFF % (vip,str(vm_ID)),
            data=body,
            headers=CAS().headers_put,
            auth=HTTPDigestAuth(admin_user, admin_passwd),
        )
        return r

    # CAS集群主机状态检测
    def CAS_detection(self,vip, admin_user, admin_password, host_root_passwd):
        # 查询所有的集群及ID
        try:

            cluster_ID_list = CAS().get_KeyandVal(
                CAS().get_xml(
                    CAS().URL.GET_CLUSTERS_ALL%(vip), admin_user, admin_password
                ),
                "id",
            )
            logger.debug("CAS：获取到所有集群信息:"+vip)
        except Exception as e:
            logger.error("CAS：获取集群信息异常:"+vip)
            return False
        for cluster_ID in cluster_ID_list:
            # 根据集群ID获取集群下的所有主机
            try:

                host_message_list = HOSTS.createHosts(
                    CAS().get_KeyandVal(
                        CAS().get_xml(
                            CAS().URL.GET_HOSTS_ALL % (vip,cluster_ID),
                            admin_user,
                            admin_password,
                        ),
                        "id",
                        "name",
                        "status",
                    )
                )
                logger.debug("获取到集群%s下的所有主机"%(str(cluster_ID)))
            except Exception as e:
                logger.error("获取主机信息异常")
                return False
            # 查询所有主机
            try:
                host_list = CAS().get_KeyandVal(
                    CAS().get_xml(
                        CAS().URL.GET_HOST%(vip), admin_user, admin_password
                    ),
                    "id",
                    "ip",
                )
            except Exception as e:
                logger.error("获取主机IP失败")
                return False
            # 检测主机状态是否正常
            for host_message in host_message_list:
                # 筛选关机的主机，1为开机
                if host_message.status != 1:
                    logger.error("主机%s处于关机状态"%(host_message.name))
                # 检测主机根目录空间

                host_Avail = int(
                    TERMINAL().run_cmd(
                        host_list[host_list.index(str(host_message.id)) + 1],
                        22,
                        host_root_passwd,
                        CAS().CMD.CHECK_ROOT_SIZE,
                    ).rstrip()[:-1]
                )
                print(host_Avail)
                if host_Avail <= host_Avail_min:
                    logger.error("主机%s根目录空间不足"%(host_message.name))
                    return False
        return True

    # CAS 平台准备动作
    def CAS_update_setout(self,vip, admin_user, admin_password,port,root_passwd):
        # 查询所有的集群及ID
        try:
            logger.debug("正在获取集群信息")
            VDIorCAS().callback_function(vip, 200, "CAS", 1, msg="正在获取集群信息")
            cluster_ID_list = CAS().get_KeyandVal(
                CAS().get_xml(CAS().URL.GET_CLUSTERS_ALL%(vip), admin_user, admin_password
                ),
                "id",
            )
        except Exception as e:
            logger.error("获取集群信息异常")
            VDIorCAS().callback_function(vip, 1000, "CAS", 1, finished=True, msg="获取集群信息异常")
            return False
        for cluster_ID in cluster_ID_list:
            # 查询HA/LB状态
            logger.debug("正在获取集群%sHA状态"%(cluster_ID))
            VDIorCAS().callback_function(vip, 200, "CAS", 1, msg="正在获取集群%sHA状态"%(cluster_ID))
            cluster_message = CAS().get_KeyandVal(
                CAS().get_xml(
                    CAS().URL.GET_CLUSTER_MESSAGE % (vip,cluster_ID),
                    admin_user,
                    admin_password,
                ),
                "enableHA",
                "enableLB",
            )
            # 查看HA状态0为关闭
            if int(cluster_message[0]) != 0:
                logger.debug("正在关闭集群%sHA"%(cluster_ID))
                VDIorCAS().callback_function(vip, 200, "CAS", 1, msg="正在关闭集群%sHA"%(cluster_ID))
                # 关闭HA
                CAS().stop_HA(cluster_ID, vip, admin_user, admin_password)
            # 获取指定集群下主机id、主机名、状态
            logger.debug("开始获取主机信息")
            VDIorCAS().callback_function(vip, 200, "CAS", 1, msg="正在获取主机信息")
            host_message_list = HOSTS.createHosts(
                CAS().get_KeyandVal(
                    CAS().get_xml(
                        CAS().URL.GET_HOSTS_ALL % (vip,cluster_ID),
                        admin_user,
                        admin_password,
                    ),
                    "id",
                    "name",
                    "status",
                )
            )
            for host_message in host_message_list:
                # 筛选关机的主机，1为开机
                if host_message.status != 1:
                    logger.error("主机%s处于关机状态，请检查"%(host_message.name))
                    VDIorCAS().callback_function(vip, 200, "CAS", 1, msg="主机%s处于关机状态，请检查"%(host_message.name))
            try:
                Master_IP = VDIorCAS().get_maset_key(vip, port, root_passwd)
                TERMINAL().run_cmd(
                    Master_IP,port, root_passwd, VDI().CMD.SCP_DOMOP % (data_host_ip)
                )
                TERMINAL().run_cmd(Master_IP, port, root_passwd, VDI().CMD.STOP_VM_EXPECT)
                VDIorCAS().callback_function(vip, 200, "CAS", 1, msg="正在执行关闭虚拟机脚本，请稍后.......")
                logger.debug("CAS:%s正在执行关闭虚拟机脚本，请稍后......." % (vip))
            except Exception as e:
                VDIorCAS().callback_function(vip, 1000, "CAS", 1, finished=True, msg="虚机执行关机脚本异常，请查看")
                logger.error("CAS:%s执行关机脚本异常，请查看" % (vip))
                return False
            list = []
            for host_message in host_message_list:
                ##需多线程
                list.append(
                    threading.Thread(
                        target=CAS().CAS_update_hosts,
                        args=(
                            vip,
                            host_message.id,
                            host_message.name,
                            admin_user,
                            admin_password,
                        ),
                    )
                )
            for i in list:
                i.start()
            list.reverse()
            for i in list:
                i.join()
            VDIorCAS().callback_function(vip, 200, "CAS", 1, finished=True, msg="平台升级前准备完成，开始升级")

    # CAS升级前每台主机的准备动作
    def CAS_update_hosts(self,vip, host_id, host_name, admin_user, admin_password):
        vm_list = CAS().get_KeyandVal(
            CAS().get_xml(
                CAS().URL.GET_VM_ALL % (vip,str(host_id)),
                admin_user,
                admin_password,
            ),
            "id",
            "vmStatus",
        )
        for vm in range(len(vm_list)):
            if vm == 0 or vm % 2 == 0:
                if vm_list[vm + 1] != "shutOff" or vm_list[vm + 1] != "shutdown":
                    # 正常关闭虚机
                    CAS().stop_vm(vm_list[vm], vip, admin_user, admin_password)
        time.sleep(50)
        for vm in range(len(vm_list)):
            if vm == 0 or vm % 2 == 0:
                if vm_list[vm + 1] != "shutOff":
                    # 强制关闭虚机
                    CAS().stop_vm_off(vm_list[vm], vip, admin_user, admin_password)
        time.sleep(10)
        # 查询主机下存储池获取存储名称
        storage_name_list = CAS().get_KeyandVal(
            CAS().get_xml(
                CAS().URL.GET_STORAGE % (vip,str(host_id)),
                admin_user,
                admin_password,
            ),
            "name",
        )

        for storage_name in storage_name_list:
            # 关闭存储池
            CAS().stop_storage(
                vip, host_id, storage_name, host_name, admin_user, admin_password
            )
            print(storage_name + "已经关闭")

    # CAS资源准备和校验
    def CAS_upcate_check(self,vip, port, root_passwd, update_specification_name):
        update_specification = []
        print(update_specification)
        if update_specification:
            Master_IP = CAS().get_maset_key(vip, port, root_passwd)
        for update_version in update_specification:
            print(update_version)
            CAS().CAS_update_main(Master_IP, port, root_passwd, update_version)

    # CAS进入升级
    def CAS_update_main(self,VIP,Master_IP, port, passwd, update_file):
        try:
            update_file = update_file.split("/")[-1]
            VDIorCAS().callback_function(VIP, 200, "CAS", 2, msg="开始解压升级文件" + update_file)
            logger.debug("CAS:%s开始解压文件%s" % (VIP, update_file))
            tar_url = TERMINAL().run_cmd(
                Master_IP, port, passwd, VDI().CMD.TAR_FILR_TONAME % (update_file)
            ).rstrip("\n")
            VDIorCAS().callback_function(VIP, 200, "CAS", 2, msg="解压完成开始，开始写入自动交互脚本")
            TERMINAL().run_cmd(Master_IP, port, passwd, VDI().CMD.UPDATE_EXPECT % (tar_url))
            VDIorCAS().callback_function(VIP, 200, "CAS", 2, msg="执行升级脚本")
            time.sleep(1)
            VDIorCAS().callback_function(VIP, 200, "CAS", 2, msg="正在进行升级请稍后......")
            logger.debug("CAS:%s正在进行升级请稍后......" % (VIP))
            TERMINAL().run_cmd(
                Master_IP, port, passwd, CAS.CMD.WRITE_CAPTURE_PY % (tar_url)
            )
            TERMINAL().run_cmd(Master_IP, port, passwd, CAS.CMD.START_CAPTURE_PY)
            ###uptcl跟踪
            VDIorCAS().callback_function(VIP, 200, "CAS", 2, finished=True, msg="等待升级完成")
            return True
        except Exception as e:
            VDIorCAS().callback_function(VIP, 1000, "CAS", 2, finished=True, msg="升级脚本执行异常")
            return False

    # CAS进入升级验收
    def CAS_update_acceptance(self,VIP,Master_IP, port, passwd):
        try:
            update_logfile = ""
            VDIorCAS().callback_function(VIP, 200, "CAS", 3, msg="正在等待升级完成，请稍后......")
            time.sleep(400)
            logger.debug("CAS:%s正在等待升级完成，请稍后......" % (Master_IP))
            while update_logfile == "":
                time.sleep(30)
                update_logfile = TERMINAL().run_cmd(
                    Master_IP, port, passwd, CAS().CMD.UPDATE_LOG_FILE
                )

            SUCCESS = TERMINAL().run_cmd(
                Master_IP, port, passwd, CAS().CMD.CAT_ERROR % (update_logfile)
            )
            VDIorCAS().callback_function(VIP, 200, "CAS", 3, msg="获取到升级完成信息")

            if SUCCESS != "":
                New_CVM_Version = TERMINAL().run_cmd(
                    Master_IP, port, passwd, CAS().CMD.CAT_CVM_VERSION
                ).rstrip("\n")
                New_CVK_Version = TERMINAL().run_cmd(
                    Master_IP, port, passwd, CAS().CMD.CAT_CVK_VERSION
                ).rstrip("\n")
                logger.debug("New_CVM_Version:%s;New_CVK_Version:%s" % (New_CVM_Version, New_CVK_Version))
                VDIorCAS().callback_function(VIP,
                                             200,
                                             "CAS",
                                             3,
                                             finished=True,
                                             msg="成功升级", New_Workspace_Version=New_CVM_Version,
                                             New_CVK_Version=New_CVK_Version
                                             )

                return {"New_Workspace_Version": New_CVM_Version,
                        "New_CVK_Version": New_CVK_Version
                        }
            else:
                VDIorCAS().callback_function(VIP, 1017, "CAS", 3, finished=True, msg=update_logfile.rstrip("\n"))
                return False
            return False
        except Exception as e:
            VDIorCAS().callback_function(VIP, 1000, "CAS", 3, finished=True, msg="升级验收异常终止")
            return False

    #CAS重启主机
    def CAS_shutdowm(
        self,vip, admin_user, admin_password, port, root_passwd, New_CVK_Version
    ):
        try:
            VDIorCAS().callback_function(vip,200, "CAS", 4, msg="正在准备重启主机，请稍后......")
            logger.debug("CAS:%s正在准备重启主机，请稍后......"%(vip))
            try:
                logger.debug("正在获取集群信息")
                VDIorCAS().callback_function(vip, 200, "CAS", 4, msg="正在获取集群信息")
                cluster_ID_list = CAS().get_KeyandVal(
                    CAS().get_xml(CAS().URL.GET_CLUSTERS_ALL % (vip), admin_user, admin_password
                                  ),
                    "id",
                )
            except Exception as e:
                logger.error("获取集群信息异常")
                VDIorCAS().callback_function(vip, 1000, "CAS", 4, finished=True, msg="获取集群信息异常")
                return False
            for cluster_ID in cluster_ID_list:
                host_massage_list = CAS().get_KeyandVal(
                        CAS().get_xml(
                            CAS().URL.GET_HOSTS_ALL % (vip, str(cluster_ID)),
                            admin_user,
                            admin_password,
                        ),
                        "ip",
                        "status"
                    )
                # host_massage_list=["10.165.9.175", "0", "10.165.9.176", "0"]

                while len(host_massage_list) > 0:
                    time.sleep(1)
                    for host_massage in host_massage_list[0::2]:
                        print(host_massage)
                        if int(host_massage_list[host_massage_list.index(host_massage)+1]) == 1:
                            if (
                                    TERMINAL().run_cmd(
                                        host_massage,
                                        port,
                                        root_passwd,
                                        CAS().CMD.CAT_CVK_VERSION,
                                    ).rstrip("\n")
                                    == New_CVK_Version
                            ):
                                logger.debug("CAS:%s正在重启主机" % (vip) + host_massage)
                                TERMINAL().run_cmd(
                                    host_massage,
                                    port,
                                    root_passwd,
                                    VDI().CMD.HOST_SHUTDOWN,
                                )
                                VDIorCAS().callback_function(
                                    vip, 200, "CAS", 4, finished=True, msg="正在重启主机" + host_massage
                                )

                                host_massage_list.remove(host_massage)
                                host_massage_list.remove(host_massage_list[host_massage_list.index(host_massage)+1])

                        else:
                            host_massage_list.remove(host_massage)
                            host_massage_list.remove(host_massage_list[host_massage_list.index(host_massage) + 1])
                            VDIorCAS().callback_function(
                                vip, 1000, "CAS", 4, finished=True, msg="部分主机未重启"
                            )
                return True


        except Exception as e:
            VDIorCAS().callback_function(
                vip, 1000, "CAS", 4, finished=True, msg="部分主机未重启异常"
            )
            return False

    #CAS等待主机重启
    def CAS_restart_status(self,vip, admin_user, admin_passwd):
        try:
            VDIorCAS().callback_function(vip,200, "CAS", 5, msg="正在等待CVM主机重启，请稍后......")
            logger.debug("CAS:%s正在等待CVM主机重启，请稍后......"%(vip))
            eventlet.monkey_patch()
            with eventlet.Timeout(1200, False):
                while True:
                    try:
                        cluster_ID_list = CAS().get_KeyandVal(
                            CAS().get_xml(CAS().URL.GET_CLUSTERS_ALL % (vip), admin_user, admin_passwd
                                          ),
                            "id",
                        )
                        if len(cluster_ID_list) != 0:
                            break
                    except Exception as e:
                        time.sleep(60)
        except Exception as e:
            VDIorCAS().callback_function(vip,1017, "CAS", 5,finished=True)
            return False
        VDIorCAS().callback_function(vip,200, "CAS", 5, msg="CVM启动完成等待其他节点主机启动完成，请稍后......")
        logger.debug("CAS:%sCVM启动完成等待其他节点主机启动完成，请稍后......"%(vip))
        try:
            eventlet.monkey_patch()
            with eventlet.Timeout(600, False):
                while True:
                    for cluster_ID in cluster_ID_list:
                        host_massage_list = CAS().get_KeyandVal(
                            CAS().get_xml(
                                CAS().URL.GET_HOSTS_ALL % (vip, str(cluster_ID)),
                                admin_user,
                                admin_passwd,
                            ),
                            "ip",
                        )
                    for host_prefix in host_massage_list:
                        host=host_prefix
                    if len( host_massage_list) == 0:
                        VDIorCAS().callback_function(vip, 200, "CAS", 5, finished=True, msg="CVK已经全部启动")
                        return True
        except Exception as e:
            VDIorCAS().callback_function(vip,1018, "CAS", 5,finished=True,msg=str(json.dumps(host_massage_list)))
            logger.error("VDI:%s部分主机连接超时"%(vip)+str(host_massage_list))
            return {"hosts_status_off_list": host_massage_list}


####################################################################################################
########################################FASTAPI模型#################################################
####################################################################################################

class CAS_RESTART_STATUS(BaseModel):
    VIP: str
    Platform_Account: str
    Platform_Pwd: str

class CAS_SHUTDOWN(BaseModel):
    VIP: str
    SSH_Port: int
    Platform_Account: str
    Platform_Pwd: str
    Root_Pwd: str
    New_CVK_Version: str

class VDI_START_VM(BaseModel):
    VIP: str
    Master_IP: str
    SSH_Port: int
    Root_Pwd: str

class VDI_START_STORAGEORHA(BaseModel):
    VIP: str
    Platform_Account: str
    Platform_Pwd: str
    Root_Pwd: str
    Platform_Version: str

class VDI_RESTART_STATUS(BaseModel):
    VIP: str
    SSH_Port: int
    Root_Pwd: str

class VDI_SHUTDOWN(BaseModel):
    VIP: str
    Master_IP: str
    SSH_Port: int
    Root_Pwd: str
    New_CVK_Version: str

class VDI_UPDATE_ACCEPTANCE(BaseModel):
    VIP: str
    Master_IP: str
    SSH_Port: str
    Root_Pwd: str

class CAS_UPDATE_ACCEPTANCE(BaseModel):
    VIP: str
    Master_IP: str
    SSH_Port: str
    Root_Pwd: str

class VDI_UPDATE_MAIN(BaseModel):
    VIP: str
    Platform_Account: str
    Platform_Pwd: str
    Master_IP: str
    SSH_Port: int
    Root_Pwd: str
    Platform_Version: str
    To_Upgrade_Versions: list

class START_CAS_UPDATE(BaseModel):
    VIP: str
    Master_IP: str
    SSH_Port: int
    Root_Pwd: str
    Upgrade_FileNams: str

class START_VDI_UPDATE(BaseModel):
    Master_IP: str
    SSH_Port: int
    Root_Pwd: str
    Upgrade_FileNams: str
    VIP: str
    Platform_Account: str
    Platform_Pwd: str
    Platform_Version: str

class VDI_STOP_IMAGES_STORAGE(BaseModel):
    VIP: str
    Platform_Account: str
    Platform_Pwd: str
    Platform_Version: str

class VDI_STOP_BT(BaseModel):
    VIP: str
    Master_IP: str
    SSH_Port: int
    Root_Pwd: str

class VDI_STOP_STORAGEORHA(BaseModel):
    VIP: str
    Platform_Account: str
    Platform_Pwd: str
    Root_Pwd: str
    Platform_Version: str

class VDI_STOP_VM(BaseModel):
    VIP: str
    Master_IP: str
    SSH_Port: int
    Root_Pwd: str

class VDI_OFF_VM(BaseModel):
    VIP: str

class CAS_UPDATE_SETOUT(BaseModel):
    VIP: str
    Platform_Account: str
    Platform_Pwd: str
    SSH_Port: int
    Root_Pwd: str

class UPDATE_detection(BaseModel):
    VIP: str
    Sys_Version: str
    Platform_Type: str
    Platform_Account: str
    Platform_Pwd: str
    Root_Pwd: str
    SSH_Port: int
    To_Upgrade_Versions: list
    Platform_ServerStatus: int
    Platform_Version: str

class CRETE_TERRACES(BaseModel):
    PlatformName: str
    VIP: str
    Sys_Version: str
    Platform_Type: str
    Platform_Account: str
    Platform_Pwd: str
    Root_Pwd: str
    SSH_Port: int

class CHECK_VDI_UPDATE(BaseModel):
    VIP: str
    Platform_Version: str
    Platform_Account: str
    Platform_Pwd: str
    Root_Pwd: str
    SSH_Port: int

class TEST(BaseModel):
    type: str
    Id: int

class UPDATE_GATEWAY(BaseModel):
    Gateway_IP: str
    SSH_Port: int
    Gateway_Passwd: str
    To_Upgrade_Versions: list

####################################################################################################
########################################公共--API部分################################################
####################################################################################################

router = FastAPI()
return_dict_unusual = {"statusCode": 202, "message": "调用异常", "result": False, "debug": None, "data": None}
return_dict_success = {"statusCode": 200, "message": "调用成功", "result": True, "debug": None, "data": None}
return_model={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": None}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None, "data": None}
                }
            },
        }
    }

###新建平台
@router.post(
    "/register/terraces/check",
    summary="CAS/VDI平台注册检测，成功返回平台版本",
    description="CAS/VDI平台注册检测，成功返回平台版本Platform_Version,否则返回falst",
    responses={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": {
                        "Platform_Version": "str"}}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None, "data": None}
                }
            },
        }
    }
)
async def create_terraces(terraces_message: CRETE_TERRACES):

    data = VDIorCAS().create_terraces(
        terraces_message.PlatformName,
        terraces_message.VIP,
        terraces_message.Sys_Version,
        terraces_message.Platform_Account,
        terraces_message.Platform_Pwd,
        terraces_message.Root_Pwd,
        terraces_message.SSH_Port,
        terraces_message.Platform_Type,

    )

    if data != False:
        return_dict_success['data']=data
        return_dict_success['message']="平台检测通过，并获取平台CVM版本信息"
        return return_dict_success
    return_dict_unusual['message']="平台检测未通过,请确认相关信息"
    return return_dict_unusual

###升级前平台检测
@router.post(
    "/detection",
    summary="CAS/VDI平台升级前检测，成功才可以创建定时任务",
    description="CAS/VDI平台升级前检测，成功才可以创建定时任务，检测成功返回管理IPMaster_IP,升级包列表update_file_list,否则返回flast",
    responses=return_model
)
async def update_detection(terraces_message: UPDATE_detection):
    p2 = Process(target=VDIorCAS().update_detection, args=(
        terraces_message.VIP,
        terraces_message.SSH_Port,
        terraces_message.To_Upgrade_Versions,
        terraces_message.Sys_Version,
        terraces_message.Platform_Account,
        terraces_message.Platform_Pwd,
        terraces_message.Root_Pwd,
        terraces_message.Platform_ServerStatus,
        terraces_message.Platform_Type,
        terraces_message.Platform_Version,

    ))
    p2.start()

    return return_dict_success


####################################################################################################
########################################CAS--API部分#################################################
####################################################################################################

##CAS升级前准备
@router.post(
    "/cas/vm/stop", summary="1、升级前准备动作", description="1、升级前准备,成功返回True，失败返回falst",responses={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": None}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None}
                }
            },
        }
    }
)
async def cas_update_setout(message: CAS_UPDATE_SETOUT):
    p2 = Process(target=CAS().CAS_update_setout(), args=(
            message.VIP,
            message.Platform_Account,
            message.Platform_Pwd,
            message.SSH_Port,
            message.Root_Pwd,))
    p2.start()
    return return_dict_success

#CAS进入升级
@router.post(
    "/cas/update/start",
    summary="2、执行VDI升级脚本",
    description="2、执行VDI升级脚本，成功返回True，失败返回falst",
    responses=return_model,
)
async def start_cas_update(update_message: START_CAS_UPDATE):
    p2 = Process(target=CAS().CAS_update_main(), args=(
        update_message.VIP,
        update_message.Master_IP,
        update_message.SSH_Port,
        update_message.Root_Pwd,
        update_message.Upgrade_FileNams,
    ))
    p2.start()
    return return_dict_success
###CAS验收
@router.post(
    "/cas/acceptance",
    summary="3、CAS升级完成验收升级任务执行状态",
    description="CAS升级后验收阶段，成功返回True，失败返回falst",
    responses={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": {"New_Workspace_Version": "str","New_CVK_Version": "str"}}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None, "data": None}
                }
            },
        }
    }
)
async def vdi_update_acceptance(acceptance_message: CAS_UPDATE_ACCEPTANCE):
    p2 = Process(target=CAS().CAS_update_acceptance(), args=(
        acceptance_message.VIP,
        acceptance_message.Master_IP,
        acceptance_message.SSH_Port,
        acceptance_message.Root_Pwd,))
    p2.start()
    return return_dict_success

####重启CAS主机
@router.post(
    "/cas/hosts/restart",
    summary="4、cas待升级完成后重启主机",
    description="cas主机重启，成功返回True，失败返回falst",
    responses=return_model,
)
async def vdi_shutdown(shutdown_message: CAS_SHUTDOWN):
    p2 = Process(target=CAS().CAS_shutdowm, args=(
            shutdown_message.VIP,
            shutdown_message.Platform_Account,
            shutdown_message.Platform_Pwd,
            shutdown_message.SSH_Port,
            shutdown_message.Root_Pwd,
            shutdown_message.New_CVK_Version,))
    p2.start()
    return return_dict_success


###等待主机重启
@router.post(
    "/cas/restart/status",
    summary="5、VDI主机重启后检测主机服务启动是否正常",
    description="等待主机重启，成功返回True，失败返回异常主机状态列表hosts_status_list",
    responses={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": None}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None, "data": {"hosts_status_off_list": "list"}}
                }
            },
        }
    }
)
async def vdi_restart_status(status_message: CAS_RESTART_STATUS):
    p2 = Process(target=CAS().CAS_restart_status, args=(
        status_message.VIP,status_message.Platform_Account, status_message.Platform_Pwd))
    p2.start()
    return return_dict_success




####################################################################################################
########################################VDI--API部分#################################################
####################################################################################################


###VDI升级执行脚本前检测
@router.post("/vdi/update/check",responses=return_model)
async def start_vdi_check(check_message: CHECK_VDI_UPDATE):
    logger.debug(check_message.Platform_Pwd,check_message.Root_Pwd)
    vdi_login = VDI().VDI_login(
            check_message.VIP,
            check_message.Platform_Account,
            check_message.Platform_Pwd,
            check_message.Platform_Version,
        )
    try:
        if vdi_login[0] == False:
            quit()
        session = vdi_login[2]
        header = vdi_login[1]
    except Exception as e:
        quit()

    p2 = Process(target=VDI().check_vdi_update, args=(
        check_message.VIP,VDI_admin,VDI_admin_passwd,check_message.Root_Pwd,check_message.SSH_Port,header,session))
    p2.start()
    return return_dict_success

###VDI升级主要流程
@router.post(
    "/vdi/update/main",
    summary="VDI主要升级相关动作，包含1-5",
    description="VDI升级流程整合，包含1-5，成功返回True，失败返回falst",
    responses=return_model,
)
async def update_vdi_main(update_message: VDI_UPDATE_MAIN):

    p2 = Process(target=VDI().VDI_update_main, args=(
    update_message.VIP,
    update_message.Platform_Account,
    update_message.Platform_Pwd,
    update_message.Master_IP,
    update_message.SSH_Port,
    update_message.Root_Pwd,
    update_message.Platform_Version,
    update_message.To_Upgrade_Versions,))
    p2.start()
    return return_dict_success

###VDI关闭虚拟机
@router.post(
    "/vdi/vm/stop", summary="1、VDI关闭虚拟机", description="1、VDI关闭虚拟机,成功返回True，失败返回falst",responses={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": None}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None, "vm_off_list": []}
                }
            },
        }
    }
)
async def stop_vdi_vm(vm_message: VDI_STOP_VM):
    p2 = Process(target=VDI().VDI_stop_vm, args=(
            vm_message.VIP,
            VDI_admin,
            VDI_admin_passwd,
            vm_message.Master_IP,
            vm_message.SSH_Port,
            vm_message.Root_Pwd,))
    p2.start()
    return return_dict_success


###强制VDI关闭虚拟机
@router.post(
    "/vdi/vm/off", summary="1、VDI强制关闭虚拟机", description="1、VDI强制关闭虚拟机,成功返回True，失败返回falst",responses={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": None}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None, "vm_off_list": []}
                }
            },
        }
    }
)
async def stop_vdi_off(vm_message: VDI_OFF_VM):
    p2 = Process(target=VDI().VDI_vm_off, args=(
        vm_message.VIP,
        VDI_admin,
        VDI_admin_passwd))
    p2.start()
    return return_dict_success

###VDI关闭HA和存储
@router.post(
    "/vdi/storageorHA/stop",
    summary="2、VDI关闭HA和存储",
    description="2、VDI关闭HA和存储，成功返回True，失败返回falst",
    responses={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": None}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None, "data": None}
                }
            },
        }
    }
)
async def stop_vdi_storageorHA(ha_message: VDI_STOP_STORAGEORHA):
    vdi_login = VDI().VDI_login(
        ha_message.VIP,
        ha_message.Platform_Account,
        ha_message.Platform_Pwd,
        ha_message.Platform_Version,
    )
    try:
        if vdi_login[0] == False:
            quit()
        session = vdi_login[2]
        header = vdi_login[1]
    except Exception as e:
        return False

    p2 = Process(target=VDI().VDI_stop_host_storageorHA, args=(
            ha_message.VIP,
            VDI_admin,
            VDI_admin_passwd,
            ha_message.Root_Pwd,
            header,
            session,))
    p2.start()
    return return_dict_success


###关闭bT
@router.post(
    "/vdi/BT/stop", summary="3、VDI关闭BT服务", description="3、VDI关闭BT服务，成功返回True，失败返回falst",responses=return_model,
)
async def stop_vdi_bt(bt_message: VDI_STOP_BT):
    p2 = Process(target= VDI().VDI_stop_BT, args=(

        bt_message.VIP,bt_message.Master_IP, bt_message.SSH_Port, bt_message.Root_Pwd))
    p2.start()
    return return_dict_success

###关闭镜像存储
@router.post(
    "/vdi/images/storage/stop",
    summary="4、VDI关闭镜像存储",
    description="4、VDI关闭镜像存储，成功返回True，失败返回falst",
    responses=return_model,
)
async def stop_vdi_images_storage(images_storage_message: VDI_STOP_IMAGES_STORAGE):
    vdi_login = VDI().VDI_login(
        images_storage_message.VIP,
        images_storage_message.Platform_Account,
        images_storage_message.Platform_Pwd,
        images_storage_message.Platform_Version,
    )

    try:
        if vdi_login[0] == False:

            quit()
        session = vdi_login[2]

        header = vdi_login[1]

    except Exception as e:

        return False

    p2 = Process(target= VDI().VDI_stop_images_storage, args=(
        images_storage_message.VIP, header, session))
    p2.start()
    return return_dict_success


###VDI 升级
@router.post(
    "/vdi/update/start",
    summary="5、执行VDI升级脚本",
    description="5、执行VDI升级脚本，成功返回True，失败返回falst",
    responses=return_model,
)
async def start_vdi_update(update_message: START_VDI_UPDATE):
    vdi_login = VDI().VDI_login(
        update_message.VIP,
        update_message.Platform_Account,
        update_message.Platform_Pwd,
        update_message.Platform_Version,
    )

    try:
        if vdi_login[0] == False:
            quit()
        session = vdi_login[2]
        header = vdi_login[1]
    except Exception as e:

        return False
    p2 = Process(target=VDI().VDI_update_cmd, args=(
        update_message.Master_IP,
        update_message.SSH_Port,
        update_message.Root_Pwd,
        update_message.Upgrade_FileNams,
        update_message.VIP,
        header,
        session))
    p2.start()
    return return_dict_success

###VDI验收
@router.post(
    "/acceptance",
    summary="6、VDI升级完成验收升级任务执行状态",
    description="VDI升级后验收阶段，成功返回True，失败返回falst",
    responses={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": {"New_Workspace_Version": "str","New_CVK_Version": "str"}}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None, "data": None}
                }
            },
        }
    }
)
async def vdi_update_acceptance(acceptance_message: VDI_UPDATE_ACCEPTANCE):
    p2 = Process(target=VDI().VDI_update_acceptance, args=(
        acceptance_message.VIP,
        acceptance_message.Master_IP,
        acceptance_message.SSH_Port,
        acceptance_message.Root_Pwd,))
    p2.start()
    return return_dict_success

###重启VDI主机
@router.post(
    "/vdi/hosts/restart",
    summary="7、VDI待升级完成后重启主机",
    description="VDI主机重启，成功返回True，失败返回falst",
    responses=return_model,
)
async def vdi_shutdown(shutdown_message: VDI_SHUTDOWN):
    p2 = Process(target=VDI().VDI_shutdowm, args=(
            shutdown_message.VIP,
            VDI_admin,
            VDI_admin_passwd,
            shutdown_message.SSH_Port,
            shutdown_message.Root_Pwd,
            shutdown_message.New_CVK_Version,))
    p2.start()
    return return_dict_success

###等待主机重启
@router.post(
    "/vdi/restart/status",
    summary="8、VDI主机重启后检测主机服务启动是否正常",
    description="等待主机重启，成功返回True，失败返回异常主机状态列表hosts_status_list",
    responses={
        200: {
            "description": "Successful Response docs",
            "content": {
                "application/json": {
                    "example": {"statusCode": 200, "message": "对于返回信息的描述", "result": True, "debug": None, "data": None}
                }
            },
        },
        202: {
            "description": "Successful Response But the task is out of order",
            "content": {
                "application/json": {
                    "example": {"statusCode": 202, "message": "对于返回信息的描述", "result": False, "debug": None, "data": {"hosts_status_off_list": "list"}}
                }
            },
        }
    }
)
async def vdi_restart_status(status_message: VDI_RESTART_STATUS):
    p2 = Process(target=VDI().VDI_restart_status, args=(
        status_message.VIP, VDI_admin, VDI_admin_passwd,status_message.SSH_Port,status_message.Root_Pwd))
    p2.start()
    return return_dict_success

###VDI主机开启HA和共享存储
@router.post(
    "/vdi/storageorHA/start",
    summary="9、VDI开启存储和HA接口",
    description="VDI开启HA和存储，成功返回True，失败返回falst",
    responses=return_model,
)
async def vdi_start_storageorha(storageorha_message: VDI_START_STORAGEORHA):
    vdi_login = VDI().VDI_login(
        storageorha_message.VIP,
        storageorha_message.Platform_Account,
        storageorha_message.Platform_Pwd,
        storageorha_message.Platform_Version,
    )

    try:
        if vdi_login[0] == False:

            return False
        session = vdi_login[2]
        header = vdi_login[1]
    except Exception as e:

        return False
    p2 = Process(target=VDI().VDI_start_host_storageorHA, args=(
            storageorha_message.VIP,
            VDI_admin,
            VDI_admin_passwd,
            storageorha_message.Root_Pwd,
            header,
            session,))
    p2.start()
    return return_dict_success



# #开启VDI虚机
@router.post(
    "/vdi/vm/start",
    summary="10、VDI开启虚机接口",
    description="开启虚拟机，成功返回True，失败返回falst",
    responses=return_model,
)
async def vdi_start_vm(vm_message: VDI_START_VM):
    p2 = Process(target=VDI().VDI_start_vm, args=(
        vm_message.VIP,
        VDI_admin,
        VDI_admin_passwd,
        vm_message.Master_IP,
        vm_message.SSH_Port,
        vm_message.Root_Pwd,))
    p2.start()
    return return_dict_success

#升级网关
@router.post(
    "/vdi/gateway/update",
    summary="升级网关",
    description="升级网关，成功返回True，失败返回falst",
    responses=return_model,
)
async def vdi_gateway_update(gateway_message: UPDATE_GATEWAY):
    p2 = Process(target=VDI().VDI_update_Gateway, args=(gateway_message.Gateway_IP,gateway_message.SSH_Port,gateway_message.Gateway_Passwd,gateway_message.To_Upgrade_Versions))
    p2.start()
    return return_dict_success

@router.get("/")
async def root():
    print(data_host_ip)
    return {"message": "Hello World"}


def CkeckConfig():
    client = nacos.NacosClient(SERVER_ADDRESSES, namespace=NAMESPACE, username=NacosUser, password=NacosPasswd)
    CONFIG = GlobalConf().get_config()
    while True:
        if client.get_config("py_config_%s.json" % (PY_CONFIG), PY_CONFIG, 60) == None:
            client.publish_config("py_config_%s.json" % (PY_CONFIG), PY_CONFIG, json.dumps(CONFIG), timeout=60,
                                  config_type="json")
        content = client.get_config("py_config_%s.json" % (PY_CONFIG), PY_CONFIG, 60)

        CONFIG = json.loads(content)
        with contextlib.closing(mmap.mmap(-1, 1024, tagname='cnblogs', access=mmap.ACCESS_WRITE)) as mem:
            mem.seek(0)
            # 数据文件服务器
            data_host_ip=CONFIG["data_host_ip"]
            mem.write(bytes(data_host_ip))
            mem.flush()
            time.sleep(0.5)



if __name__ == "__main__":

    p1 = Process(target=VDIorCAS().Send_Health_Beat, args=()).start()
    uvicorn.run(router, host="0.0.0.0", port=int(NacosPort))












