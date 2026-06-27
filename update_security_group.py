# 自动添加当前的动态ip, 到阿里云 ECS 安全组

#coding=utf-8
import json
import os
import sys
import requests
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkecs.request.v20140526 import DescribeSecurityGroupAttributeRequest

# 读取配置文件，环境变量优先级更高（可覆盖配置文件）
def load_config():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config.py")

    if os.path.exists(config_path):
        import importlib.util
        spec = importlib.util.spec_from_file_location("config", config_path)
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        print("已从 config.py 加载配置")
    else:
        print("未找到 config.py，将使用环境变量")
        config = None

    def get_cfg(name, default=""):
        env_val = os.environ.get(name)
        if env_val is not None:
            return env_val
        if config and hasattr(config, name):
            return getattr(config, name)
        return default

    return {
        "aliyun_ak":        get_cfg("aliyun_ak"),
        "aliyun_sk":        get_cfg("aliyun_sk"),
        "region_id":        get_cfg("region_id"),
        "security_group_id": get_cfg("security_group_id"),
        "port_range":       get_cfg("port_range"),
        "description":      get_cfg("description", "auto added"),
        "priority":         int(get_cfg("priority", 2)),
    }

cfg = load_config()
aliyun_ak = cfg["aliyun_ak"]
aliyun_sk = cfg["aliyun_sk"]
region_id = cfg["region_id"]
security_group_id = cfg["security_group_id"]
port_range = cfg["port_range"]
description = cfg["description"]
default_priority = cfg["priority"]

if not security_group_id or not aliyun_ak or not aliyun_sk:
    print("请确保在 config.py 或环境变量中设置 security_group_id, aliyun_ak, aliyun_sk, region_id, port_range")
    sys.exit(-1)

client = AcsClient(
    aliyun_ak,  # 此处填写你刚才创建的RAM子账号的AccessKeyId
    aliyun_sk,  # 此处填写你刚才创建的RAM子账号的AccessKeySecret
    region_id  # 此处填写你要管理的区域
)

#获取外网ip地址（多服务兜底）
def get_now_ip():
    import re
    headers = {"User-Agent": "curl/10.0"}
    services = [
         ("https://api-ipv4.ip.sb/ip", "text"),
         ("https://ipv4.ifconfig.me", "text")
     ]
    for url, mode in services:
        try:
            response = requests.get(url, headers=headers, timeout=5)
            text = response.text.strip()
            if mode == "text":
                now_ip = text
            elif mode == "regex":
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
                now_ip = match.group(1) if match else ""
            elif mode == "json":
                import json
                now_ip = json.loads(text).get("origin", "").split(",")[0].strip()
            if now_ip:
                print("current ip address:%s (via %s)" % (now_ip, url))
                return now_ip
        except Exception as e:
            print("  %s failed: %s" % (url, e))
    return ""

#根据ip和port移除规则
def remove_ip(securityGroupId, sourceCidrIp, portRange):
    request = CommonRequest()
    request.set_accept_format('json')
    request.set_method('POST')
    request.set_protocol_type('https')
    request.set_domain('ecs.aliyuncs.com')
    request.set_version('2014-05-26')
    request.set_action_name('RevokeSecurityGroup')
    request.add_query_param('RegionId', region_id)
    request.add_query_param('SecurityGroupId', securityGroupId)
    request.add_query_param('SourceCidrIp', sourceCidrIp)
    request.add_query_param('PortRange', portRange)
    request.add_query_param('IpProtocol', 'tcp')
    request.add_query_param('NicType', 'intranet')
    response = client.do_action_with_exception(request)

#添加指定的IP地址到安全组中:
def add_ip(securityGroupId, sourceCidrIp, portRange, priority):
    request = CommonRequest()
    request.set_accept_format('json')
    request.set_method('POST')
    request.set_protocol_type('https')
    request.set_domain('ecs.aliyuncs.com')
    request.set_version('2014-05-26')
    request.set_action_name('AuthorizeSecurityGroup')
    request.add_query_param('RegionId', region_id)
    request.add_query_param('SecurityGroupId', securityGroupId)
    request.add_query_param('SourceCidrIp', sourceCidrIp)
    request.add_query_param('PortRange', portRange)
    request.add_query_param('Priority', priority)
    request.add_query_param('IpProtocol', 'tcp')
    request.add_query_param('NicType', 'intranet')
    request.add_query_param("Description", description)
    response = client.do_action_with_exception(request)

print("1.query current security group...")
request = DescribeSecurityGroupAttributeRequest.DescribeSecurityGroupAttributeRequest()
request.set_SecurityGroupId(security_group_id)


response = client.do_action_with_exception(request)
responsepermissions = json.loads(response)
permissions = responsepermissions.get("Permissions").get("Permission")
print(response.decode('utf-8'))

vpcId = responsepermissions.get("VpcId")
securityGroupNameLocal = responsepermissions.get("SecurityGroupName")
securityGroupId = responsepermissions.get("SecurityGroupId")

current_ip_in_perm_list = False

print("2.detect current ip address...")
cur_ip = get_now_ip()

print("3.remove existed priority group with specified priority...")
for perm in permissions:
    
    ## 只处理脚本自动添加的规则 (Description == "auto added")
    if perm.get("Description") != description:
        continue
    if port_range == perm.get("PortRange") and perm.get("Priority") == default_priority:
        print("Policy:%s SourceCidrIp:%s NicType:%s PortRange:%s Desc:%s" % 
          (perm.get("Policy"), perm.get("SourceCidrIp"), perm.get("NicType"), 
          perm.get("PortRange"), perm.get("Description") ))
        if cur_ip != perm.get("SourceCidrIp"):
            remove_ip(securityGroupId, perm.get("SourceCidrIp"), port_range)
        else:
            current_ip_in_perm_list = True

print("current ip:%s, current ip in permission list:%s" % (cur_ip, current_ip_in_perm_list) )

print("4.add current ip address to permission list")
if not current_ip_in_perm_list:
    # add to permission list:
    add_ip(securityGroupId, cur_ip, port_range, default_priority)