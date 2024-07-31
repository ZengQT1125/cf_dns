import requests
import traceback
import time
import os
import json
import requests
from bs4 import BeautifulSoup

# API 密钥
CF_API_TOKEN    =   os.environ["CF_API_TOKEN"]
CF_ZONE_ID      =   os.environ["CF_ZONE_ID"]
CF_DNS_NAME     =   os.environ["CF_DNS_NAME"]

#CF_API_TOKEN    =   "1Qu94vrjm1XZQtslS8RwF-CLH0k9B_5r9-uFQYMr"
#CF_ZONE_ID      =   "6ac25611a42697d493622342cdb8fffb"
#CF_DNS_NAME     =   "dns.164746.xyz"

# pushplus_token
PUSHPLUS_TOKEN  =   "1111"



headers = {
    'Authorization': f'Bearer {CF_API_TOKEN}',
    'Content-Type': 'application/json'
}

def extract_and_save_ips(url, output_file='ip_list.txt'):
    try:
        response = requests.get(url)
        response.raise_for_status()
        page_content = response.text

        print("Page content fetched")  # 调试信息
        soup = BeautifulSoup(page_content, 'html.parser')
        ip_table = soup.find('table')

        if ip_table:
            print("Table found")  # 调试信息
            ip_list = []
            for row in ip_table.find_all('tr')[1:]:
                cols = row.find_all('td')
                if len(cols) >= 1:
                    ip_address = cols[0].text.strip()
                    ip_list.append(f"{ip_address}:443#")
                    print(f"IP found: {ip_address}")

            if ip_list:
                try:
                    workspace = os.getenv('GITHUB_WORKSPACE', '')
                    output_path = os.path.join(workspace, output_file)
                    with open(output_file, 'a') as f:  # 使用追加模式
                        for ip in ip_list:
                            f.write(f"{ip}\n")
                    print(f"IP addresses saved to {output_file}")
                except IOError as e:
                    print(f"Error writing to file {output_path}: {e}")
            else:
                print("No IP addresses found.")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching IP addresses: {e}")





def get_cf_speed_test_ip(timeout=10, max_retries=5):
    for attempt in range(max_retries):
        try:
            # 发送 GET 请求，设置超时
            response = requests.get('https://ip.164746.xyz/ipTop.html', timeout=timeout)
            # 检查响应状态码
            if response.status_code == 200:
                return response.text
        except Exception as e:
            traceback.print_exc()
            print(f"get_cf_speed_test_ip Request failed (attempt {attempt + 1}/{max_retries}): {e}")
    # 如果所有尝试都失败，返回 None 或者抛出异常，根据需要进行处理
    return None

# 获取 DNS 记录
def get_dns_records(name):
    def_info = []
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        records = response.json()['result']
        for record in records:
            if record['name'] == name:
                def_info.append(record['id'])
        return def_info
    else:
        print('Error fetching DNS records:', response.text)

# 更新 DNS 记录
def update_dns_record(record_id, name, cf_ip):
    url = f'https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/dns_records/{record_id}'
    data = {
        'type': 'A',
        'name': name,
        'content': cf_ip
    }

    response = requests.put(url, headers=headers, json=data)

    if response.status_code == 200:
        print(f"cf_dns_change success: ---- Time: " + str(
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + " ---- ip：" + str(cf_ip))
        return "ip:" + str(cf_ip) + "解析" + str(name) + "成功"
    else:
        traceback.print_exc()
        print(f"cf_dns_change ERROR: ---- Time: " + str(
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + " ---- MESSAGE: " + str(e))
        return "ip:" + str(cf_ip) + "解析" + str(name) + "失败"

# 消息推送
def push_plus(content):
    url = 'http://www.pushplus.plus/send'
    data = {
        "token": PUSHPLUS_TOKEN,
        "title": "IP优选DNSCF推送",
        "content": content,
        "template": "markdown",
        "channel": "wechat"
    }
    body = json.dumps(data).encode(encoding='utf-8')
    headers = {'Content-Type': 'application/json'}
    requests.post(url, data=body, headers=headers)

def main():
    # 抓取并保存 IP 地址
    extract_and_save_ips('https://ip.164746.xyz/')   
    
    # 文件已自动关闭
    # 获取最新优选IP
    ip_addresses_str = get_cf_speed_test_ip()
    ip_addresses = ip_addresses_str.split(',')
    dns_records = get_dns_records(CF_DNS_NAME)
    push_plus_content = []

    # 检查 dns_records 是否为空
    if not dns_records:
        print("Error: No DNS records found for", CF_DNS_NAME)
        return

    # 确保 IP 地址数量不超过域名记录数量
    num_ips = min(len(ip_addresses), len(dns_records))

    # 遍历有效 IP 地址
    for index in range(num_ips):
        ip_address = ip_addresses[index]
        # 执行 DNS 变更
        dns = update_dns_record(dns_records[index], CF_DNS_NAME, ip_address)
        push_plus_content.append(dns)

    push_plus('\n'.join(push_plus_content))

if __name__ == '__main__':
    main()
