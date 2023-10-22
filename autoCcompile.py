import subprocess
import os, sysconfig, sys


def transformC():
    commandWin = "python -m cython --embed -o client/connection.c client/connectionC.py"
    commandLin = "python3 -m cython --embed -o client/connection.c client/connectionC.py"
    if os.name == "posix":
        os.system(commandLin)
        LinuxCompilation()
    else:
        os.system(commandWin)
        WindowsCompilation()


def WindowsCompilation():
    if os.path.exists("client/connection.c"):
        # Variables para el comando windows
        libsPath = os.path.join(sysconfig.get_path('data'), 'libs')
        includePath = sysconfig.get_path('include')
        pythonV = ".".join(map(str, sys.version_info[:2])).replace(".", "")

        # Comando formado
        if icon:
            formedPowerShellCommand = f"gcc -mwindows -municode -DMS_WIN64 client/connection.c -o {name}.exe -L{libsPath} -I{includePath} -lpython{pythonV} icon.o"
        else:
            formedPowerShellCommand = f"gcc -mwindows -municode -DMS_WIN64 client/connection.c -o {name}.exe -L{libsPath} -I{includePath} -lpython{pythonV}"
        print("\n\nExecuting command to compile: ", formedPowerShellCommand)

        cmp = subprocess.Popen(formedPowerShellCommand, shell=True)
        cmp.wait()

        print(f"\n\nCompilation was done, check for ./{name}")

    else:
        print("\n\nC module not found... try to install cython (pip install cython) or execute this command:\n\tpython -m cython --embed -o client/connection.c client/connectionC.py")


def LinuxCompilation():
    if os.path.exists("client/connection.c"):
        # Variables para el comando linux
        includePath = sysconfig.get_path('include')
        pythonV = "python" + ".".join(map(str, sys.version_info[:2]))

        # Comando formado
        if icon:
            formedBashCommand = f"gcc -Os -I{includePath} client/connection.c -o {name} $(python3-config --ldflags) -l{pythonV} icon.o"
        else:
            formedBashCommand = f"gcc -Os -I{includePath} client/connection.c -o {name} $(python3-config --ldflags) -l{pythonV}"


        print("\n\nExecuting command to compile: ", formedBashCommand)

        cmp = subprocess.Popen(formedBashCommand, shell=True)
        cmp.wait()

        print(f"\n\nCompilation was done, check for ./{name}")

    else:
        print("\n\nC module not found... try to install cython (pip install cython) or execute this command:\n\tpython -m cython --embed -o client/connection.c client/connectionC.py")


def setParameters():
    global name, icon
    input("\nEste Script solo funcionará si tienes todas las dependencias necesarias para compila el código C.\n\t\t CTRL + C to Exit | ENTER to Continue")
    name = input("Introduce un nombre para el binario [VMware-player-full-17.0.2-21581411] ---> ")
    if not name:
        name = "VMware-player-full-17.0.2-21581411"
    icon = input("Quieres el icono de VmWare? [S/n] ---> ")
    if icon.lower() == "n":
        icon = False
    else:
        icon = True
    transformC()


if __name__ == "__main__":
    try:
        setParameters()
    except KeyboardInterrupt:
        exit(0)