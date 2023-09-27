import concurrent
from concurrent import futures
import socket
import time
from colorama import Fore
from datetime import datetime


def init_scan(target, now):
    ports = 65535
    open_ports = []
    def scaning(port):

        print("\r" + 'Analizando Puerto : %s/%s [%s%s] %.2f%%' % (port, ports, "▓" * int(port * 25 / ports),
                                                    "▒" * (25 - int(port * 25 / ports)),
                                float(port / ports * 100)), end="")

        # Creamos el Socket para la conexión
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Definimos tiempo máximo de espera a la conexion
        socket.setdefaulttimeout(0.15)
        # creamos la conexion
        result = s.connect_ex((target, port))
        # Si resulta victorioisa la conexion informamos de puerto abierto
        if result == 0:
            open_ports.append(port)
        s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        futures = []
        for port in range(1, ports + 1):
            try: 
                futures.append(executor.submit(scaning, port))
            # Excepciones del código
            except KeyboardInterrupt:
                end = datetime.now()
                elapsed = end - now
                print(Fore.YELLOW + '\n\nAnálisis interrumpido en el puerto {}.'.format(port))
                break
            except Exception as err:
                print("Error inesperado : {}".format(err))

    print(open_ports)

init_scan('127.0.0.1', datetime.now())