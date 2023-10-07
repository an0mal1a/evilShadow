import multiprocessing
import pprint
import services
from nmap_vscan import vscan
import socket
import tempfile

servicesInfo = tempfile.NamedTemporaryFile(delete=False)
servicesInfo.write(services.returnValue())
servicesInfo.close()

# Variables Globales
global_timeout = 15
# Crear un proceso para cada puerto y configurar límites de tiempo individuales
processes = []
result_queue = multiprocessing.Queue()
nmap = vscan.ServiceScan(servicesInfo.name)

# Lista de puertos a escanear
ip = "www.apache.org"
ports = [80,443]

# Función para realizar el escaneo en un puerto con un límite de tiempo
def scan_port(port, result_queue):
    try:
        result = nmap.scan(ip, port, "tcp")
        result_queue.put((port, str(result)))
        # sock.send(result) ENVIAMOS PARA QUE VEA COMO VA EL ESCANEO
    except socket.timeout as e:
        result_queue.put((port, f"Max Timeout reached: {str(e)}"))
    except ConnectionRefusedError as e:
        result_queue.put((port, f"Closed: {str(e)}"))
    except ConnectionResetError as e:
        result_queue.put((port, f"Error: {str(e)}"))
    except Exception as e:
        result_queue.put((port, f"Error: {str(e)}"))


def processData():
    # Recolectar resultados de la cola
    responses = []
    formed = {ip: {}}
    while not result_queue.empty():
        port, result = result_queue.get()
        formed[ip][port] = result

    responses.append(formed)
    return responses


def initScanServices():
    for port in ports:
        process = multiprocessing.Process(target=scan_port, args=(port, result_queue))
        process.start()
        processes.append(process)

    i = 0
    # Esperar a que todos los procesos terminen o los termina si exceden el tiempo de espera
    for process in processes:
        process.join(timeout=global_timeout)
        if process.is_alive():
            process.terminate()
        i += 1


def startServices():
    initScanServices()
    data = processData()
    print(len(str(data)))
    pprint.pprint(data)

if __name__ == "__main__":
    startServices()