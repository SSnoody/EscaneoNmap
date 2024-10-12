import nmap
from CorreoElectronico import CorreoElectronico
import re

class P6:
    def __init__(self, ipObjetivo):
        self.ipObjetivo = ipObjetivo
        self.nm = nmap.PortScanner()
        self.puertosAbiertos = "-p "
        self.destinatarioCorreo = ""

    def validarIP(self):
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not pattern.match(self.ipObjetivo):
            raise ValueError(f"La IP {self.ipObjetivo} no es válida.")

    def escanearPuertos(self):
        try:
            self.validarIP()
            resultados = self.nm.scan(hosts=self.ipObjetivo, arguments="-sT -n -Pn -T4")
            return resultados
        except ValueError as e:
            print(e)
            return None
        except Exception as e:
            print(f"Error al escanear puertos: {e}")
            return None

    def generarInforme(self, resultados):
        if resultados:
            informe = f"\nHost : {self.ipObjetivo}\n"
            informe += f"State : {self.nm[self.ipObjetivo].state()}\n"
            for proto in self.nm[self.ipObjetivo].all_protocols():
                informe += f"Protocol : {proto}\n\n"
                lport = self.nm[self.ipObjetivo][proto].keys()
                sorted(lport)
                for port in lport:
                    informe += f"port : {port}\tstate : {self.nm[self.ipObjetivo][proto][port]['state']}\n"
                    if self.puertosAbiertos == "-p ":
                        self.puertosAbiertos += str(port)
                    else:
                        self.puertosAbiertos += "," + str(port)
            informe += f"\nPuertos abiertos: {self.puertosAbiertos}{self.ipObjetivo}"
            return informe
        else:
            return "No se pudo realizar el escaneo."

    def obtenerDestinatarioCorreo(self):
        while True:
            correo = input("Ingrese la dirección de correo para enviar el informe: ")
            if "@" not in correo or "." not in correo.split("@")[1]:
                print("Dirección de correo inválida. Intente nuevamente.")
            else:
                self.destinatarioCorreo = correo
                break

def enviarInformePorCorreo(ipObjetivo):
    scanner = P6(ipObjetivo)
    resultados = scanner.escanearPuertos()
    informe = scanner.generarInforme(resultados)
    
    scanner.obtenerDestinatarioCorreo()
    
    asunto = f"Informe de escaneo de puertos para {ipObjetivo}"
    mensaje = informe

    correo = CorreoElectronico()
    correo.enviarCorreo(scanner.destinatarioCorreo, asunto, mensaje)

# Ejemplo de uso
ipObjetivo = input("[+] IP Objetivo ==> ")
enviarInformePorCorreo(ipObjetivo)
