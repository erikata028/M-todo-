# M-todo-
import requests, re, json

ipsAlmacenadas = []
fechasIp = {}

def extractFromRegularExpression(regex, data):
    if data:
        return re.findall(regex, data)
    return None

# Obtenemos el contenido del log de Apache
data = requests.get("https://raw.githubusercontent.com/elastic/examples/refs/heads/master/Common%20Data%20Formats/apache_logs/apache_logs").text

# Expresión regular que captura la IP, fecha, hora, método HTTP y la URL solicitada
regex = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s-\s-\s\[(\d{2}/[a-zA-Z]{3}/\d{4}):(\d{2}:\d{2}:\d{2})\s.*\] \"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s([^\s]+)"

# Extraemos los resultados del log
resultado = extractFromRegularExpression(regex, data)

for ip, fecha, hora, metodo, url in resultado:
    if metodo == "GET":  # Filtramos solo las solicitudes GET
        if ip not in ipsAlmacenadas:
            ipsAlmacenadas.append(ip)
            fechasIp[ip] = []
        fechasIp[ip].append(f"{fecha} {hora} {metodo} {url}")
        print(f"IP: {ip} Fecha: {fecha} Hora: {hora} Metodo: {metodo} URL: {url}")
