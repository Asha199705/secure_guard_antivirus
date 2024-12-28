from scapy.all import *

# Целевой IP-адрес и порт
target_ip = "10.0.2.15"
target_port = 80  # Замените порт на нужный (например, 80 для HTTP)

# Создание пакета с кастомной нагрузкой
packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S') / Raw(load=b"TestPayloadInjection")

# Отправка пакета
send(packet, count=1)  # Отправляем 1 пакет
print(f"Packet sent to {target_ip}:{target_port}")
