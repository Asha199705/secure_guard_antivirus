import pika
from scapy.all import sniff, IP, Raw

# Настройка RabbitMQ
rabbitmq_host = 'localhost'
queue_name = 'network_injections'

# Установление соединения с RabbitMQ
connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
channel = connection.channel()

# Создание очереди
channel.queue_declare(queue=queue_name)

# Функция для отправки данных о пакете в RabbitMQ
def send_packet_data(packet):
    if IP in packet:
        data = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "payload": bytes(packet[Raw].load).hex() if Raw in packet else None
        }
        channel.basic_publish(exchange='', routing_key=queue_name, body=str(data))
        print(f"Sent data to RabbitMQ: {data}")

# Перехват пакетов
def packet_sniffer(packet):
    if IP in packet:
        print(f"Packet detected: {packet.summary()}")
        send_packet_data(packet)

# Запуск сниффера
def start_sniffer():
    print("Starting packet sniffer...")
    sniff(filter="ip", prn=packet_sniffer, count=10)  # Перехват 10 пакетов

if __name__ == "__main__":
    try:
        start_sniffer()
    except KeyboardInterrupt:
        print("\nStopping sniffer...")
    finally:
        connection.close()
