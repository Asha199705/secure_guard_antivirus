import pika

connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()

channel.queue_declare(queue='scan_queue')

def send_file_path(file_path):
    channel.basic_publish(exchange='',
                          routing_key='scan_queue',
                          body=file_path)
    print(f" [x] Sent {file_path}")

send_file_path('/path/to/your/file')
connection.close()
