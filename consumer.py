import pika
import os
import psutil
import pandas as pd
import logging
from logging.handlers import RotatingFileHandler

# Настройка логирования
logger = logging.getLogger('AntivirusConsumer')
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('antivirus_consumer.log', maxBytes=2000000, backupCount=5)
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

def scan_file(file_path):
    try:
        result = os.system(f'clamscan {file_path}')
        return result
    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        return None

def monitor_system():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'memory_info', 'cpu_percent']):
        try:
            proc_info = proc.info
            proc_info['memory'] = proc.memory_info().rss / (1024 * 1024)  # in MB
            proc_info['cpu'] = proc.cpu_percent(interval=1)
            processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def display_processes_as_table(processes):
    df = pd.DataFrame(processes)
    return df

def create_connection():
    return pika.BlockingConnection(pika.ConnectionParameters('localhost', heartbeat=600))

connection = create_connection()
channel = connection.channel()

channel.queue_declare(queue='scan_queue')

def callback(ch, method, properties, body):
    file_path = body.decode()
    logger.info(f" [x] Received {file_path}")
    
    # Monitor system before scan
    processes_before = monitor_system()
    logger.info(f" [x] System processes before scan:\n {display_processes_as_table(processes_before)}")
    
    result = scan_file(file_path)
    if result is not None:
        logger.info(f" [x] Scan result: {result}")
    
    # Monitor system after scan
    processes_after = monitor_system()
    logger.info(f" [x] System processes after scan:\n {display_processes_as_table(processes_after)}")

while True:
    try:
        channel.basic_consume(queue='scan_queue', on_message_callback=callback, auto_ack=True)
        logger.info(' [*] Waiting for messages. To exit press CTRL+C')
        channel.start_consuming()
    except pika.exceptions.StreamLostError as e:
        logger.error(f"Connection lost, retrying... {e}")
        time.sleep(5)
        connection = create_connection()
        channel = connection.channel()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        break
