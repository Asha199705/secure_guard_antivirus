from flask import Flask, request, jsonify
import pika
import os
import psutil

app = Flask(__name__)

def send_file_path(file_path):
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    channel.queue_declare(queue='scan_queue')
    channel.basic_publish(exchange='',
                          routing_key='scan_queue',
                          body=file_path)
    connection.close()
    return "File path sent to scan queue"

def scan_file(file_path):
    result = os.system(f'clamscan {file_path}')
    return result

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

@app.route('/scan', methods=['POST'])
def scan():
    file_path = request.json.get('file_path')
    if file_path:
        send_file_path(file_path)
        return jsonify({"message": "File path sent to scan queue"})
    else:
        return jsonify({"error": "No file path provided"}), 400

@app.route('/monitor', methods=['GET'])
def monitor():
    processes = monitor_system()
    return jsonify(processes)

if __name__ == '__main__':
    app.run(debug=True)
