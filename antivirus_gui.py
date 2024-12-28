import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox
import os
import psutil
import hashlib
import time


class ModernAntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureGuard Antivirus")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f5f5f5")

        # Создание основного макета
        self.create_main_layout()

        # Создание боковой панели
        self.create_sidebar()

        # Создание верхней панели инструментов
        self.create_toolbar()

        # Создание областей контента
        self.create_scan_area()
        self.create_process_details_area()
        self.create_monitor_area()

    def create_main_layout(self):
        """Создаёт основной макет приложения."""
        self.main_container = tk.Frame(self.root, bg="#f5f5f5")
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.main_container.columnconfigure(1, weight=1)
        self.main_container.rowconfigure(2, weight=1)

    def create_sidebar(self):
        """Создаёт боковую панель с кнопками навигации."""
        sidebar = tk.Frame(self.main_container, width=200, bg="#e0e0e0", relief=tk.RAISED, borderwidth=1)
        sidebar.grid(row=0, column=0, rowspan=4, sticky="nsew", padx=(0, 10))
        sidebar.grid_propagate(False)

        buttons = [
            ("Scan", "🔍", None),  # Placeholder
            ("Monitor", "💻", None),  # Placeholder
            ("Logs", "📋", self.show_logs),
            ("Settings", "⚙️", self.show_settings),  # Settings button
        ]

        for text, emoji, command in buttons:
            tk.Button(
                sidebar,
                text=f"{emoji} {text}",
                bg="#d3d3d3",
                fg="black",
                font=("Arial", 12),
                anchor="w",
                relief=tk.FLAT,
                activebackground="#0078d7",
                activeforeground="white",
                command=command
            ).pack(fill=tk.X, padx=5, pady=5)

    def create_toolbar(self):
        """Создаёт верхнюю панель инструментов."""
        toolbar = tk.Frame(self.main_container, bg="#e0e0e0")
        toolbar.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

        buttons = [
            ("Scan File", "🔍", self.start_scan),
            ("System Scan", "💻", self.show_monitor),
            ("Quarantine", "🔒", self.show_quarantine_info)  # Верхняя кнопка Quarantine остаётся
        ]

        for text, emoji, command in buttons:
            tk.Button(
                toolbar,
                text=f"{emoji} {text}",
                bg="#d3d3d3",
                fg="black",
                font=("Arial", 10),
                command=command,
                relief=tk.RAISED,
                activebackground="#0078d7",
                activeforeground="white"
            ).pack(side=tk.LEFT, padx=5, pady=5)

    def create_scan_area(self):
        """Создаёт область для отображения результатов сканирования."""
        scan_frame = tk.Frame(self.main_container, bg="#f5f5f5")
        scan_frame.grid(row=1, column=1, sticky="nsew", padx=10, pady=5)

        self.scan_progress = ttk.Progressbar(
            scan_frame,
            orient=tk.HORIZONTAL,
            length=600,
            mode='determinate'
        )
        self.scan_progress.pack(fill=tk.X, pady=10)

        self.scan_results = scrolledtext.ScrolledText(
            scan_frame,
            height=10,
            bg="#ffffff",
            fg="black",
            font=("Consolas", 10)
        )
        self.scan_results.pack(fill=tk.BOTH, expand=True)

    def create_process_details_area(self):
        """Создаёт область для отображения деталей процесса."""
        details_frame = tk.Frame(self.main_container, bg="#f5f5f5", relief=tk.RAISED, borderwidth=1)
        details_frame.grid(row=2, column=1, sticky="nsew", padx=10, pady=5)

        self.process_details_text = tk.Text(
            details_frame,
            height=10,
            bg="#ffffff",
            fg="black",
            font=("Consolas", 10)
        )
        self.process_details_text.pack(fill=tk.BOTH, expand=True)

        filter_frame = tk.Frame(details_frame, bg="#f5f5f5")
        filter_frame.pack(fill=tk.X, pady=5)

        self.filter_entry = ttk.Entry(filter_frame, width=10)
        self.filter_entry.pack(side=tk.LEFT, padx=5)

        self.filter_button = ttk.Button(
            filter_frame,
            text="Filter Process",
            command=self.show_process_details
        )
        self.filter_button.pack(side=tk.LEFT, padx=5)

    def create_monitor_area(self):
        """Создаёт область для мониторинга системы."""
        monitor_frame = tk.Frame(self.main_container, bg="#f5f5f5")
        monitor_frame.grid(row=3, column=1, sticky="nsew", padx=10, pady=5)

        self.process_tree = ttk.Treeview(
            monitor_frame,
            columns=('PID', 'Name', 'CPU', 'Memory'),
            show='headings'
        )
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Name', text='Process Name')
        self.process_tree.heading('CPU', text='CPU Usage')
        self.process_tree.heading('Memory', text='Memory Usage')
        self.process_tree.pack(fill=tk.BOTH, expand=True)

        refresh_button = ttk.Button(
            monitor_frame,
            text="Refresh Processes",
            command=self.show_monitor
        )
        refresh_button.pack(fill=tk.X, pady=5)

    def show_process_details(self):
        """Показывает детальную информацию о процессе."""
        pid = self.filter_entry.get().strip()
        self.process_details_text.delete(1.0, tk.END)

        if not pid.isdigit():
            self.process_details_text.insert(tk.END, "Invalid PID. Please enter a numeric PID.\n")
            return

        try:
            process = psutil.Process(int(pid))
            details = {
                "PID": process.pid,
                "Name": process.name(),
                "CPU Usage": f"{process.cpu_percent(interval=0.1)}%",
                "Memory Info (RSS)": f"{process.memory_info().rss / 1024 / 1024:.2f} MB",
                "Memory Info (VMS)": f"{process.memory_info().vms / 1024 / 1024:.2f} MB",
                "User": process.username(),
                "Status": process.status(),
                "Created Time": time.ctime(process.create_time()),
                "Executable": process.exe(),
                "MD5 Hash": self.get_file_hash(process.exe())
            }

            for key, value in details.items():
                self.process_details_text.insert(tk.END, f"{key}: {value}\n")
        except psutil.NoSuchProcess:
            self.process_details_text.insert(tk.END, f"No process found with PID {pid}.\n")
        except Exception as e:
            self.process_details_text.insert(tk.END, str(e) + "\n")

    def get_file_hash(self, file_path):
        """Возвращает MD5 хэш файла."""
        try:
            with open(file_path, "rb") as f:
                hash_md5 = hashlib.md5()
                while chunk := f.read(4096):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return "N/A"

    def start_scan(self):
        """Метод для сканирования файлов."""
        file_path = filedialog.askopenfilename(title="Select file to scan")
        if file_path:
            self.simulate_scan(file_path)

    def simulate_scan(self, file_path):
        """Сканирование файла с помощью ClamAV."""
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Scanning file: {file_path}...\n")
        self.scan_progress.start()

        try:
            result = os.popen(f"clamscan \"{file_path}\"").read()
            self.scan_progress.stop()
            self.scan_results.insert(tk.END, result + "\n")

            if "FOUND" in result:
                self.scan_results.insert(tk.END, "Threat detected!\n", "red")
                self.scan_results.tag_config("red", foreground="red")
            elif "OK" in result:
                self.scan_results.insert(tk.END, "No threats found.\n", "green")
                self.scan_results.tag_config("green", foreground="green")
            else:
                self.scan_results.insert(tk.END, "An error occurred during scanning.\n", "orange")
                self.scan_results.tag_config("orange", foreground="orange")
        except Exception as e:
            self.scan_progress.stop()
            self.scan_results.insert(tk.END, f"Error scanning file {file_path}: {e}\n", "red")
            self.scan_results.tag_config("red", foreground="red")

    def show_monitor(self):
        """Отображает системные процессы."""
        processes = [
            (p.info['pid'], p.info['name'], p.info['cpu_percent'], p.memory_info().rss // 1024)
            for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info'])
        ]
        for row in self.process_tree.get_children():
            self.process_tree.delete(row)
        for process in processes:
            self.process_tree.insert("", tk.END, values=process)

    def show_logs(self):
        """Displays the content of the log file in the content area."""
        log_file_path = "rabbitmq_antivirus.log"
        try:
            with open(log_file_path, "r") as log_file:
                log_content = log_file.read()
            self.scan_results.delete(1.0, tk.END)
            self.scan_results.insert(tk.END, log_content)
        except FileNotFoundError:
            self.scan_results.delete(1.0, tk.END)
            self.scan_results.insert(tk.END, "Log file not found.")
        except Exception as e:
            self.scan_results.delete(1.0, tk.END)
            self.scan_results.insert(tk.END, f"Error reading log file: {e}")

    def show_settings(self):
        """Отображает окно настроек с информацией о приложении."""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        settings_window.configure(bg="#f5f5f5")

        info = [
            ("Address", "А.Пушкина 11"),
            ("Phone", "87058262527"),
            ("Version", "SecureGuard Antivirus v1.0.0"),
            ("Support Email", "support@secureguard.com"),
            ("License", "Free Edition"),
        ]

        for label, value in info:
            tk.Label(
                settings_window,
                text=f"{label}:",
                font=("Arial", 12, "bold"),
                bg="#f5f5f5"
            ).pack(anchor="w", padx=10, pady=5)
            tk.Label(
                settings_window,
                text=value,
                font=("Arial", 12),
                bg="#f5f5f5"
            ).pack(anchor="w", padx=20)

        tk.Button(
            settings_window,
            text="Close",
            command=settings_window.destroy,
            bg="#d3d3d3",
            font=("Arial", 10),
            relief=tk.RAISED
        ).pack(side=tk.BOTTOM, pady=10)

    def show_quarantine_info(self):
        """Отображает информацию о карантине."""
        messagebox.showinfo(
            "Quarantine",
            "Заражённые файлы будут перемещены в карантин для дальнейшего анализа."
        )


def main():
    root = tk.Tk()
    app = ModernAntivirusApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
