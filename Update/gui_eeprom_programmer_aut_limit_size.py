import os
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from tkinter import ttk
import threading
import queue
import serial
import time
from serial.tools import list_ports

class EEPROMProgrammerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EEPROM Programmer")
        # Set main window size to 1300x800.
        self.geometry("1300x800")
        self.msg_queue = queue.Queue()
        self.operation_thread = None
        self.cancel_requested = False  # Flag to cancel the operation
        self.read_data = []            # Holds read bytes for the hex dump
        self.create_widgets()

    def create_widgets(self):
        # -- Top Control Area --
        control_frame = tk.Frame(self)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        # COM Port
        tk.Label(control_frame, text="COM Port:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.com_entry = tk.Entry(control_frame)
        self.com_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.com_entry.insert(0, "COM13")
        tk.Button(control_frame, text="Select Port", command=self.select_serial_port).grid(row=0, column=2, padx=5, pady=5)

        # Offset and Limit
        tk.Label(control_frame, text="Offset:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.offset_entry = tk.Entry(control_frame)
        self.offset_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.offset_entry.insert(0, "0")
        tk.Label(control_frame, text="Limit (bytes):").grid(row=1, column=2, padx=5, pady=5, sticky="e")
        self.limit_entry = tk.Entry(control_frame)
        self.limit_entry.grid(row=1, column=3, padx=5, pady=5, sticky="w")
        self.limit_entry.insert(0, "32768")

        # File Selection (for write mode) with automatic limit update
        tk.Label(control_frame, text="File:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.file_entry = tk.Entry(control_frame, width=80)
        self.file_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        tk.Button(control_frame, text="Select File", command=self.select_file).grid(row=2, column=2, padx=5, pady=5)

        # Operation Selection
        self.op_var = tk.StringVar(value="write")
        tk.Label(control_frame, text="Operation:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        tk.Radiobutton(control_frame, text="Read", variable=self.op_var, value="read").grid(row=3, column=1, sticky="w")
        tk.Radiobutton(control_frame, text="Write", variable=self.op_var, value="write").grid(row=3, column=2, sticky="w")
        tk.Radiobutton(control_frame, text="Clear", variable=self.op_var, value="clear").grid(row=3, column=3, sticky="w")

        # Run, Cancel, and Clear Log buttons
        self.run_button = tk.Button(control_frame, text="Run Operation", command=self.start_operation)
        self.run_button.grid(row=4, column=1, padx=5, pady=10)
        self.cancel_button = tk.Button(control_frame, text="Cancel Operation", command=self.cancel_operation, state="disabled")
        self.cancel_button.grid(row=4, column=2, padx=5, pady=10)
        self.clear_log_button = tk.Button(control_frame, text="Clear Log", command=self.clear_output)
        self.clear_log_button.grid(row=4, column=3, padx=5, pady=10)

        # -- Paned Window for HEX Dump and Operational Log --
        self.pw = tk.PanedWindow(self, orient=tk.HORIZONTAL)
        self.pw.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left pane: HEX Dump
        hex_frame = tk.Frame(self.pw)
        tk.Label(hex_frame, text="HEX Dump").pack(anchor="w")
        self.hex_text = scrolledtext.ScrolledText(hex_frame, font=("Consolas", 10), width=50)
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        header = "Address   " + " ".join("{:X}".format(i) for i in range(16)) + "   Dump\n"
        header += "-" * (9 + 3*16 + 4 + 16)
        self.hex_text.insert(tk.END, header + "\n")
        self.hex_text.config(state="disabled")
        self.pw.add(hex_frame)

        # Right pane: Operational Log
        log_frame = tk.Frame(self.pw)
        tk.Label(log_frame, text="Operational Log").pack(anchor="w")
        self.log_text = scrolledtext.ScrolledText(log_frame, font=("Consolas", 10), width=50, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.pw.add(log_frame)

        # Equalize the PanedWindow panes (50-50 split)
        self.after(100, self.equalize_panels)

        # -- Bottom Progress Meter --
        progress_frame = tk.Frame(self)
        progress_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        self.progress_label = tk.Label(progress_frame, text="Progress: 0 bytes")
        self.progress_label.pack()

    def equalize_panels(self):
        total_width = self.pw.winfo_width()
        if total_width > 0:
            self.pw.sash_place(0, total_width // 2, 0)
        else:
            self.after(100, self.equalize_panels)

    def select_serial_port(self):
        ports = list_ports.comports()
        port_win = tk.Toplevel(self)
        port_win.title("Select Serial Port")
        port_win.geometry("300x250")
        lb = tk.Listbox(port_win, width=40)
        lb.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        for port in ports:
            lb.insert(tk.END, port.device)
        def choose_port():
            try:
                selection = lb.curselection()
                if selection:
                    selected_port = lb.get(selection[0])
                    self.com_entry.delete(0, tk.END)
                    self.com_entry.insert(0, selected_port)
                    port_win.destroy()
                else:
                    messagebox.showwarning("No Selection", "Please select a port from the list.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        tk.Button(port_win, text="Select", command=choose_port).pack(pady=5)

    def select_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")]
        )
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            # If in write mode, update the limit automatically based on the file size.
            if self.op_var.get() == "write":
                try:
                    file_size = os.path.getsize(file_path)
                    self.limit_entry.delete(0, tk.END)
                    self.limit_entry.insert(0, str(file_size))
                    self.append_log(f"File size is {file_size} bytes; limit updated accordingly.")
                except Exception as e:
                    self.append_log(f"Error reading file size: {e}")

    def start_operation(self):
        self.run_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        self.cancel_requested = False
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Progress: 0 bytes")
        # For read operation, clear previous hex dump (keeping header)
        if self.op_var.get() == "read":
            self.read_data = []
            self.hex_text.config(state="normal")
            header = self.hex_text.get("1.0", "2.0")
            self.hex_text.delete("1.0", tk.END)
            self.hex_text.insert(tk.END, header)
            self.hex_text.config(state="disabled")
        self.operation_thread = threading.Thread(target=self.run_operation, daemon=True)
        self.operation_thread.start()
        self.after(100, self.process_queue)

    def cancel_operation(self):
        self.cancel_requested = True
        self.append_log("Cancellation requested...")

    def clear_output(self):
        self.log_text.delete("1.0", tk.END)

    def process_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                if isinstance(msg, tuple):
                    if msg[0] == "progress_max":
                        # Set maximum to total number of bytes.
                        self.progress_bar.config(maximum=msg[1])
                    elif msg[0] == "progress":
                        self.progress_bar['value'] = msg[1]
                        self.progress_label.config(text=f"Progress: {msg[1]} bytes")
                else:
                    self.append_log(msg)
        except queue.Empty:
            pass
        if self.operation_thread.is_alive():
            self.after(100, self.process_queue)
        else:
            self.run_button.config(state="normal")
            self.cancel_button.config(state="disabled")

    def append_log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def update_hex_window(self):
        row_size = 16
        lines = []
        for i in range(0, len(self.read_data), row_size):
            row_data = self.read_data[i:i+row_size]
            hex_str = " ".join("{:02X}".format(b) for b in row_data)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else '.' for b in row_data)
            line = "{:04X}    {:<47}   {}".format(i, hex_str, ascii_str)
            lines.append(line)
        dump = "\n".join(lines)
        header = "Address   " + " ".join("{:X}".format(i) for i in range(16)) + "   Dump\n"
        header += "-" * (9 + 3*16 + 4 + 16)
        full_text = header + "\n" + dump
        self.hex_text.config(state="normal")
        self.hex_text.delete("1.0", tk.END)
        self.hex_text.insert(tk.END, full_text)
        self.hex_text.config(state="disabled")

    def run_operation(self):
        try:
            com_port = self.com_entry.get().strip()
            offset = int(self.offset_entry.get().strip() or 0)
            limit = int(self.limit_entry.get().strip() or 32768)
            operation = self.op_var.get()
            file_path = self.file_entry.get().strip()
            # Set maximum progress in bytes.
            total_bytes = limit
            self.msg_queue.put(("progress_max", total_bytes))
            processed_bytes = 0
            self.msg_queue.put(f"Connecting to {com_port} at 115200...")
            ser = serial.Serial(com_port, 115200, timeout=2)
            time.sleep(1)
            if not ser.is_open:
                self.msg_queue.put(f"Failed to open {com_port}")
                return
            ser.flushInput()
            self.msg_queue.put(f"Connected to {ser.name} at {ser.baudrate}")
            addr = offset
            if operation == "read":
                self.msg_queue.put("Reading EEPROM...")
                for _ in range(limit):
                    if self.cancel_requested:
                        self.msg_queue.put("Operation cancelled.")
                        break
                    command = "RD" + format(addr, '04X') + "\n"
                    ser.write(command.encode())
                    response = ser.readline().decode().strip()
                    self.msg_queue.put(f"{format(addr, '04X')} : {response.zfill(2)}")
                    try:
                        data_byte = int(response, 16)
                    except ValueError:
                        data_byte = 0
                    self.read_data.append(data_byte)
                    addr += 1
                    processed_bytes += 1
                    self.msg_queue.put(("progress", processed_bytes))
                    if processed_bytes % 16 == 0:
                        self.after(0, self.update_hex_window)
            elif operation == "write":
                if not file_path:
                    self.msg_queue.put("No file selected for writing.")
                    return
                self.msg_queue.put(f"Writing file {file_path} to EEPROM")
                with open(file_path, 'rb') as file:
                    contents = file.read()
                file_size = len(contents)
                effective_size = min(file_size, limit)
                self.msg_queue.put(f"Input file size: {file_size} bytes")
                self.msg_queue.put(f"Will write from address {offset:04X} to {offset + effective_size - 1:04X}")
                self.msg_queue.put(f"Limiting to first {effective_size} bytes")
                for i, b in enumerate(contents):
                    if self.cancel_requested:
                        self.msg_queue.put("Operation cancelled.")
                        break
                    if i >= effective_size:
                        break
                    command = "WR" + format(addr, '04X') + format(b, '02X') + "\n"
                    ser.write(command.encode())
                    addr += 1
                    processed_bytes += 1
                    self.msg_queue.put(("progress", processed_bytes))
                    response = ser.readline().decode().strip()
                    if response != "DONE":
                        self.msg_queue.put(f"Error at address {format(addr-1, '04X')}: {response}")
                        ser.close()
                        return
                    else:
                        self.msg_queue.put(f"Wrote byte at {format(addr-1, '04X')}")
            elif operation == "clear":
                self.msg_queue.put("Clearing EEPROM...")
                for _ in range(limit):
                    if self.cancel_requested:
                        self.msg_queue.put("Operation cancelled.")
                        break
                    command = "WR" + format(addr, '04X') + format(255, '02X') + "\n"
                    ser.write(command.encode())
                    addr += 1
                    processed_bytes += 1
                    self.msg_queue.put(("progress", processed_bytes))
                    response = ser.readline().decode().strip()
                    if response != "DONE":
                        self.msg_queue.put(f"Error at address {format(addr-1, '04X')}: {response}")
                        ser.close()
                        return
                    else:
                        self.msg_queue.put(f"Cleared byte at {format(addr-1, '04X')}")
            ser.close()
            self.msg_queue.put(f"Closed {com_port}")
        except Exception as e:
            self.msg_queue.put("Exception: " + str(e))

if __name__ == "__main__":
    app = EEPROMProgrammerApp()
    app.mainloop()
