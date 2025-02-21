import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import win32api
import win32con
import win32process
import win32event
import threading
import time
import math
import sys
import os
import logging 

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Log everything (DEBUG and above)
    format="%(asctime)s - %(levelname)s - %(message)s",  # Log format
    filename="dll_injector_debug.log",  # Log to a file
    filemode="w",  # Overwrite the log file each run
)

def resource_path(relative_path):
    """Get the absolute path to a resource, works for dev and for PyInstaller."""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class DLLInjectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ZeroDay Injector")
        self.root.geometry("400x300")  

        
        self.root.configure(bg="#2e2e2e")
        self.style = ttk.Style()
        self.style.theme_use("clam")  
        
        self.style.configure(".", background="#2e2e2e", foreground="white")
        self.style.configure("TLabel", background="#2e2e2e", foreground="white")
        self.style.configure("TFrame", background="#2e2e2e")
        self.style.configure("TCombobox", fieldbackground="#3e3e3e", foreground="white", background="#3e3e3e")
        self.style.configure("TButton", background="#3e3e3e", foreground="white", borderwidth=0)
        self.style.map("TButton", background=[("active", "#4e4e4e")])

        
        self.style.configure("TLabelframe", background="#2e2e2e", foreground="white", borderwidth=0)
        self.style.configure("TLabelframe.Label", background="#2e2e2e", foreground="white")

        
        self.dll_frame = ttk.LabelFrame(root, text="Select DLL")
        self.dll_frame.pack(pady=10, padx=20, fill=tk.X)

        self.select_dll_button = ttk.Button(
            self.dll_frame,
            text="Select DLL",
            command=self.select_dll,
        )
        self.select_dll_button.pack(side=tk.LEFT, padx=10, pady=10, expand=True)

        self.refresh_button = ttk.Button(
            self.dll_frame,
            text="Refresh",
            command=self.refresh_processes,
        )
        self.refresh_button.pack(side=tk.RIGHT, padx=10, pady=10, expand=True)

        
        self.selected_dll_label = ttk.Label(self.dll_frame, text="Selected DLL: None", font=("Arial", 8))
        self.selected_dll_label.pack(pady=5)

        
        self.process_frame = ttk.LabelFrame(root, text="Select Process")
        self.process_frame.pack(pady=10, padx=20, fill=tk.X)

        self.process_var = tk.StringVar()
        self.process_combobox = ttk.Combobox(self.process_frame, textvariable=self.process_var, state="readonly")
        self.process_combobox.pack(pady=10, padx=10, fill=tk.X)

        
        self.inject_button = tk.Button(
            root,
            text="Inject DLL",
            command=self.inject_dll,
            bg="#3e3e3e",  
            fg="white",  
            font=("Arial", 10),
            relief="flat",
            borderwidth=0,
        )
        self.inject_button.pack(pady=20)

        
        self.rgb_running = True
        self.hue = 0  # HUE CHANGE HERE
        self.rgb_thread = threading.Thread(target=self.animate_rgb_text, daemon=True)
        self.rgb_thread.start()

        self.refresh_processes()

    def animate_rgb_text(self):
        """Animate the Inject DLL button text with smooth RGB colors."""
        while self.rgb_running:
            # rgb calc (dont delete bro)
            r = int((math.sin(self.hue + 0) * 127 + 128))
            g = int((math.sin(self.hue + 2) * 127 + 128))
            b = int((math.sin(self.hue + 4) * 127 + 128))
            
            color = f"#{r:02x}{g:02x}{b:02x}"
            
            self.inject_button.config(fg=color)
            
            self.hue += 0.01
            if self.hue > 2 * math.pi:
                self.hue -= 2 * math.pi
            time.sleep(0.05)  

    def select_dll(self):
        """Allow the user to select a DLL file."""
        dll_path = filedialog.askopenfilename(title="Select DLL to Inject", filetypes=[("DLL Files", "*.dll")])
        if dll_path:
            self.selected_dll_label.config(text=f"Selected DLL: {os.path.basename(dll_path)}")
            self.dll_path = dll_path
            logging.info(f"DLL selected: {dll_path}") 

    def refresh_processes(self):
        """Refresh the list of running processes."""
        processes = self.get_running_processes()
        self.process_combobox["values"] = processes
        if processes:
            self.process_combobox.current(0)
        logging.info(f"Processes refreshed: {processes}")  

    def get_running_processes(self):
        """Get a list of running processes, excluding system processes."""
        process_list = []
        system_processes = ["svchost.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "smss.exe", "dwm.exe", "explorer.exe"]

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_info = proc.info
                process_name = process_info['name'].lower()

                
                if process_name not in system_processes and not self.is_system_process(proc):
                    process_list.append(f"{process_info['name']} (PID: {process_info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return process_list

    def is_system_process(self, proc):
        """Check if a process is a system process."""
        try:
            
            username = proc.username()
            return username in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return True

    def inject_dll(self):
        """Inject a DLL into the selected process."""
        try:
            selected_process = self.process_var.get()
            if not selected_process:
                messagebox.showwarning("Warning", "No process selected.")
                return


            pid = int(selected_process.split("(PID: ")[1].rstrip(")"))
            logging.info(f"Selected process: {selected_process}, PID: {pid}")  # Log selected process


            if not hasattr(self, 'dll_path'):
                messagebox.showwarning("Warning", "No DLL file selected.")
                return

            if not os.path.exists(self.dll_path):
                messagebox.showwarning("Warning", f"DLL file not found: {self.dll_path}")
                return

            process_handle = None
            dll_path_address = None
            thread_handle = None

            process_handle = win32api.OpenProcess(
                win32con.PROCESS_ALL_ACCESS, False, pid
            )
            logging.info(f"Process Handle: {process_handle}")  
            if not process_handle:
                error_code = win32api.GetLastError()
                raise Exception(f"Failed to open process. Error code: {error_code}")

            
            dll_path_address = win32process.VirtualAllocEx(
                process_handle,
                0,
                len(self.dll_path) + 1,
                win32con.MEM_COMMIT,
                win32con.PAGE_READWRITE,
            )
            logging.info(f"DLL Path Address: {dll_path_address}") 

            if not dll_path_address:
                raise Exception("Failed to allocate memory in the target process.")

            
            written = win32process.WriteProcessMemory(
                process_handle,                 
                dll_path_address,                
                self.dll_path.encode("utf-8")   
            )
            if not written:
                raise Exception("Failed to write DLL path to target process memory.")


            kernel32_handle = win32api.GetModuleHandle("kernel32.dll")
            load_library_address = win32api.GetProcAddress(kernel32_handle, "LoadLibraryA")
            logging.info(f"LoadLibrary Address: {load_library_address}")

            if not load_library_address:
                raise Exception("Failed to get address of LoadLibraryA.")


            thread_handle, thread_id = win32process.CreateRemoteThread(
                process_handle,
                None,
                0,
                load_library_address,
                dll_path_address,
                0,
            )
            logging.info(f"Thread Handle: {thread_handle}, Thread ID: {thread_id}")  

            if not thread_handle:
                error_code = win32api.GetLastError()
                raise Exception(f"Failed to create remote thread. Error code: {error_code}")

            win32event.WaitForSingleObject(thread_handle, win32event.INFINITE)

            win32process.VirtualFreeEx(process_handle, dll_path_address, 0, win32con.MEM_RELEASE)
            win32api.CloseHandle(thread_handle)
            win32api.CloseHandle(process_handle)

            messagebox.showinfo("Success", f"DLL injected into {selected_process}.")
        except Exception as e:
            logging.error(f"Failed to inject DLL: {e}", exc_info=True)  
            messagebox.showerror("Error", f"Failed to inject DLL: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DLLInjectorApp(root)
    root.mainloop()