import customtkinter as ctk
from tkinter import filedialog
import psutil
import win32api
import win32con
import win32process
import win32event
import win32gui
import threading
import time
import math
import sys
import os
import logging
import struct
import platform
import ctypes

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="dll_injector_debug.log",
    filemode="w",
)

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class DLLInjectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ZeroDay Injector")
        self.root.geometry("500x550")
        self.root.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.main_frame = ctk.CTkFrame(root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.dll_frame = ctk.CTkFrame(self.main_frame)
        self.dll_frame.pack(fill="x", pady=10, padx=10)
        self.select_dll_button = ctk.CTkButton(self.dll_frame, text="Select DLL", command=self.select_dll, corner_radius=8)
        self.select_dll_button.pack(side="left", padx=10, pady=10, expand=True)
        self.refresh_button = ctk.CTkButton(self.dll_frame, text="Refresh", command=self.refresh_processes, corner_radius=8)
        self.refresh_button.pack(side="right", padx=10, pady=10, expand=True)
        self.selected_dll_label = ctk.CTkLabel(self.dll_frame, text="Selected DLL: None", font=("Arial", 12))
        self.selected_dll_label.pack(pady=5)
        self.selected_process_label = ctk.CTkLabel(self.dll_frame, text="Selected Process: None", font=("Arial", 12))
        self.selected_process_label.pack(pady=5)
        self.process_frame = ctk.CTkFrame(self.main_frame)
        self.process_frame.pack(fill="both", expand=True, pady=10, padx=10)
        self.process_scrollable_frame = ctk.CTkScrollableFrame(self.process_frame, label_text="Select Process", label_font=("Arial", 12), scrollbar_button_color="#1f6aa5", scrollbar_button_hover_color="#144870", corner_radius=8)
        self.process_scrollable_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.inject_button = ctk.CTkButton(self.main_frame, text="Inject DLL", command=self.start_injection_thread, corner_radius=8, fg_color="#1f6aa5", hover_color="#144870")
        self.inject_button.pack(pady=20)
        self.rgb_running = True
        self.hue = 0
        self.rgb_thread = threading.Thread(target=self.animate_rgb_text, daemon=True)
        self.rgb_thread.start()
        self.version_label = ctk.CTkLabel(self.main_frame, text="v1.0.1  |  Made by Zeuos", font=("Arial", 10), fg_color="#2e2e2e", corner_radius=8)
        self.version_label.pack(side="bottom", pady=10)
        self.refresh_processes()

    def animate_rgb_text(self):
        while self.rgb_running:
            r = int((math.sin(self.hue + 0) * 127 + 128))
            g = int((math.sin(self.hue + 2) * 127 + 128))
            b = int((math.sin(self.hue + 4) * 127 + 128))
            color = f"#{r:02x}{g:02x}{b:02x}"
            self.inject_button.configure(fg_color=color)
            self.hue += 0.01
            if self.hue > 2 * math.pi:
                self.hue -= 2 * math.pi
            time.sleep(0.05)

    def select_dll(self):
        dll_path = filedialog.askopenfilename(title="Select DLL to Inject", filetypes=[("DLL Files", "*.dll")])
        if dll_path:
            self.selected_dll_label.configure(text=f"Selected DLL: {os.path.basename(dll_path)}")
            self.dll_path = dll_path
            logging.info(f"DLL selected: {dll_path}")

    def refresh_processes(self):
        for widget in self.process_scrollable_frame.winfo_children():
            widget.destroy()
        processes = self.get_visible_processes()
        for process in processes:
            process_button = ctk.CTkButton(self.process_scrollable_frame, text=process, command=lambda p=process: self.select_process(p), corner_radius=8, fg_color="#2e2e2e", hover_color="#3e3e3e")
            process_button.pack(fill="x", padx=5, pady=2)
        logging.info(f"Processes refreshed: {processes}")

    def select_process(self, process):
        self.selected_process = process
        self.selected_process_label.configure(text=f"Selected Process: {process}")
        logging.info(f"Selected process: {process}")

    def get_visible_processes(self):
        visible_processes = set()
        def enum_windows_callback(hwnd, _):
            if win32gui.IsWindowVisible(hwnd):
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                visible_processes.add(pid)
        win32gui.EnumWindows(enum_windows_callback, None)
        process_list = []
        system_processes = {"svchost.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "smss.exe", "dwm.exe", "explorer.exe"}
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                process_info = proc.info
                process_name = process_info['name'].lower()
                username = process_info['username']
                if (process_info['pid'] in visible_processes and username not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") and process_name not in system_processes):
                    process_list.append(f"{process_info['name']} (PID: {process_info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return process_list

    def start_injection_thread(self):
        if not hasattr(self, 'selected_process'):
            self.show_custom_message("Warning", "No process selected.")
            return
        if not hasattr(self, 'dll_path'):
            self.show_custom_message("Warning", "No DLL file selected.")
            return
        self.inject_button.configure(state="disabled")
        injection_thread = threading.Thread(target=self.inject_dll, daemon=True)
        injection_thread.start()

    def inject_dll(self):
        try:
            selected_process = self.selected_process
            pid = int(selected_process.split("(PID: ")[1].rstrip(")"))
            logging.info(f"Selected process: {selected_process}, PID: {pid}")
            if not os.path.exists(self.dll_path):
                self.show_custom_message("Warning", f"DLL file not found: {self.dll_path}")
                return
            process_handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
            logging.info(f"Process Handle: {process_handle}")
            if not process_handle:
                error_code = win32api.GetLastError()
                raise Exception(f"Failed to open process. Error code: {error_code}")
            is_target_64bit = self.is_process_64bit(pid)
            is_dll_64bit = self.is_dll_64bit(self.dll_path)
            if is_target_64bit != is_dll_64bit:
                raise Exception("Architecture mismatch: Ensure the DLL matches the target process architecture.")
            dll_path_address = win32process.VirtualAllocEx(process_handle, 0, len(self.dll_path) + 1, win32con.MEM_COMMIT, win32con.PAGE_READWRITE)
            logging.info(f"DLL Path Address: {dll_path_address}")
            if not dll_path_address:
                raise Exception("Failed to allocate memory in the target process.")
            written = win32process.WriteProcessMemory(process_handle, dll_path_address, self.dll_path.encode("utf-8"))
            if not written:
                raise Exception("Failed to write DLL path to target process memory.")
            kernel32_handle = win32api.GetModuleHandle("kernel32.dll")
            load_library_address = win32api.GetProcAddress(kernel32_handle, "LoadLibraryA")
            logging.info(f"LoadLibrary Address: {load_library_address}")
            if not load_library_address:
                raise Exception("Failed to get address of LoadLibraryA.")
            thread_handle, thread_id = win32process.CreateRemoteThread(process_handle, None, 0, load_library_address, dll_path_address, 0)
            logging.info(f"Thread Handle: {thread_handle}, Thread ID: {thread_id}")
            if not thread_handle:
                error_code = win32api.GetLastError()
                raise Exception(f"Failed to create remote thread. Error code: {error_code}")
            win32event.WaitForSingleObject(thread_handle, win32event.INFINITE)
            win32process.VirtualFreeEx(process_handle, dll_path_address, 0, win32con.MEM_RELEASE)
            win32api.CloseHandle(thread_handle)
            win32api.CloseHandle(process_handle)
            self.show_custom_message("Success", f"DLL injected into {selected_process}.")
        except Exception as e:
            logging.error(f"Failed to inject DLL: {e}", exc_info=True)
            self.show_custom_message("Error", f"Failed to inject DLL: {e}")
        finally:
            self.inject_button.configure(state="normal")

    def is_process_64bit(self, pid):
        try:
            # Use IsWow64Process to determine if the process is 32-bit or 64-bit
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not handle:
                error_code = ctypes.windll.kernel32.GetLastError()
                raise Exception(f"Failed to open process. Error code: {error_code}")
            is_wow64 = ctypes.c_int(0)
            ctypes.windll.kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
            ctypes.windll.kernel32.CloseHandle(handle)
            return is_wow64.value == 0  # If not WOW64, it's a 64-bit process
        except Exception as e:
            logging.error(f"Failed to determine process architecture: {e}", exc_info=True)
            return False

    def is_dll_64bit(self, dll_path):
        with open(dll_path, 'rb') as f:
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]
            f.seek(pe_offset + 4)
            machine = struct.unpack('<H', f.read(2))[0]
            return machine == 0x8664

    def show_custom_message(self, title, message):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        label = ctk.CTkLabel(dialog, text=message, font=("Arial", 12))
        label.pack(pady=20, padx=20)
        ok_button = ctk.CTkButton(dialog, text="OK", command=dialog.destroy, corner_radius=8)
        ok_button.pack(pady=10)
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f"+{x}+{y}")

if __name__ == "__main__":
    root = ctk.CTk()
    app = DLLInjectorApp(root)
    root.mainloop()