# backend/system_control.py
# Full Laptop Control — Volume, Brightness, Power, Screenshot, System Info etc.

import os
import subprocess
import ctypes
import time
import datetime
import socket
import platform

# ===================== VOLUME CONTROL =====================
def volume_up(steps=5):
    """Volume increase karo."""
    try:
        from ctypes import cast, POINTER
        from comtypes import CLSCTX_ALL
        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
        
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume = cast(interface, POINTER(IAudioEndpointVolume))
        
        current = volume.GetMasterVolumeLevelScalar()
        new_vol = min(1.0, current + (steps * 0.1))
        volume.SetMasterVolumeLevelScalar(new_vol, None)
        return True, f"Volume badhaya — ab {int(new_vol * 100)}% hai"
    except ImportError:
        # Fallback: keyboard shortcut
        import ctypes
        for _ in range(steps):
            ctypes.windll.user32.keybd_event(0xAF, 0, 0, 0)   # VK_VOLUME_UP
            ctypes.windll.user32.keybd_event(0xAF, 0, 2, 0)
            time.sleep(0.05)
        return True, f"Volume {steps} step badha diya mamu!"

def volume_down(steps=5):
    """Volume decrease karo."""
    try:
        from ctypes import cast, POINTER
        from comtypes import CLSCTX_ALL
        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
        
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume = cast(interface, POINTER(IAudioEndpointVolume))
        
        current = volume.GetMasterVolumeLevelScalar()
        new_vol = max(0.0, current - (steps * 0.1))
        volume.SetMasterVolumeLevelScalar(new_vol, None)
        return True, f"Volume kam kiya — ab {int(new_vol * 100)}% hai"
    except ImportError:
        import ctypes
        for _ in range(steps):
            ctypes.windll.user32.keybd_event(0xAE, 0, 0, 0)   # VK_VOLUME_DOWN
            ctypes.windll.user32.keybd_event(0xAE, 0, 2, 0)
            time.sleep(0.05)
        return True, f"Volume {steps} step kam kar diya mamu!"

def volume_mute():
    """Volume mute/unmute toggle."""
    ctypes.windll.user32.keybd_event(0xAD, 0, 0, 0)   # VK_VOLUME_MUTE
    ctypes.windll.user32.keybd_event(0xAD, 0, 2, 0)
    return True, "Volume mute/unmute ho gaya!"

def volume_set(level):
    """Volume set karo (0-100)."""
    try:
        from ctypes import cast, POINTER
        from comtypes import CLSCTX_ALL
        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
        
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume = cast(interface, POINTER(IAudioEndpointVolume))
        
        volume.SetMasterVolumeLevelScalar(level / 100.0, None)
        return True, f"Volume {level}% pe set kar diya!"
    except ImportError:
        return False, "pycaw install nahi hai, pip install pycaw kar mamu!"

def get_volume():
    """Current volume level."""
    try:
        from ctypes import cast, POINTER
        from comtypes import CLSCTX_ALL
        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
        
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume = cast(interface, POINTER(IAudioEndpointVolume))
        
        current = volume.GetMasterVolumeLevelScalar()
        return True, f"Mamu, abhi volume {int(current * 100)}% pe hai!"
    except ImportError:
        return False, "Volume check nahi ho paya!"


# ===================== BRIGHTNESS CONTROL =====================
def brightness_set(level):
    """Screen brightness set karo (0-100)."""
    try:
        subprocess.run(
            ["powershell", "-Command",
             f"(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods).WmiSetBrightness(1, {level})"],
            capture_output=True, timeout=5
        )
        return True, f"Brightness {level}% pe set kar diya!"
    except:
        return False, "Brightness change nahi ho paya mamu!"

def brightness_up(step=20):
    """Brightness increase."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness).CurrentBrightness"],
            capture_output=True, text=True, timeout=5
        )
        current = int(result.stdout.strip())
        new_level = min(100, current + step)
        return brightness_set(new_level)
    except:
        return False, "Brightness badha nahi paya!"

def brightness_down(step=20):
    """Brightness decrease."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness).CurrentBrightness"],
            capture_output=True, text=True, timeout=5
        )
        current = int(result.stdout.strip())
        new_level = max(0, current - step)
        return brightness_set(new_level)
    except:
        return False, "Brightness kam nahi ho paya!"

def get_brightness():
    """Current brightness."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness).CurrentBrightness"],
            capture_output=True, text=True, timeout=5
        )
        level = int(result.stdout.strip())
        return True, f"Abhi brightness {level}% pe hai mamu!"
    except:
        return False, "Brightness check nahi ho paya!"


# ===================== POWER CONTROL =====================
def shutdown_pc(delay=5):
    """Laptop shutdown."""
    os.system(f"shutdown /s /t {delay}")
    return True, f"Bye mamu! Laptop {delay} second mein band ho jayega!"

def restart_pc(delay=5):
    """Laptop restart."""
    os.system(f"shutdown /r /t {delay}")
    return True, f"Laptop {delay} second mein restart hoga mamu!"

def cancel_shutdown():
    """Shutdown/restart cancel."""
    os.system("shutdown /a")
    return True, "Shutdown cancel kar diya mamu! Phew!"

def lock_pc():
    """Screen lock."""
    ctypes.windll.user32.LockWorkStation()
    return True, "Screen lock kar diya mamu!"

def sleep_pc():
    """PC sleep mode."""
    os.system("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
    return True, "Laptop sleep mode mein ja raha hai... goodnight mamu!"

def logoff_pc():
    """User logoff."""
    os.system("shutdown /l")
    return True, "Log off ho raha hai mamu!"


# ===================== SCREENSHOT =====================
def take_screenshot():
    """Screenshot le kar save karo."""
    try:
        import pyautogui
        screenshots_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Dhriti_Screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(screenshots_dir, f"screenshot_{timestamp}.png")
        
        img = pyautogui.screenshot()
        img.save(filepath)
        return True, f"Screenshot le liya mamu! Desktop pe Dhriti_Screenshots folder mein save hai."
    except ImportError:
        # Fallback: use Windows Snipping
        import ctypes
        ctypes.windll.user32.keybd_event(0x2C, 0, 0, 0)  # VK_SNAPSHOT (Print Screen)
        ctypes.windll.user32.keybd_event(0x2C, 0, 2, 0)
        return True, "Screenshot clipboard mein copy ho gaya! Paint mein paste kar le."


# ===================== SYSTEM INFO =====================
def get_battery():
    """Battery status."""
    try:
        import psutil
        battery = psutil.sensors_battery()
        if battery:
            percent = battery.percent
            plugged = "charge ho rahi hai" if battery.power_plugged else "battery pe chal raha hai"
            secs = battery.secsleft
            if secs == psutil.POWER_TIME_UNLIMITED:
                time_left = "unlimited"
            elif secs == psutil.POWER_TIME_UNKNOWN:
                time_left = "pata nahi"
            else:
                hrs = secs // 3600
                mins = (secs % 3600) // 60
                time_left = f"{hrs} ghanta {mins} minute"
            return True, f"Battery {percent}% hai, {plugged}. Time left: {time_left}"
        return False, "Battery info nahi mila!"
    except ImportError:
        return False, "psutil install nahi hai mamu!"

def get_cpu_usage():
    """CPU usage."""
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=1)
        return True, f"CPU usage abhi {cpu}% hai mamu!"
    except ImportError:
        return False, "psutil install nahi hai!"

def get_ram_usage():
    """RAM usage."""
    try:
        import psutil
        ram = psutil.virtual_memory()
        used_gb = ram.used / (1024**3)
        total_gb = ram.total / (1024**3)
        return True, f"RAM usage: {used_gb:.1f} GB / {total_gb:.1f} GB ({ram.percent}%)"
    except ImportError:
        return False, "psutil install nahi hai!"

def get_disk_usage():
    """Disk usage."""
    try:
        import psutil
        disk = psutil.disk_usage('C:\\')
        used_gb = disk.used / (1024**3)
        total_gb = disk.total / (1024**3)
        free_gb = disk.free / (1024**3)
        return True, f"C drive: {used_gb:.0f} GB used, {free_gb:.0f} GB free, total {total_gb:.0f} GB ({disk.percent}% used)"
    except ImportError:
        return False, "psutil install nahi hai!"

def get_ip_address():
    """IP address."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return True, f"Tera PC name: {hostname}, IP address: {local_ip}"
    except:
        return False, "IP address nahi mila mamu!"

def get_system_info():
    """Full system info."""
    info = []
    info.append(f"OS: {platform.system()} {platform.release()} ({platform.version()})")
    info.append(f"PC Name: {platform.node()}")
    info.append(f"Processor: {platform.processor()}")
    info.append(f"Architecture: {platform.machine()}")
    
    try:
        import psutil
        ram = psutil.virtual_memory()
        info.append(f"RAM: {ram.total / (1024**3):.1f} GB")
        battery = psutil.sensors_battery()
        if battery:
            info.append(f"Battery: {battery.percent}%")
    except:
        pass
    
    return True, " | ".join(info)


# ===================== APP MANAGEMENT =====================
def open_task_manager():
    """Task Manager kholo."""
    os.system("taskmgr")
    return True, "Task Manager khol diya mamu!"

def open_settings():
    """Windows Settings."""
    os.system("start ms-settings:")
    return True, "Settings khol diya!"

def open_file_explorer():
    """File Explorer."""
    os.system("explorer")
    return True, "File Explorer khol diya!"

def open_cmd():
    """Command Prompt."""
    os.system("start cmd")
    return True, "Command Prompt khol diya!"

def open_notepad():
    """Notepad."""
    os.system("notepad")
    return True, "Notepad khol diya mamu!"

def open_calculator():
    """Calculator."""
    os.system("calc")
    return True, "Calculator khol diya!"

def close_app(app_name):
    """Koi bhi app band karo by name."""
    try:
        os.system(f"taskkill /f /im {app_name}.exe")
        return True, f"{app_name} band kar diya mamu!"
    except:
        return False, f"{app_name} band nahi ho paya!"


# ===================== KEYBOARD SHORTCUTS =====================
def minimize_all():
    """Sab windows minimize."""
    ctypes.windll.user32.keybd_event(0x5B, 0, 0, 0)  # Win key down
    ctypes.windll.user32.keybd_event(0x44, 0, 0, 0)  # D key down 
    ctypes.windll.user32.keybd_event(0x44, 0, 2, 0)  # D key up
    ctypes.windll.user32.keybd_event(0x5B, 0, 2, 0)  # Win key up
    return True, "Sab windows minimize ho gayi mamu!"

def alt_tab():
    """Window switch."""
    ctypes.windll.user32.keybd_event(0x12, 0, 0, 0)  # Alt down
    ctypes.windll.user32.keybd_event(0x09, 0, 0, 0)  # Tab down
    ctypes.windll.user32.keybd_event(0x09, 0, 2, 0)  # Tab up
    ctypes.windll.user32.keybd_event(0x12, 0, 2, 0)  # Alt up
    return True, "Window switch kar diya!"

def close_current_window():
    """Current window band karo (Alt+F4)."""
    ctypes.windll.user32.keybd_event(0x12, 0, 0, 0)  # Alt down
    ctypes.windll.user32.keybd_event(0x73, 0, 0, 0)  # F4 down
    ctypes.windll.user32.keybd_event(0x73, 0, 2, 0)  # F4 up
    ctypes.windll.user32.keybd_event(0x12, 0, 2, 0)  # Alt up
    return True, "Window band kar diya!"

def maximize_window():
    """Current window maximize."""
    import ctypes
    ctypes.windll.user32.keybd_event(0x5B, 0, 0, 0)  # Win
    ctypes.windll.user32.keybd_event(0x26, 0, 0, 0)  # Up arrow
    ctypes.windll.user32.keybd_event(0x26, 0, 2, 0)
    ctypes.windll.user32.keybd_event(0x5B, 0, 2, 0)
    return True, "Window maximize ho gayi!"


# ===================== CLIPBOARD =====================
def copy_clipboard():
    """Ctrl+C."""
    ctypes.windll.user32.keybd_event(0x11, 0, 0, 0)  # Ctrl
    ctypes.windll.user32.keybd_event(0x43, 0, 0, 0)  # C
    ctypes.windll.user32.keybd_event(0x43, 0, 2, 0)
    ctypes.windll.user32.keybd_event(0x11, 0, 2, 0)
    return True, "Copy ho gaya mamu!"

def paste_clipboard():
    """Ctrl+V."""
    ctypes.windll.user32.keybd_event(0x11, 0, 0, 0)
    ctypes.windll.user32.keybd_event(0x56, 0, 0, 0)  # V
    ctypes.windll.user32.keybd_event(0x56, 0, 2, 0)
    ctypes.windll.user32.keybd_event(0x11, 0, 2, 0)
    return True, "Paste ho gaya!"

def undo_action():
    """Ctrl+Z."""
    ctypes.windll.user32.keybd_event(0x11, 0, 0, 0)
    ctypes.windll.user32.keybd_event(0x5A, 0, 0, 0)  # Z
    ctypes.windll.user32.keybd_event(0x5A, 0, 2, 0)
    ctypes.windll.user32.keybd_event(0x11, 0, 2, 0)
    return True, "Undo ho gaya mamu!"

def select_all():
    """Ctrl+A."""
    ctypes.windll.user32.keybd_event(0x11, 0, 0, 0)
    ctypes.windll.user32.keybd_event(0x41, 0, 0, 0)  # A
    ctypes.windll.user32.keybd_event(0x41, 0, 2, 0)
    ctypes.windll.user32.keybd_event(0x11, 0, 2, 0)
    return True, "Sab select ho gaya!"


# ===================== WIFI CONTROL =====================
def wifi_on():
    """Wifi enable."""
    os.system('netsh interface set interface "Wi-Fi" enabled')
    return True, "WiFi on kar diya mamu!"

def wifi_off():
    """Wifi disable."""
    os.system('netsh interface set interface "Wi-Fi" disabled')
    return True, "WiFi off kar diya!"

def wifi_status():
    """WiFi connection status."""
    try:
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                              capture_output=True, text=True, timeout=5)
        output = result.stdout
        if "connected" in output.lower():
            # Find SSID
            for line in output.split("\n"):
                if "SSID" in line and "BSSID" not in line:
                    ssid = line.split(":")[1].strip()
                    return True, f"WiFi connected hai — network: {ssid}"
            return True, "WiFi connected hai mamu!"
        else:
            return True, "WiFi disconnect hai abhi!"
    except:
        return False, "WiFi status check nahi ho paya!"


# ===================== DATE/TIME =====================
def get_time():
    """Current time."""
    now = datetime.datetime.now()
    hour = now.strftime("%I")
    minute = now.strftime("%M")
    ampm = "subah" if now.hour < 12 else ("dopahar" if now.hour < 17 else "shaam")
    return True, f"Mamu, abhi {hour} bajke {minute} minute hue hain, {ampm} ke!"

def get_date():
    """Current date."""
    now = datetime.datetime.now()
    days_hindi = ["Somvaar", "Mangalvaar", "Budhvaar", "Guruvaar", "Shukravaar", "Shanivaar", "Ravivaar"]
    months = ["January", "February", "March", "April", "May", "June",
              "July", "August", "September", "October", "November", "December"]
    day_name = days_hindi[now.weekday()]
    return True, f"Aaj {day_name} hai, {now.day} {months[now.month-1]} {now.year}"


# ===================== SEARCH =====================
def google_search(query):
    """Google pe search karo."""
    import webbrowser
    url = f"https://www.google.com/search?q={query}"
    webbrowser.open(url)
    return True, f"Google pe '{query}' search kar raha hoon mamu!"

def youtube_search(query):
    """YouTube pe search karo."""
    import webbrowser
    url = f"https://www.youtube.com/results?search_query={query}"
    webbrowser.open(url)
    return True, f"YouTube pe '{query}' search kar raha hoon!"


# ===================== EMPTY RECYCLE BIN =====================
def empty_recycle_bin():
    """Recycle bin khaali karo."""
    try:
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x07)
        return True, "Recycle bin saaf kar diya mamu! Ab system mein jagah hai!"
    except:
        return False, "Recycle bin khaali nahi ho paya!"
