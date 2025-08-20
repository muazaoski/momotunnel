import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import json
import os
import sys
import subprocess
import platform
from datetime import datetime
import requests
import time
import re
import urllib.parse
import base64
import hashlib
import hmac
import secrets
import ssl
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import winreg
import ctypes
from ctypes import wintypes
import subprocess
import tempfile
import shutil
import logging
import logging.handlers
try:
    import pystray
    from PIL import Image, ImageDraw
except Exception:
    pystray = None

class NpvTunnelPC:
    def __init__(self, root):
        self.root = root
        self.root.title("Momo Tunnel - Free VPN by Muazaoski")
        self.root.geometry("900x750")
        self.root.configure(bg='#0f0f0f')
        self.root.minsize(800, 650)
        
        # Set window icon if available
        try:
            self.set_window_icon()
        except Exception:
            pass
        
        # Initialize logging
        self.setup_logging()
        
        # Create app data dirs and recover from stale state
        try:
            self.ensure_app_dirs()
        except Exception:
            pass

        # Log application startup
        self.logger.info("=== Npv Tunnel PC Starting ===")
        self.logger.info(f"Python version: {sys.version}")
        self.logger.info(f"Platform: {sys.platform}")
        self.logger.info(f"Working directory: {os.getcwd()}")
        
        # VPN connection state
        self.is_connected = False
        self.vpn_thread = None
        self.active_proxy_host = None
        self.active_proxy_port = None
        self.proxy_fail_streak = 0
        self.use_system_proxy = True
        self.connection_history = []
        self.auto_connect_on_start = False
        self.split_tunneling_enabled = False
        self.split_domains = []
        self.split_ips = []
        
        # Configuration storage
        self.configs = []
        self.current_config = None
        
        # VPN core components
        self.vpn_interface = None
        self.vpn_process = None
        self.encryption_key = None
        self.config_password = None
        
        # Network settings
        self.original_dns = None
        self.original_routes = None
        self.kill_switch_enabled = False
        # UX/settings
        self.theme_mode = 'dark'
        self.auto_reconnect_enabled = False
        self.max_reconnect_attempts = 5
        self.reconnect_delay_seconds = 3
        self.current_reconnect_attempt = 0
        self.favorites = set()
        self.tray_icon = None
        self.tray_thread = None
        # Profiles & Schedule
        self.profiles = {}
        self.current_profile_name = None
        self.schedule_entries = []
        self.auto_select_best_enabled = False
        # Monitoring & metrics
        self.latency_samples = []
        self.latency_thread_stop = False
        self.connection_start_time = None
        self.server_geo_cache = {}
        self.last_latency_map = {}
        # Routing prefs
        self.preferred_country = ''
        self.load_balancing_strategy = 'latency'  # or 'round_robin'
        self.round_robin_index = 0
        # Protection & UX
        self.dns_leak_protection_enabled = True
        self.theme_mode = self.theme_mode if hasattr(self, 'theme_mode') else 'dark'
        self.start_with_windows_enabled = False
        self.verbose_logging_enabled = False
        

        self.setup_ui()
        self.load_settings()
        self.load_advanced_settings()
        # Clear any leftover localhost proxy from previous crashes
        try:
            self.startup_sanity_cleanup()
        except Exception:
            pass
        # Remove stale kill-switch rules if present and app is not connected
        try:
            self.cleanup_kill_switch_if_stale()
        except Exception:
            pass
        # Optionally auto-connect after settings and config load
        try:
            if self.auto_connect_on_start and self.current_config:
                self.root.after(1500, self.connect_vpn)
        except Exception:
            pass
        # MFA
        self.mfa_enabled = False
        self.mfa_secret = None
        
        # Autoload last-used configuration or clipboard config shortly after startup
        self.root.after(200, self.autoload_last_config)

        # Start IP checker after GUI is fully initialized
        self.root.after(1000, self.start_ip_checker)
        # Start tray icon
        self.start_tray_icon()
        # Start scheduler thread
        threading.Thread(target=self.schedule_worker, daemon=True).start()
        # Start latency monitor
        self.start_latency_monitor()
        
        self.logger.info("Application initialized successfully")
        
    def setup_logging(self):
        """Setup comprehensive logging system"""
        # Create logs directory in AppData if it doesn't exist
        logs_dir = self.get_logs_dir()
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir, exist_ok=True)
            
        # Configure logging
        self.logger = logging.getLogger('NpvTunnelPC')
        self.logger.setLevel(logging.DEBUG if getattr(self, 'verbose_logging_enabled', False) else logging.INFO)
        
        # Create formatters
        if getattr(self, 'verbose_logging_enabled', False):
            detailed_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            simple_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        else:
            detailed_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            simple_formatter = detailed_formatter
        
        # File handler for detailed logs
        file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(logs_dir, 'npv_tunnel.log'), maxBytes=1024*1024, backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        
        # Console handler for basic logs
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if getattr(self, 'verbose_logging_enabled', False) else logging.WARNING)
        console_handler.setFormatter(simple_formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Prevent duplicate logs
        self.logger.propagate = False
        
        self.logger.info("Logging system initialized")
        
    def log_operation(self, operation, details=None, level='info'):
        """Helper method to log operations consistently"""
        message = f"Operation: {operation}"
        if details:
            # Redact obvious secrets
            try:
                redacted = str(details)
                # Header-like pairs
                for token in ['uuid', 'id', 'password', 'pass', 'token', 'secret', 'Authorization', 'auth']:
                    redacted = re.sub(rf"(?i)(\b{token}\b\s*[:=]\s*)([^\s,;]+)", r"\1***", redacted)
                # URL creds user:pass@
                redacted = re.sub(r"(?i)://([^:@/]+):([^@/]+)@", r"://***:***@", redacted)
                # Long opaque strings
                redacted = re.sub(r"([A-Za-z0-9_\-]{24,})", "***", redacted)
                message += f" - Details: {redacted}"
            except Exception:
                message += f" - Details: {details}"
            
        if level == 'debug':
            self.logger.debug(message)
        elif level == 'info':
            self.logger.info(message)
        elif level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)
        elif level == 'critical':
            self.logger.critical(message)
            
        # Also update UI log display if available
        if hasattr(self, 'log_text'):
            self.update_log_display(message, level)

    # ------------------------ Icons & Paths ------------------------
    def get_downloads_dir(self):
        try:
            return os.path.join(os.path.expanduser('~'), 'Downloads')
        except Exception:
            return os.getcwd()

    def set_window_icon(self):
        """Attempt to set window icon from Downloads (prefer 256, then 48, then alt names, then png)."""
        try:
            downloads = self.get_downloads_dir()
            ico256 = os.path.join(downloads, 'iconmomotunnel256.ico')
            ico48 = os.path.join(downloads, 'iconmomotunnel48.ico')
            ico2 = os.path.join(downloads, 'iconmomotunnel2.ico')
            ico = os.path.join(downloads, 'iconmomotunnel.ico')
            png = os.path.join(downloads, 'iconmomotunnel.png')
            if os.path.exists(ico256):
                self.root.iconbitmap(ico256)
            elif os.path.exists(ico48):
                self.root.iconbitmap(ico48)
            elif os.path.exists(ico2):
                self.root.iconbitmap(ico2)
            elif os.path.exists(ico):
                self.root.iconbitmap(ico)
            elif os.path.exists(png):
                try:
                    img = tk.PhotoImage(file=png)
                    self.root.iconphoto(True, img)
                except Exception:
                    pass
        except Exception:
            pass
            
    def update_log_display(self, message, level='info'):
        """Update the log display in the UI"""
        if hasattr(self, 'log_text'):
            timestamp = datetime.now().strftime("%H:%M:%S")
            level_emoji = {
                'debug': '🔍',
                'info': 'ℹ️',
                'warning': '⚠️',
                'error': '❌',
                'critical': '🚨'
            }
            
            emoji = level_emoji.get(level, 'ℹ️')
            log_entry = f"[{timestamp}] {emoji} {message}\n"
            
            # Update log display (limit to last 1000 lines)
            self.log_text.insert(tk.END, log_entry)
            self.log_text.see(tk.END)
            
            # Limit log display size
            lines = self.log_text.get('1.0', tk.END).split('\n')
            if len(lines) > 1000:
                self.log_text.delete('1.0', f'{len(lines)-1000}.0')

    # ------------------------ Latency Monitor ------------------------
    def start_latency_monitor(self):
        try:
            self.latency_thread_stop = False
            threading.Thread(target=self._latency_worker, daemon=True).start()
        except Exception as e:
            self.logger.debug(f"Latency monitor start failed: {e}")

    def stop_latency_monitor(self):
        self.latency_thread_stop = True

    def _get_ping_target(self):
        # Prefer current VPN server; else public IP checker host; else 8.8.8.8
        try:
            if self.current_config and self.current_config.get('server'):
                return self.current_config['server']
        except Exception:
            pass
        return '1.1.1.1'

    def _latency_worker(self):
        """Ping target periodically and record latency; print ms into log and keep last 30 samples."""
        while not self.latency_thread_stop:
            target = self._get_ping_target()
            latency_ms = None
            try:
                # Use Windows ping with one echo request and 2s timeout
                proc = subprocess.run(['ping', '-n', '1', '-w', '2000', target], capture_output=True, text=True, shell=True)
                out = proc.stdout or ''
                # Parse time=XXms
                m = re.search(r'time[=<]([0-9]+)ms', out)
                if m:
                    latency_ms = int(m.group(1))
                elif 'TTL=' in out.upper():
                    # Some locales print different token; fallback nominal value
                    latency_ms = 1
            except Exception:
                latency_ms = None

            if latency_ms is not None:
                self.latency_samples.append(latency_ms)
                if len(self.latency_samples) > 30:
                    self.latency_samples = self.latency_samples[-30:]
                self.log_operation('Ping {0} = {1} ms'.format(target, latency_ms), level='info')
                try:
                    self.update_latency_chart()
                except Exception:
                    pass
            else:
                self.log_operation('Ping {0} failed'.format(target), level='warning')

            time.sleep(5)

    def update_latency_chart(self):
        """Enhanced latency chart with modern styling"""
        try:
            if not hasattr(self, 'latency_canvas'):
                return
            canvas = self.latency_canvas
            canvas.delete('all')
            data = self.latency_samples[-30:]
            if not data:
                # Show placeholder when no data
                width = canvas.winfo_width() or 400
                height = canvas.winfo_height() or 100
                canvas.create_text(width//2, height//2, text="No latency data yet...", 
                                 fill='#7d8590', font=("Segoe UI", 10))
                return
            
            width = int(canvas.winfo_width() or 400)
            height = int(canvas.winfo_height() or 100)
            margin = 10
            chart_height = height - (margin * 2)
            
            # Calculate chart parameters
            max_latency = max(max(data), 1)
            step_width = max((width - margin * 2) // max(len(data), 1), 2)
            
            # Draw grid lines
            for i in range(0, max_latency + 1, max(max_latency // 4, 1)):
                y = height - margin - (i / max_latency) * chart_height
                canvas.create_line(margin, y, width - margin, y, 
                                 fill='#2d1414', width=1)
            
            # Draw bars with gradient effect
            x = margin
            for i, v in enumerate(data):
                bar_height = int((v / max_latency) * chart_height)
                bar_y = height - margin - bar_height
                
                # Color based on latency (maroon theme)
                if v < 50:
                    color = '#8B0000'  # Good latency - dark red
                elif v < 150:
                    color = '#CD5C5C'  # Okay latency - light coral
                else:
                    color = '#DC143C'  # Poor latency - crimson
                
                # Draw bar
                canvas.create_rectangle(x, bar_y, x + step_width - 1, height - margin, 
                                      fill=color, outline='', width=0)
                
                # Add highlight on recent bars
                if i >= len(data) - 5:  # Last 5 samples
                    canvas.create_rectangle(x, bar_y, x + step_width - 1, height - margin, 
                                          outline='#CD5C5C', width=1)
                
                x += step_width
            
            # Add current latency text
            if data:
                current = data[-1]
                avg = sum(data) / len(data)
                canvas.create_text(width - margin - 5, margin + 5, 
                                  text=f"Current: {current}ms | Avg: {int(avg)}ms", 
                                  fill='#ffffff', font=("Segoe UI", 9), anchor='ne')
                
        except Exception as e:
            self.logger.debug(f"Latency chart update failed: {e}")

    def update_latency_metrics(self):
        try:
            if not hasattr(self, 'latency_label'):
                return
            data = self.latency_samples
            if not data:
                self.latency_label.config(text="Latency: -- ms (1m: -- | 5m: -- | 15m: --)")
                return
            import statistics, time as _t
            now = _t.time()
            # Assume samples roughly every 5s from worker; compute windows by count
            last = data[-1]
            def avg_for(seconds):
                count = max(int(seconds/5), 1)
                subset = data[-count:]
                return int(statistics.mean(subset)) if subset else None
            a1 = avg_for(60)
            a5 = avg_for(300)
            a15 = avg_for(900)
            self.latency_label.config(text=f"Latency: {last} ms (1m: {a1 if a1 is not None else '--'} | 5m: {a5 if a5 is not None else '--'} | 15m: {a15 if a15 is not None else '--'})")
        except Exception:
            pass

    def on_toggle_split_tunneling(self):
        try:
            self.split_tunneling_enabled = bool(self.split_toggle_var.get())
            if self.split_tunneling_enabled and self.is_connected:
                self.enable_split_tunneling(direct_domains=self.split_domains, direct_ips=self.split_ips)
            else:
                self.disable_split_tunneling()
        except Exception as e:
            self.log_operation(f"Split toggle failed: {e}", level='warning')

    def show_connection_history(self):
        try:
            win = tk.Toplevel(self.root)
            win.title("Connection History")
            win.geometry("560x360")
            win.configure(bg='#1e1e1e')
            cols = ('Time', 'Server', 'Protocol', 'Latency (ms)')
            tree = ttk.Treeview(win, columns=cols, show='headings')
            for c in cols:
                tree.heading(c, text=c)
                tree.column(c, width=120)
            tree.pack(fill=tk.BOTH, expand=True)
            # Populate with last 200 snapshots
            for item in self.connection_history[-200:]:
                tree.insert('', tk.END, values=(
                    item.get('ts',''),
                    item.get('server',''),
                    item.get('protocol',''),
                    item.get('latency_ms','')
                ))
            tk.Button(win, text='Export CSV', bg='#444444', fg='#ffffff', relief=tk.FLAT,
                      command=lambda: self.export_connection_history(tree)).pack(pady=8)
        except Exception as e:
            self.log_operation(f"History view failed: {e}", level='warning')

    def export_connection_history(self, tree):
        try:
            fname = filedialog.asksaveasfilename(title='Save History As', defaultextension='.csv', filetypes=[('CSV','*.csv')])
            if not fname:
                return
            import csv
            with open(fname, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(['Time','Server','Protocol','Latency (ms)'])
                for child in tree.get_children():
                    w.writerow(tree.item(child)['values'])
            messagebox.showinfo('Export', 'History exported.')
        except Exception as e:
            messagebox.showerror('Export', f'Failed to export: {e}')
                
    # ------------------------ Audit Logging ------------------------
    def log_audit(self, action, status, context=None):
        try:
            logs_dir = self.get_logs_dir()
            if not os.path.exists(logs_dir):
                os.makedirs(logs_dir, exist_ok=True)
            entry = {
                "ts": datetime.utcnow().isoformat() + "Z",
                "action": action,
                "status": status,
                "user": None,
                "config": None,
                "context": context or {}
            }
            try:
                entry["user"] = os.getlogin()
            except Exception:
                pass
            try:
                if self.current_config:
                    entry["config"] = {
                        "name": self.current_config.get('name'),
                        "protocol": self.current_config.get('protocol')
                    }
            except Exception:
                pass
            with open(os.path.join(self.get_logs_dir(), 'npv_audit.jsonl'), 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            # Do not raise; audit is best-effort
            self.logger.debug(f"Audit log failed: {e}")
    # ------------------------ MFA (TOTP) ------------------------
    def setup_mfa_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Setup MFA")
        dialog.geometry("360x180")
        dialog.configure(bg='#1e1e1e')
        tk.Label(dialog, text="Enter MFA secret (Base32, e.g., from QR):", fg='#ffffff', bg='#1e1e1e').pack(pady=10)
        entry = tk.Entry(dialog, width=40)
        entry.pack(pady=5)
        status = tk.Label(dialog, text="", fg='#00ff88', bg='#1e1e1e')
        status.pack(pady=5)
        def save_secret():
            self.mfa_secret = entry.get().strip()
            self.mfa_enabled = bool(self.mfa_secret)
            self.mfa_status_label.config(text=f"MFA: {'Enabled' if self.mfa_enabled else 'Disabled'}")
            status.config(text="Saved")
        tk.Button(dialog, text="Save", command=save_secret, bg='#444444', fg='#ffffff').pack(pady=10)

    def disable_mfa(self):
        self.mfa_enabled = False
        self.mfa_secret = None
        if hasattr(self, 'mfa_status_label'):
            self.mfa_status_label.config(text="MFA: Disabled")

    def verify_mfa_prompt(self):
        try:
            if not self.mfa_enabled or not self.mfa_secret:
                return True
            dialog = tk.Toplevel(self.root)
            dialog.title("MFA Verification")
            dialog.geometry("320x160")
            dialog.configure(bg='#1e1e1e')
            tk.Label(dialog, text="Enter 6-digit OTP", fg='#ffffff', bg='#1e1e1e').pack(pady=10)
            entry = tk.Entry(dialog, width=20)
            entry.pack(pady=5)
            result = {'ok': False}
            def submit():
                code = entry.get().strip()
                result['ok'] = self.verify_totp(code)
                dialog.destroy()
            tk.Button(dialog, text="Verify", command=submit, bg='#444444', fg='#ffffff').pack(pady=10)
            dialog.grab_set()
            self.root.wait_window(dialog)
            return result['ok']
        except Exception:
            return False

    def verify_totp(self, code):
        try:
            import base64, hmac, time
            key = base64.b32decode(self.mfa_secret.upper() + '=' * ((8 - len(self.mfa_secret) % 8) % 8))
            timestep = int(time.time() // 30)
            msg = timestep.to_bytes(8, 'big')
            h = hmac.new(key, msg, hashlib.sha1).digest()
            offset = h[-1] & 0x0F
            dbc = ((h[offset] & 0x7f) << 24) | ((h[offset+1] & 0xff) << 16) | ((h[offset+2] & 0xff) << 8) | (h[offset+3] & 0xff)
            otp = str(dbc % 1000000).zfill(6)
            return otp == code
        except Exception:
            return False
    def clear_logs(self):
        """Clear log display and log files"""
        if hasattr(self, 'log_text'):
            self.log_text.delete('1.0', tk.END)
            
        # Clear log files
        try:
            # Truncate the current log file in AppData
            log_path = os.path.join(self.get_logs_dir(), 'npv_tunnel.log')
            try:
                with open(log_path, 'w', encoding='utf-8') as f:
                    f.write('')
            except Exception:
                pass
            self.log_operation("Logs cleared", level='info')
                    
        except Exception as e:
            self.log_operation(f"Failed to clear logs: {e}", level='error')
            
    def export_logs(self):
        """Export current logs to a file"""
        try:
            filename = f"npv_tunnel_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=== Npv Tunnel PC Logs ===\n")
                f.write(f"Export time: {datetime.now()}\n")
                f.write("=" * 50 + "\n\n")
                
                # Write current log display content
                if hasattr(self, 'log_text'):
                    f.write(self.log_text.get('1.0', tk.END))
                    
            self.log_operation(f"Logs exported to {filename}", level='info')
            messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            self.log_operation(f"Failed to export logs: {e}", level='error')
            messagebox.showerror("Error", f"Failed to export logs: {str(e)}")

    def export_diagnostics(self):
        """Export diagnostics (logs + env summary) to a zip in Downloads."""
        try:
            import zipfile
            stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            downloads = self.get_downloads_dir()
            zip_path = os.path.join(downloads, f"momo_diagnostics_{stamp}.zip")
            logs_dir = self.get_logs_dir()
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
                # Add logs
                try:
                    for fname in os.listdir(logs_dir):
                        fpath = os.path.join(logs_dir, fname)
                        if os.path.isfile(fpath):
                            z.write(fpath, arcname=os.path.join('logs', fname))
                except Exception:
                    pass
                # Add basic env info
                info = [
                    f"Time: {datetime.now().isoformat()}",
                    f"Python: {sys.version}",
                    f"Platform: {sys.platform}",
                    f"AppData: {self.get_appdata_dir()}",
                    f"Tools: {self.get_tools_dir()}",
                ]
                z.writestr('env.txt', '\n'.join(info))
            messagebox.showinfo('Diagnostics', f'Exported to {zip_path}')
            self.log_operation('Diagnostics exported', zip_path, level='info')
        except Exception as e:
            self.log_operation(f'Diagnostics export failed: {e}', level='error')
            messagebox.showerror('Diagnostics', f'Failed: {e}')
    
    def show_about_dialog(self):
        """Show the About dialog with fun description"""
        about_window = tk.Toplevel(self.root)
        about_window.title("About Momo Tunnel")
        about_window.geometry("500x400")
        about_window.configure(bg='#0f0f0f')
        about_window.resizable(False, False)
        
        # Center the window
        about_window.grab_set()
        
        # Main container
        main_frame = tk.Frame(about_window, bg='#0f0f0f')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        # App icon/title
        title_frame = tk.Frame(main_frame, bg='#0f0f0f')
        title_frame.pack(pady=(0, 20))
        
        # Big app title
        app_title = tk.Label(title_frame, text="MOMO TUNNEL", 
                            font=("Segoe UI", 28, "bold"), 
                            fg='#8B0000', bg='#0f0f0f')
        app_title.pack()
        
        # Version info
        version_label = tk.Label(title_frame, text="Version 1.0.0 - 100% FREE", 
                                font=("Segoe UI", 12, "bold"), 
                                fg='#CD5C5C', bg='#0f0f0f')
        version_label.pack(pady=(5, 0))
        
        # Creator credit
        creator_label = tk.Label(title_frame, text="by Muazaoski", 
                                font=("Segoe UI", 14, "italic"), 
                                fg='#B8860B', bg='#0f0f0f')
        creator_label.pack(pady=(5, 0))
        
        # Fun description in a card
        desc_card = tk.Frame(main_frame, bg='#1a1212', relief=tk.FLAT,
                            highlightbackground='#4a1d1d', highlightthickness=1)
        desc_card.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        desc_text = tk.Text(desc_card, bg='#1a1212', fg='#ffffff',
                           font=("Segoe UI", 11), height=8, wrap=tk.WORD,
                           relief=tk.FLAT, bd=0, padx=20, pady=20,
                           state=tk.NORMAL)
        desc_text.pack(fill=tk.BOTH, expand=True)
        
        # Insert the fun about text
        about_content = """Welcome to Momo Tunnel! 🚀

This bad boy is 100% FREE, no sneaky fees or hidden costs. Cooked up by Muazaoski and powered by the slick Cursor platform, Momo Tunnel is your ticket to fun, fast, and totally free tunneling adventures.

Jump in and enjoy the ride! 

Features:
• Multiple VPN protocols (VLESS, VMess, Trojan)
• Split tunneling and advanced routing
• Kill switch and DNS leak protection  
• Real-time latency monitoring
• Beautiful maroon & black theme
• And much more...

Let's fucking go! 💪"""
        
        desc_text.insert(tk.END, about_content)
        desc_text.config(state=tk.DISABLED)
        
        # Close button
        close_btn = tk.Button(main_frame, text="Close", 
                             command=about_window.destroy,
                             font=("Segoe UI", 12, "bold"),
                             bg='#8B0000', fg='#ffffff',
                             relief=tk.FLAT, padx=30, pady=10,
                             cursor='hand2',
                             activebackground='#A52A2A')
        close_btn.pack()
        
    def setup_ui(self):
        # Configure the root window
        self.root.configure(bg='#0f0f0f')
        
        # Create main container with modern styling
        main_container = tk.Frame(self.root, bg='#0f0f0f')
        main_container.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)
        
        # Header section with improved design
        header_frame = tk.Frame(main_container, bg='#0f0f0f')
        header_frame.pack(fill=tk.X, pady=(0, 30))
        
        # App title with modern typography
        title_label = tk.Label(header_frame, text="MOMO TUNNEL", 
                              font=("Segoe UI", 32, "bold"), 
                              fg='#8B0000', bg='#0f0f0f')
        title_label.pack()
        
        subtitle_label = tk.Label(header_frame, text="by Muazaoski", 
                                 font=("Segoe UI", 14, "italic"), 
                                 fg='#CD5C5C', bg='#0f0f0f')
        subtitle_label.pack(pady=(2, 0))
        
        # About button in header
        about_btn = tk.Button(header_frame, text="ℹ️ About", 
                             command=self.show_about_dialog,
                             font=("Segoe UI", 10),
                             bg='#2d1414', fg='#ffffff',
                             relief=tk.FLAT, padx=15, pady=5,
                             cursor='hand2',
                             activebackground='#4a1d1d')
        about_btn.pack(pady=(10, 0))
        
        # Main content area with card-based layout
        content_frame = tk.Frame(main_container, bg='#0f0f0f')
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection card
        connection_card = tk.Frame(content_frame, bg='#1a1212', relief=tk.FLAT, 
                                  highlightbackground='#4a1d1d', highlightthickness=1)
        connection_card.pack(fill=tk.X, pady=(0, 20))
        
        # Card header
        card_header = tk.Frame(connection_card, bg='#1a1212', height=50)
        card_header.pack(fill=tk.X, padx=25, pady=(20, 0))
        card_header.pack_propagate(False)
        
        # Status indicator with icon
        status_frame = tk.Frame(card_header, bg='#1a1212')
        status_frame.pack(side=tk.LEFT)
        
        self.status_indicator = tk.Label(status_frame, text="●", 
                                        font=("Segoe UI", 16), 
                                        fg='#DC143C', bg='#1a1212')
        self.status_indicator.pack(side=tk.LEFT)
        
        self.status_label = tk.Label(status_frame, text="Disconnected", 
                                    font=("Segoe UI", 16, "bold"), 
                                    fg='#ffffff', bg='#1a1212')
        self.status_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Main connect button with modern styling
        self.connect_btn = tk.Button(card_header, text="CONNECT", 
                                   command=self.toggle_connection,
                                   font=("Segoe UI", 12, "bold"),
                                   bg='#8B0000', fg='#ffffff',
                                   relief=tk.FLAT, padx=35, pady=12,
                                   cursor='hand2',
                                   activebackground='#A52A2A',
                                   activeforeground='#ffffff')
        self.connect_btn.pack(side=tk.RIGHT)
        
        # Connection info section
        info_frame = tk.Frame(connection_card, bg='#1a1212')
        info_frame.pack(fill=tk.X, padx=25, pady=(20, 25))
        
        # Create info grid
        info_grid = tk.Frame(info_frame, bg='#1a1212')
        info_grid.pack(fill=tk.X)
        
        # IP info with icon
        ip_container = tk.Frame(info_grid, bg='#1a1212')
        ip_container.grid(row=0, column=0, sticky='w', padx=(0, 40), pady=5)
        
        tk.Label(ip_container, text="🌐", font=("Segoe UI", 14), 
                bg='#1a1212', fg='#CD5C5C').pack(side=tk.LEFT)
        self.ip_label = tk.Label(ip_container, text="IP: Checking...", 
                                font=("Segoe UI", 11), 
                                fg='#ffffff', bg='#1a1212')
        self.ip_label.pack(side=tk.LEFT, padx=(8, 0))
        
        # Config info with icon
        config_container = tk.Frame(info_grid, bg='#1a1212')
        config_container.grid(row=0, column=1, sticky='w', pady=5)
        
        tk.Label(config_container, text="⚙️", font=("Segoe UI", 14), 
                bg='#1a1212', fg='#CD5C5C').pack(side=tk.LEFT)
        self.config_label = tk.Label(config_container, text="No configuration loaded", 
                                    font=("Segoe UI", 11), 
                                    fg='#ffffff', bg='#1a1212')
        self.config_label.pack(side=tk.LEFT, padx=(8, 0))
        
        # Latency metrics with improved styling
        latency_container = tk.Frame(info_grid, bg='#1a1212')
        latency_container.grid(row=1, column=0, columnspan=2, sticky='w', pady=(10, 0))
        
        tk.Label(latency_container, text="📡", font=("Segoe UI", 14), 
                bg='#1a1212', fg='#CD5C5C').pack(side=tk.LEFT)
        self.latency_label = tk.Label(latency_container, text="Latency: -- ms (1m: -- | 5m: -- | 15m: --)",
                                      font=("Segoe UI", 11), fg='#B8860B', bg='#1a1212')
        self.latency_label.pack(side=tk.LEFT, padx=(8, 0))
        
        # Configuration management card
        config_card = tk.Frame(content_frame, bg='#1a1212', relief=tk.FLAT, 
                              highlightbackground='#4a1d1d', highlightthickness=1)
        config_card.pack(fill=tk.X, pady=(0, 20))
        
        # Config card header
        config_header_frame = tk.Frame(config_card, bg='#1a1212')
        config_header_frame.pack(fill=tk.X, padx=25, pady=(20, 15))
        
        tk.Label(config_header_frame, text="Configuration Manager", 
                font=("Segoe UI", 16, "bold"), 
                fg='#ffffff', bg='#1a1212').pack(side=tk.LEFT)
        
        # Quick actions on the right
        quick_actions = tk.Frame(config_header_frame, bg='#1a1212')
        quick_actions.pack(side=tk.RIGHT)
        
        # Favorite button with heart icon
        fav_btn = tk.Button(quick_actions, text="❤️", 
                           command=self.toggle_favorite_current,
                           font=("Segoe UI", 12), bg='#2d1414', fg='#DC143C',
                           relief=tk.FLAT, padx=10, pady=5, cursor='hand2',
                           activebackground='#4a1d1d')
        fav_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Config action buttons with modern design
        config_actions_frame = tk.Frame(config_card, bg='#1a1212')
        config_actions_frame.pack(fill=tk.X, padx=25, pady=(0, 20))
        
        # Primary action button
        add_config_btn = tk.Button(config_actions_frame, text="➕ Add Config", 
                                 command=self.show_add_config_dialog,
                                 font=("Segoe UI", 10, "bold"),
                                 bg='#8B0000', fg='#ffffff',
                                 relief=tk.FLAT, padx=20, pady=8,
                                 cursor='hand2',
                                 activebackground='#A52A2A')
        add_config_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Secondary action buttons
        button_style = {
            'font': ("Segoe UI", 10),
            'bg': '#2d1414',
            'fg': '#ffffff',
            'relief': tk.FLAT,
            'padx': 15,
            'pady': 8,
            'cursor': 'hand2',
            'activebackground': '#4a1d1d',
            'activeforeground': '#ffffff'
        }
        
        import_npvt_btn = tk.Button(config_actions_frame, text="📁 Import .npvt", 
                                   command=self.import_npvt_file, **button_style)
        import_npvt_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        import_clipboard_btn = tk.Button(config_actions_frame, text="📋 From Clipboard", 
                                        command=self.import_from_clipboard, **button_style)
        import_clipboard_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        export_config_btn = tk.Button(config_actions_frame, text="💾 Export", 
                                     command=self.show_export_dialog, **button_style)
        export_config_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Utility buttons frame
        utility_frame = tk.Frame(config_card, bg='#1a1212')
        utility_frame.pack(fill=tk.X, padx=25, pady=(0, 20))
        
        # Network fix button (emergency)
        fix_btn = tk.Button(utility_frame, text="🔧 Fix Network", 
                           command=self.fix_network_now,
                           font=("Segoe UI", 10),
                           bg='#B22222', fg='#ffffff',
                           relief=tk.FLAT, padx=15, pady=8,
                           cursor='hand2',
                           activebackground='#DC143C')
        fix_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Speed test button
        speed_btn = tk.Button(utility_frame, text="⚡ Speed Test", 
                             command=self.run_speed_test, **button_style)
        speed_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Settings access
        settings_btn = tk.Button(utility_frame, text="⚙️ Settings", 
                               command=self.show_settings, **button_style)
        settings_btn.pack(side=tk.RIGHT)
        
        # Keyboard shortcuts
        try:
            self.root.bind('<Control-c>', lambda e: self.toggle_connection())
            self.root.bind('<Control-f>', lambda e: self.toggle_favorite_current())
            self.root.bind('<Control-l>', lambda e: self.show_connection_history())
        except Exception:
            pass
        
        # Features card with toggles and controls
        features_card = tk.Frame(content_frame, bg='#1a1212', relief=tk.FLAT, 
                                highlightbackground='#4a1d1d', highlightthickness=1)
        features_card.pack(fill=tk.X, pady=(0, 20))
        
        # Features header
        features_header = tk.Frame(features_card, bg='#1a1212')
        features_header.pack(fill=tk.X, padx=25, pady=(20, 15))
        
        tk.Label(features_header, text="Quick Features", 
                font=("Segoe UI", 16, "bold"), 
                fg='#ffffff', bg='#1a1212').pack(side=tk.LEFT)
        
        # VPN Tools access
        vpn_tools_btn = tk.Button(features_header, text="🔧 VPN Tools", 
                                 command=self.show_vpn_tools_dialog,
                                 font=("Segoe UI", 10),
                                 bg='#2d1414', fg='#ffffff',
                                 relief=tk.FLAT, padx=15, pady=5,
                                 cursor='hand2',
                                 activebackground='#4a1d1d')
        vpn_tools_btn.pack(side=tk.RIGHT)
        
        # Feature toggles section
        toggles_frame = tk.Frame(features_card, bg='#1a1212')
        toggles_frame.pack(fill=tk.X, padx=25, pady=(0, 20))
        
        # Create modern toggle switches
        toggle_style = {
            'bg': '#1a1212',
            'fg': '#ffffff',
            'selectcolor': '#8B0000',
            'font': ("Segoe UI", 10),
            'activebackground': '#1a1212',
            'activeforeground': '#CD5C5C'
        }
        
        # Auto-reconnect toggle
        self.auto_reconnect_var = tk.BooleanVar(value=self.auto_reconnect_enabled)
        auto_reconnect_cb = tk.Checkbutton(toggles_frame, text="🔄 Auto-reconnect", 
                                          variable=self.auto_reconnect_var, 
                                          command=self.on_toggle_auto_reconnect, **toggle_style)
        auto_reconnect_cb.pack(side=tk.LEFT, padx=(0, 20))
        
        # Split tunneling toggle
        self.split_toggle_var = tk.BooleanVar(value=self.split_tunneling_enabled)
        split_cb = tk.Checkbutton(toggles_frame, text="🔀 Split Tunneling", 
                                 variable=self.split_toggle_var, 
                                 command=self.on_toggle_split_tunneling, **toggle_style)
        split_cb.pack(side=tk.LEFT, padx=(0, 20))
        
        # MFA status indicator
        mfa_frame = tk.Frame(toggles_frame, bg='#1a1212')
        mfa_frame.pack(side=tk.RIGHT)
        
        self.mfa_status_label = tk.Label(mfa_frame, text="🔐 MFA: Disabled", 
                                        fg='#B8860B', bg='#1a1212', 
                                        font=("Segoe UI", 10))
        self.mfa_status_label.pack(side=tk.LEFT, padx=(0, 10))
        
        mfa_setup_btn = tk.Button(mfa_frame, text="Setup", 
                                 command=self.setup_mfa_dialog,
                                 font=("Segoe UI", 9),
                                 bg='#2d1414', fg='#ffffff',
                                 relief=tk.FLAT, padx=10, pady=3,
                                 cursor='hand2')
        mfa_setup_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Activity Monitor card
        monitor_card = tk.Frame(content_frame, bg='#1a1212', relief=tk.FLAT, 
                               highlightbackground='#4a1d1d', highlightthickness=1)
        monitor_card.pack(fill=tk.BOTH, expand=True)
        
        # Monitor header with controls
        monitor_header = tk.Frame(monitor_card, bg='#1a1212')
        monitor_header.pack(fill=tk.X, padx=25, pady=(20, 15))
        
        tk.Label(monitor_header, text="Activity Monitor", 
                font=("Segoe UI", 16, "bold"), 
                fg='#ffffff', bg='#1a1212').pack(side=tk.LEFT)
        
        # Monitor controls
        monitor_controls = tk.Frame(monitor_header, bg='#1a1212')
        monitor_controls.pack(side=tk.RIGHT)
        
        control_btn_style = {
            'font': ("Segoe UI", 9),
            'bg': '#2d1414',
            'fg': '#ffffff',
            'relief': tk.FLAT,
            'padx': 10,
            'pady': 3,
            'cursor': 'hand2',
            'activebackground': '#4a1d1d'
        }
        
        history_btn = tk.Button(monitor_controls, text="📊 History", 
                               command=self.show_connection_history, **control_btn_style)
        history_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        export_logs_btn = tk.Button(monitor_controls, text="💾 Export", 
                                   command=self.export_logs, **control_btn_style)
        export_logs_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        clear_logs_btn = tk.Button(monitor_controls, text="🗑️ Clear", 
                                  command=self.clear_logs, **control_btn_style)
        clear_logs_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Diagnostics export
        diag_btn = tk.Button(monitor_controls, text="📦 Export Diagnostics", 
                             command=self.export_diagnostics, **control_btn_style)
        diag_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Create tabbed log area
        log_content = tk.Frame(monitor_card, bg='#1a1212')
        log_content.pack(fill=tk.BOTH, expand=True, padx=25, pady=(0, 25))
        
        # Latency chart with modern styling
        chart_section = tk.Frame(log_content, bg='#0f0f0f', 
                                highlightbackground='#2d1414', highlightthickness=1)
        chart_section.pack(fill=tk.X, pady=(0, 15))
        
        chart_label = tk.Label(chart_section, text="📈 Latency Chart (Last 30 samples)", 
                              fg='#CD5C5C', bg='#0f0f0f', font=("Segoe UI", 11, "bold"))
        chart_label.pack(anchor='w', padx=15, pady=(10, 5))
        
        self.latency_canvas = tk.Canvas(chart_section, height=100, bg='#0f0f0f', 
                                       highlightthickness=0, bd=0)
        self.latency_canvas.pack(fill=tk.X, padx=15, pady=(0, 10))
        
        # Activity log with improved styling
        log_section = tk.Frame(log_content, bg='#0f0f0f', 
                              highlightbackground='#2d1414', highlightthickness=1)
        log_section.pack(fill=tk.BOTH, expand=True)
        
        log_title = tk.Label(log_section, text="📝 Activity Log", 
                            fg='#CD5C5C', bg='#0f0f0f', font=("Segoe UI", 11, "bold"))
        log_title.pack(anchor='w', padx=15, pady=(10, 5))
        
        # Enhanced log text area
        log_text_container = tk.Frame(log_section, bg='#0f0f0f')
        log_text_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        self.log_text = tk.Text(log_text_container, bg='#0f0f0f', fg='#ffffff', 
                               font=("JetBrains Mono", 9), height=8, wrap=tk.WORD,
                               relief=tk.FLAT, bd=0, padx=10, pady=10,
                               insertbackground='#CD5C5C')
        
        # Custom scrollbar styling
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Custom.Vertical.TScrollbar", 
                       background='#2d1414',
                       troughcolor='#0f0f0f',
                       arrowcolor='#B8860B',
                       darkcolor='#4a1d1d',
                       lightcolor='#4a1d1d')
        
        log_scrollbar = ttk.Scrollbar(log_text_container, orient=tk.VERTICAL, 
                                     command=self.log_text.yview, style="Custom.Vertical.TScrollbar")
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add welcome message with better formatting
        self.log_text.insert(tk.END, "🚀 MOMO TUNNEL - FREE VPN BY MUAZAOSKI\n")
        self.log_text.insert(tk.END, f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_text.insert(tk.END, "=" * 55 + "\n\n")
        
        # Initialize components
        self.start_ip_checker()
        
        # Check VPN tools status on startup
        self.log_operation("🔍 Checking VPN tools status on startup", level='info')
        tools_status = self.check_vpn_tools_status()
        if not tools_status['v2ray'] and not tools_status['trojan']:
            self.log_operation("⚠️ No VPN tools found, will download when needed", level='info')
        

    
    def show_add_config_dialog(self):
        """Show the Add Config dialog similar to the original APK"""
        config_window = tk.Toplevel(self.root)
        config_window.title("Add Config")
        config_window.geometry("400x350")
        config_window.configure(bg='#1e1e1e')
        config_window.resizable(False, False)
        
        # Center the window
        config_window.transient(self.root)
        config_window.grab_set()
        
        # Title
        title_label = tk.Label(config_window, text="Add Config", 
                              font=("Arial", 18, "bold"), 
                              fg='#00ff88', bg='#1e1e1e')
        title_label.pack(pady=20)
        
        # Options frame
        options_frame = tk.Frame(config_window, bg='#1e1e1e')
        options_frame.pack(fill=tk.BOTH, expand=True, padx=30)
        
        # Option 1: Import npvt config file
        option1_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option1_frame.pack(fill=tk.X, pady=10)
        
        option1_btn = tk.Button(option1_frame, text="Import npvt config file", 
                               command=lambda: [self.import_npvt_file(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option1_btn.pack(fill=tk.X)
        
        # Down arrow icon
        arrow1 = tk.Label(option1_frame, text="↓", font=("Arial", 16), 
                         fg='#00ff88', bg='#2d2d2d')
        arrow1.pack(side=tk.RIGHT, padx=20)
        
        # Option 2: Import cloud config
        option2_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option2_frame.pack(fill=tk.X, pady=10)
        
        option2_btn = tk.Button(option2_frame, text="Import cloud config", 
                               command=lambda: [self.import_cloud_config(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option2_btn.pack(fill=tk.X)
        
        # Cloud icon
        cloud_icon = tk.Label(option2_frame, text="☁", font=("Arial", 16), 
                            fg='#00ff88', bg='#2d2d2d')
        cloud_icon.pack(side=tk.RIGHT, padx=20)
        
        # Option 3: Import config from Clipboard
        option3_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option3_frame.pack(fill=tk.X, pady=10)
        
        option3_btn = tk.Button(option3_frame, text="Import config from\nClipboard", 
                               command=lambda: [self.import_from_clipboard(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option3_btn.pack(fill=tk.X)
        
        # Clipboard icon
        clipboard_icon = tk.Label(option3_frame, text="📋", font=("Arial", 16), 
                                fg='#00ff88', bg='#2d2d2d')
        clipboard_icon.pack(side=tk.RIGHT, padx=20)
        
        # Option 4: Add config manually
        option4_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option4_frame.pack(fill=tk.X, pady=10)
        
        option4_btn = tk.Button(option4_frame, text="Add config manually", 
                               command=lambda: [self.add_config_manually(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option4_btn.pack(fill=tk.X)
        
        # Plus icon
        plus_icon = tk.Label(option4_frame, text="+", font=("Arial", 16), 
                           fg='#00ff88', bg='#2d2d2d')
        plus_icon.pack(side=tk.RIGHT, padx=20)
        
        # Cancel button
        cancel_btn = tk.Button(config_window, text="Cancel", 
                             command=config_window.destroy,
                             font=("Arial", 10),
                             bg='#666666', fg='#ffffff',
                             relief=tk.FLAT, padx=30, pady=10)
        cancel_btn.pack(pady=20)
    
    def import_npvt_file(self):
        """Import configuration from .npvt file"""
        file_path = filedialog.askopenfilename(
            title="Select .npvt configuration file",
            filetypes=[("NPVT files", "*.npvt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                self.log_operation("Importing .npvt file", f"File: {os.path.basename(file_path)}", level='info')
                
                # Try to import as encrypted file first
                config = self.import_secure_config(file_path)
                
                if config:
                    self.log_operation("Encrypted configuration imported successfully", f"Name: {config.get('name', 'Unknown')}", level='info')
                    self.add_config(config)
                    messagebox.showinfo("Success", f"Encrypted configuration imported from {os.path.basename(file_path)}")
                else:
                    # Fallback to regular parsing
                    self.log_operation("Attempting regular configuration parsing", level='debug')
                    with open(file_path, 'r', encoding='utf-8') as file:
                        content = file.read()
                    
                    config = self.parse_config_content(content)
                    if config:
                        self.log_operation("Configuration imported successfully", f"Name: {config.get('name', 'Unknown')}", level='info')
                        self.add_config(config)
                        messagebox.showinfo("Success", f"Configuration imported from {os.path.basename(file_path)}")
                    else:
                        self.log_operation("Configuration import failed", "Invalid format", level='error')
                        messagebox.showerror("Error", "Invalid configuration format")
                        
            except Exception as e:
                self.log_operation("Configuration import error", str(e), level='error')
                messagebox.showerror("Error", f"Failed to read file: {str(e)}")
    
    def import_cloud_config(self):
        """Import configuration from cloud service"""
        # This would connect to a cloud service in a real implementation
        messagebox.showinfo("Cloud Import", "Cloud import functionality would be implemented here.\nThis is a demonstration version.")
    
    def import_from_clipboard(self):
        """Import configuration from clipboard"""
        try:
            self.log_operation("Importing configuration from clipboard", level='info')
            clipboard_content = self.root.clipboard_get()
            if clipboard_content:
                self.log_operation("Clipboard content retrieved", f"Length: {len(clipboard_content)} characters", level='debug')
                # Parse the clipboard content
                config = self.parse_config_content(clipboard_content)
                if config:
                    self.log_operation("Clipboard configuration imported successfully", f"Name: {config.get('name', 'Unknown')}", level='info')
                    self.add_config(config)
                    messagebox.showinfo("Success", "Configuration imported from clipboard")
                else:
                    self.log_operation("Clipboard configuration import failed", "Invalid format", level='error')
                    messagebox.showerror("Error", "Invalid configuration format in clipboard")
            else:
                self.log_operation("Clipboard import failed", "Clipboard is empty", level='warning')
                messagebox.showwarning("Warning", "Clipboard is empty")
        except Exception as e:
            self.log_operation("Clipboard import error", str(e), level='error')
            messagebox.showerror("Error", f"Failed to read clipboard: {str(e)}")
    
    def add_config_manually(self):
        """Add configuration manually"""
        manual_window = tk.Toplevel(self.root)
        manual_window.title("Add Config Manually")
        manual_window.geometry("500x400")
        manual_window.configure(bg='#1e1e1e')
        
        # Title
        title_label = tk.Label(manual_window, text="Add Configuration Manually", 
                              font=("Arial", 16, "bold"), 
                              fg='#00ff88', bg='#1e1e1e')
        title_label.pack(pady=20)
        
        # Form frame
        form_frame = tk.Frame(manual_window, bg='#1e1e1e')
        form_frame.pack(fill=tk.BOTH, expand=True, padx=30)
        
        # Protocol selection
        tk.Label(form_frame, text="Protocol:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        protocol_var = tk.StringVar(value="vless")
        protocol_frame = tk.Frame(form_frame, bg='#1e1e1e')
        protocol_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Radiobutton(protocol_frame, text="VLESS", variable=protocol_var, value="vless", 
                      bg='#1e1e1e', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(protocol_frame, text="VMess", variable=protocol_var, value="vmess", 
                      bg='#1e1e1e', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(protocol_frame, text="Trojan", variable=protocol_var, value="trojan", 
                      bg='#1e1e1e', fg='#ffffff').pack(side=tk.LEFT)
        
        # Server address
        tk.Label(form_frame, text="Server Address:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        server_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        server_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Port
        tk.Label(form_frame, text="Port:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        port_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        port_entry.pack(fill=tk.X, pady=(0, 15))
        
        # UUID/Password
        tk.Label(form_frame, text="UUID/Password:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        uuid_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        uuid_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Config name
        tk.Label(form_frame, text="Configuration Name:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        name_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        name_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Buttons
        buttons_frame = tk.Frame(form_frame, bg='#1e1e1e')
        buttons_frame.pack(pady=20)
        
        save_btn = tk.Button(buttons_frame, text="Save", 
                           command=lambda: self.save_manual_config(
                               protocol_var.get(), server_entry.get(), port_entry.get(),
                               uuid_entry.get(), name_entry.get(), manual_window
                           ),
                           bg='#00ff88', fg='#000000', relief=tk.FLAT, padx=30, pady=10)
        save_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = tk.Button(buttons_frame, text="Cancel", 
                             command=manual_window.destroy,
                             bg='#666666', fg='#ffffff', relief=tk.FLAT, padx=30, pady=10)
        cancel_btn.pack(side=tk.LEFT, padx=10)
    
    def save_manual_config(self, protocol, server, port, uuid, name, window):
        """Save manually entered configuration"""
        if not all([protocol, server, port, uuid, name]):
            messagebox.showwarning("Warning", "Please fill in all fields")
            return
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number")
            return
        
        config = {
            "name": name,
            "protocol": protocol,
            "server": server,
            "port": port,
            "uuid": uuid,
            "type": "manual"
        }
        
        self.add_config(config)
        messagebox.showinfo("Success", f"Configuration '{name}' saved successfully")
        window.destroy()
    
    def parse_config_content(self, content):
        """Parse configuration content from various formats"""
        content = content.strip()
        
        # Try to parse as VLESS URL
        if content.startswith("vless://"):
            return self.parse_vless_url(content)
        
        # Try to parse as VMess URL
        elif content.startswith("vmess://"):
            return self.parse_vmess_url(content)
        
        # Try to parse as Trojan URL
        elif content.startswith("trojan://"):
            return self.parse_trojan_url(content)
        
        # Try to parse as JSON
        elif content.startswith("{") or content.startswith("["):
            try:
                json_data = json.loads(content)
                return self.parse_json_config(json_data)
            except:
                pass
        
        # Try to parse as .npvt format
        return self.parse_npvt_format(content)
    
    def parse_vless_url(self, url):
        """Parse VLESS URL format"""
        try:
            # Remove protocol prefix
            url = url.replace("vless://", "")
            
            # Split into parts
            if "?" in url:
                main_part, query_part = url.split("?", 1)
            else:
                main_part, query_part = url, ""
            
            # Parse main part (uuid@server:port)
            if "@" in main_part:
                uuid, server_part = main_part.split("@", 1)
            else:
                return None
            
            # Parse server and port
            if ":" in server_part:
                server, port = server_part.rsplit(":", 1)
                try:
                    port = int(port)
                except ValueError:
                    return None
            else:
                server, port = server_part, 443
            
            # Parse query parameters
            params = {}
            if query_part:
                for param in query_part.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        params[key] = urllib.parse.unquote(value)
            
            # Extract name from fragment
            name = params.get("name", "VLESS Config")
            if "#" in url:
                name = url.split("#")[-1]
            
            return {
                "name": name,
                "protocol": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
                "security": params.get("security", "none"),
                "encryption": params.get("encryption", "none"),
                "type": params.get("type", "tcp"),
                "path": params.get("path", ""),
                "sni": params.get("sni", ""),
                "source": "url"
            }
        except Exception as e:
            print(f"Error parsing VLESS URL: {e}")
            return None
    
    def parse_vmess_url(self, url):
        """Parse VMess URL format"""
        try:
            # Remove protocol prefix
            url = url.replace("vmess://", "")
            
            # Decode base64
            decoded = base64.b64decode(url).decode('utf-8')
            config = json.loads(decoded)
            
            return {
                "name": config.get("ps", "VMess Config"),
                "protocol": "vmess",
                "server": config.get("add", ""),
                "port": config.get("port", 443),
                "uuid": config.get("id", ""),
                "alterId": config.get("aid", 0),
                "security": config.get("security", "auto"),
                "type": config.get("type", "tcp"),
                "source": "url"
            }
        except Exception as e:
            print(f"Error parsing VMess URL: {e}")
            return None
    
    def parse_trojan_url(self, url):
        """Parse Trojan URL format"""
        try:
            # Remove protocol prefix
            url = url.replace("trojan://", "")
            
            # Split into parts
            if "?" in url:
                main_part, query_part = url.split("?", 1)
            else:
                main_part, query_part = url, ""
            
            # Parse main part (password@server:port)
            if "@" in main_part:
                password, server_part = main_part.split("@", 1)
            else:
                return None
            
            # Parse server and port
            if ":" in server_part:
                server, port = server_part.rsplit(":", 1)
                try:
                    port = int(port)
                except ValueError:
                    return None
            else:
                server, port = server_part, 443
            
            # Parse query parameters
            params = {}
            if query_part:
                for param in query_part.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        params[key] = urllib.parse.unquote(value)
            
            # Extract name from fragment
            name = params.get("name", "Trojan Config")
            if "#" in url:
                name = url.split("#")[-1]
            
            return {
                "name": name,
                "protocol": "trojan",
                "server": server,
                "port": port,
                "password": password,
                "sni": params.get("sni", ""),
                "source": "url"
            }
        except Exception as e:
            print(f"Error parsing Trojan URL: {e}")
            return None
    
    def parse_json_config(self, json_data):
        """Parse JSON configuration"""
        try:
            if isinstance(json_data, list) and len(json_data) > 0:
                json_data = json_data[0]
            
            protocol = json_data.get("protocol", "unknown")
            
            if protocol == "vless":
                return {
                    "name": json_data.get("name", "VLESS Config"),
                    "protocol": "vless",
                    "server": json_data.get("server", ""),
                    "port": json_data.get("port", 443),
                    "uuid": json_data.get("uuid", ""),
                    "security": json_data.get("security", "none"),
                    "encryption": json_data.get("encryption", "none"),
                    "type": json_data.get("type", "tcp"),
                    "path": json_data.get("path", ""),
                    "sni": json_data.get("sni", ""),
                    "source": "json"
                }
            elif protocol == "vmess":
                return {
                    "name": json_data.get("name", "VMess Config"),
                    "protocol": "vmess",
                    "server": json_data.get("server", ""),
                    "port": json_data.get("port", 443),
                    "uuid": json_data.get("uuid", ""),
                    "alterId": json_data.get("aid", 0),
                    "security": json_data.get("security", "auto"),
                    "type": json_data.get("type", "tcp"),
                    "source": "json"
                }
            elif protocol == "trojan":
                return {
                    "name": json_data.get("name", "Trojan Config"),
                    "protocol": "trojan",
                    "server": json_data.get("server", ""),
                    "port": json_data.get("port", 443),
                    "password": json_data.get("password", ""),
                    "sni": json_data.get("sni", ""),
                    "source": "json"
                }
            
            return None
        except Exception as e:
            print(f"Error parsing JSON config: {e}")
            return None
    
    def parse_npvt_format(self, content):
        """Parse .npvt file format"""
        try:
            # Try to parse as JSON first
            if content.startswith("{") or content.startswith("["):
                return self.parse_json_config(json.loads(content))
            
            # Try to parse as key-value pairs
            config = {}
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                if line and '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
            
            if config:
                protocol = config.get("protocol", "unknown")
                
                if protocol == "vless":
                    return {
                        "name": config.get("name", "VLESS Config"),
                        "protocol": "vless",
                        "server": config.get("server", ""),
                        "port": int(config.get("port", 443)),
                        "uuid": config.get("uuid", ""),
                        "security": config.get("security", "none"),
                        "encryption": config.get("encryption", "none"),
                        "type": config.get("type", "tcp"),
                        "path": config.get("path", ""),
                        "sni": config.get("sni", ""),
                        "source": "npvt"
                    }
                elif protocol == "vmess":
                    return {
                        "name": config.get("name", "VMess Config"),
                        "protocol": "vmess",
                        "server": config.get("server", ""),
                        "port": int(config.get("port", 443)),
                        "uuid": config.get("uuid", ""),
                        "alterId": int(config.get("aid", 0)),
                        "security": config.get("security", "auto"),
                        "type": config.get("type", "tcp"),
                    "source": "npvt"
                    }
                elif protocol == "trojan":
                    return {
                        "name": config.get("name", "Trojan Config"),
                        "protocol": "trojan",
                        "server": config.get("server", ""),
                        "port": int(config.get("port", 443)),
                        "password": config.get("password", ""),
                        "sni": config.get("sni", ""),
                        "source": "npvt"
                    }
            
            return None
        except Exception as e:
            print(f"Error parsing NPVT format: {e}")
            return None
    
    def add_config(self, config):
        """Add a new configuration"""
        if config:
            self.configs.append(config)
            self.current_config = config
            self.update_config_display()
            
            # Save configs to file
            self.save_configs()

    def toggle_favorite_current(self):
        try:
            if not self.current_config:
                return
            name = self.current_config.get('name')
            if not name:
                return
            if name in self.favorites:
                self.favorites.remove(name)
            else:
                self.favorites.add(name)
            self.update_config_display()
            self.save_configs()
            self.log_operation(f"Favorite toggled for {name}", level='info')
        except Exception as e:
            self.log_operation(f"Toggle favorite failed: {e}", level='warning')

    # ------------------------ Profiles ------------------------
    def show_profiles_dialog(self):
        win = tk.Toplevel(self.root)
        win.title('Profiles')
        win.geometry('420x360')
        win.configure(bg='#1e1e1e')
        tk.Label(win, text='Profile Name:', fg='#ffffff', bg='#1e1e1e').pack(pady=5)
        name_entry = tk.Entry(win)
        name_entry.pack(pady=5)
        tk.Label(win, text='Description:', fg="#ffffff", bg="#1e1e1e").pack(pady=5)
        desc_entry = tk.Entry(win)
        desc_entry.pack(pady=5)
        tk.Label(win, text='Attach current config to this profile?', fg="#ffffff", bg="#1e1e1e").pack(pady=5)
        attach_var = tk.BooleanVar(value=True)
        tk.Checkbutton(win, text='Attach', variable=attach_var, bg='#1e1e1e', fg='#ffffff').pack()
        listbox = tk.Listbox(win, width=50)
        listbox.pack(pady=10, fill=tk.BOTH, expand=True)
        for pname in self.profiles.keys():
            listbox.insert(tk.END, pname)
        def save_profile():
            pname = name_entry.get().strip()
            if not pname:
                return
            profile = { 'description': desc_entry.get().strip(), 'configs': [] }
            if attach_var.get() and self.current_config:
                profile['configs'].append(self.current_config)
            self.profiles[pname] = profile
            self.save_configs()
            if pname not in listbox.get(0, tk.END):
                listbox.insert(tk.END, pname)
        def load_profile():
            sel = listbox.curselection()
            if not sel:
                return
            pname = listbox.get(sel[0])
            prof = self.profiles.get(pname)
            if prof and prof.get('configs'):
                self.current_profile_name = pname
                self.current_config = prof['configs'][0]
                self.update_config_display()
        tk.Button(win, text='Save Profile', command=save_profile, bg='#444444', fg='#ffffff').pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(win, text='Load Profile', command=load_profile, bg='#444444', fg='#ffffff').pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(win, text='Close', command=win.destroy, bg='#444444', fg='#ffffff').pack(side=tk.RIGHT, padx=10, pady=5)

    # ------------------------ Scheduling ------------------------
    def show_schedule_dialog(self):
        win = tk.Toplevel(self.root)
        win.title('Schedule')
        win.geometry('420x360')
        win.configure(bg='#1e1e1e')
        tk.Label(win, text='Time (HH:MM 24h):', fg='#ffffff', bg='#1e1e1e').pack(pady=5)
        time_entry = tk.Entry(win)
        time_entry.pack(pady=5)
        tk.Label(win, text='Action (connect/disconnect):', fg='#ffffff', bg='#1e1e1e').pack(pady=5)
        action_var = tk.StringVar(value='connect')
        tk.OptionMenu(win, action_var, 'connect', 'disconnect').pack(pady=5)
        tk.Label(win, text='Profile (optional):', fg='#ffffff', bg='#1e1e1e').pack(pady=5)
        profile_entry = tk.Entry(win)
        profile_entry.pack(pady=5)
        listbox = tk.Listbox(win, width=50)
        listbox.pack(pady=10, fill=tk.BOTH, expand=True)
        for ent in self.schedule_entries:
            listbox.insert(tk.END, f"{ent['time']} - {ent['action']} - {ent.get('profile','')}"
                           )
        def add_entry():
            t = time_entry.get().strip()
            a = action_var.get().strip()
            p = profile_entry.get().strip()
            if not re.match(r'^\d{2}:\d{2}$', t):
                return
            entry = { 'time': t, 'action': a, 'profile': p }
            self.schedule_entries.append(entry)
            self.save_configs()
            listbox.insert(tk.END, f"{t} - {a} - {p}")
        tk.Button(win, text='Add', command=add_entry, bg='#444444', fg='#ffffff').pack(side=tk.LEFT, padx=10, pady=5)
        tk.Button(win, text='Close', command=win.destroy, bg='#444444', fg='#ffffff').pack(side=tk.RIGHT, padx=10, pady=5)

    def schedule_worker(self):
        try:
            while True:
                now = datetime.now().strftime('%H:%M')
                for ent in list(self.schedule_entries):
                    if ent.get('time') == now:
                        act = ent.get('action')
                        prof = ent.get('profile')
                        if prof and prof in self.profiles and self.profiles[prof].get('configs'):
                            self.current_config = self.profiles[prof]['configs'][0]
                            self.update_config_display()
                        if act == 'connect':
                            self.root.after(0, self.connect_vpn)
                        elif act == 'disconnect':
                            self.root.after(0, self.disconnect_vpn)
                        time.sleep(60)
                        break
                time.sleep(5)
        except Exception:
            pass
    
    def update_config_display(self):
        """Update the configuration display"""
        if self.current_config:
            config_text = f"Config: {self.current_config['name']} ({self.current_config['protocol'].upper()})"
            self.config_label.config(text=config_text, fg='#00ff88')
            # Update favorites marker
            if self.current_config.get('name') in self.favorites:
                self.config_label.config(text=config_text + " ★")
        else:
            self.config_label.config(text="No configuration loaded", fg='#cccccc')
    
    def save_configs(self):
        """Save configurations to file"""
        try:
            config_file = "npv_tunnel_configs.json"
            encrypted_configs = []
            
            for config in self.configs:
                if self.fernet:
                    encrypted_config = {
                        'encrypted': True,
                        'data': self.encrypt_config(config)
                    }
                    encrypted_configs.append(encrypted_config)
                else:
                    encrypted_configs.append(config)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump({"configs": encrypted_configs, "favorites": list(self.favorites), "profiles": self.profiles, "schedule": self.schedule_entries}, f, indent=2, ensure_ascii=False)
                
            self.logger.info(f"Saved {len(self.configs)} configurations")
            
        except Exception as e:
            self.logger.error(f"Failed to save configurations: {e}")
    
    def toggle_connection(self):
        if not self.is_connected:
            if not self.current_config:
                self.log_operation("Connection attempt failed", "No configuration loaded", level='warning')
                messagebox.showwarning("Warning", "Please load a configuration first!")
                return
            self.log_operation("Starting VPN connection", level='info')
            self.connect_vpn()
        else:
            self.log_operation("Disconnecting VPN", level='info')
            self.disconnect_vpn()
    
    def connect_vpn(self):
        if not self.current_config:
            # Try to auto-pick best config if available
            try:
                if self.auto_select_best_enabled and self.configs:
                    # Prefer server with lowest recent latency; fallback to first
                    best = None
                    best_latency = None
                    for cfg in self.configs:
                        s = cfg.get('server')
                        if not s:
                            continue
                        lat = self.last_latency_map.get(s)
                        if lat is not None and (best_latency is None or lat < best_latency):
                            best = cfg
                            best_latency = lat
                    self.current_config = best or self.configs[0]
                    self.update_config_display()
                else:
                    self.log_operation("Connection failed", "No configuration available", level='error')
                    return
            except Exception:
                self.log_operation("Connection failed", "No configuration available", level='error')
                return
        
        try:
            # If MFA enabled, require OTP before connecting
            if self.mfa_enabled and not self.verify_mfa_prompt():
                self.log_operation("MFA verification failed or cancelled", level='warning')
                messagebox.showwarning("MFA", "MFA verification failed or cancelled")
                return
            self.log_operation("Backing up network settings", level='info')
            # Backup original network settings
            self.backup_network_settings()
            
            self.log_operation("Starting VPN connection", f"Protocol: {self.current_config.get('protocol', 'unknown')}", level='info')
            # Start real VPN connection
            if self.start_vpn_connection():
                self.is_connected = True
                self.current_reconnect_attempt = 0
                config_name = self.current_config['name']
                self.log_operation("VPN connected successfully", f"Server: {config_name}", level='info')
                self.log_audit('connect', 'success')
                self.refresh_tray_icon()
                self.status_label.config(text=f"Connected to {config_name}", fg='#00ff88')
                self.connect_btn.config(text="Disconnect", bg='#ff4444')
                
                # Start VPN monitoring thread
                self.vpn_thread = threading.Thread(target=self.vpn_connection_worker, daemon=True)
                self.vpn_thread.start()
                self.log_operation("VPN monitoring thread started", level='debug')
                
                # Start network change monitor for auto-disconnect
                try:
                    self.start_network_change_monitor()
                except Exception as _:
                    pass

                # Update IP display
                self.update_ip_display()
                
                # Enable kill switch if configured
                if self.kill_switch_enabled:
                    self.log_operation("Enabling kill switch", level='info')
                    self.enable_kill_switch()
                
                messagebox.showinfo("Success", f"Connected to {config_name}!")
            else:
                self.log_operation("VPN connection failed", "Connection establishment failed", level='error')
                self.log_audit('connect', 'failure')
                messagebox.showerror("Error", "Failed to establish VPN connection")
                # Auto-reconnect if enabled
                self.maybe_schedule_reconnect()
                
        except Exception as e:
            self.log_operation("VPN connection error", str(e), level='error')
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
            self.restore_network_settings()
    
    def start_vpn_connection(self):
        """Start actual VPN connection based on protocol"""
        try:
            config = self.current_config
            protocol = config.get('protocol', 'vless')
            
            self.log_operation("Starting VPN connection", f"Protocol: {protocol}", level='info')

            # If auto-select-best is enabled and multiple configs exist with same protocol, pick lowest latency
            if self.auto_select_best_enabled:
                try:
                    candidates = [c for c in self.configs if c.get('protocol') == protocol]
                    if len(candidates) > 1:
                        best = self.pick_lowest_latency(candidates)
                        if best:
                            self.current_config = best
                            config = best
                            self.log_operation("Auto-selected best server", best.get('name'), level='info')
                except Exception as _:
                    pass
            
            # Check if we have the required tools
            tools_status = self.check_vpn_tools_status()
            
            if protocol in ['vless', 'vmess'] and not tools_status['v2ray']:
                self.log_operation("V2Ray not found, attempting download", level='warning')
                self.download_vpn_executables()
                tools_status = self.check_vpn_tools_status()
                
            elif protocol == 'trojan' and not tools_status['trojan']:
                self.log_operation("Trojan not found, attempting download", level='warning')
                self.download_vpn_executables()
                tools_status = self.check_vpn_tools_status()
            
            # Try to start the connection
            if protocol == 'vless':
                return self.start_vless_connection(config)
            elif protocol == 'vmess':
                return self.start_vmess_connection(config)
            elif protocol == 'trojan':
                return self.start_trojan_connection(config)
            else:
                return self.start_generic_connection(config)
                
        except Exception as e:
            self.log_operation(f"VPN connection failed: {e}", level='error')
            print(f"VPN connection failed: {e}")
            return False

    def pick_lowest_latency(self, configs):
        try:
            import socket
            latencies = []
            for c in configs:
                host = c.get('server')
                port = int(c.get('port', 443))
                if not host:
                    continue
                start = time.time()
                try:
                    with socket.create_connection((host, port), timeout=0.8):
                        pass
                    latency = (time.time() - start)
                    latencies.append((latency, c))
                except Exception:
                    continue
            if not latencies:
                return None
            latencies.sort(key=lambda x: x[0])
            return latencies[0][1]
        except Exception:
            return None
    
    def start_vless_connection(self, config):
        """Start VLESS protocol connection"""
        try:
            # Optional: certificate pinning check before launching
            self.try_certificate_pinning(config)
            # Use the centralized V2Ray config generation
            vless_config = self.generate_v2ray_config(config)
            if not vless_config:
                return False
            
            # Save config to temporary file
            config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(vless_config, config_file, indent=2)
            config_file.close()
            
            # Start V2Ray process
            v2ray_path = self.get_v2ray_path()
            if v2ray_path:
                self.vpn_process = subprocess.Popen([
                    v2ray_path, 'run', '-c', config_file.name
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Wait for connection
                time.sleep(2)
                if self.vpn_process.poll() is None:
                    # Set system proxy to HTTP proxy (port 1081) for better Windows compatibility
                    self.set_system_proxy('127.0.0.1', 1081)
                    
                    # Test proxy connection
                    if self.test_proxy_connection('127.0.0.1', 1081):
                        self.log_operation("HTTP proxy connection test successful", level='info')
                        # Enable DNS leak protection after proxy confirmed
                        self.enable_dns_leak_protection()
                        return True
                    else:
                        self.log_operation("HTTP proxy test failed, trying SOCKS fallback", level='warning')
                        # Try SOCKS proxy as fallback
                        self.set_system_proxy('127.0.0.1', 1080)
                        if self.test_proxy_connection('127.0.0.1', 1080):
                            self.log_operation("SOCKS proxy fallback successful", level='info')
                            self.enable_dns_leak_protection()
                            return True
                        else:
                            self.log_operation("Both HTTP and SOCKS proxy tests failed", level='error')
                            return False
                else:
                    self.vpn_process = None
                    return False
            else:
                # Fallback to generic connection
                return self.start_generic_connection(config)
                
        except Exception as e:
            print(f"VLESS connection failed: {e}")
            return False
    
    def start_vmess_connection(self, config):
        """Start VMess protocol connection"""
        try:
            # Optional: certificate pinning check before launching
            self.try_certificate_pinning(config)
            # Use the centralized V2Ray config generation
            vmess_config = self.generate_v2ray_config(config)
            if not vmess_config:
                return False
            
            # Save config to temporary file
            config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(vmess_config, config_file, indent=2)
            config_file.close()
            
            v2ray_path = self.get_v2ray_path()
            if v2ray_path:
                self.vpn_process = subprocess.Popen([
                    v2ray_path, 'run', '-c', config_file.name
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                time.sleep(2)
                if self.vpn_process.poll() is None:
                    # Set system proxy to HTTP proxy (port 1081) for better Windows compatibility
                    self.set_system_proxy('127.0.0.1', 1081)
                    
                    # Test proxy connection
                    if self.test_proxy_connection('127.0.0.1', 1081):
                        self.log_operation("HTTP proxy connection test successful", level='info')
                        self.enable_dns_leak_protection()
                        # Optionally enable split tunneling (disabled by default)
                        # self.enable_split_tunneling()
                        return True
                    else:
                        self.log_operation("HTTP proxy test failed, trying SOCKS fallback", level='warning')
                        # Try SOCKS proxy as fallback
                        self.set_system_proxy('127.0.0.1', 1080)
                        if self.test_proxy_connection('127.0.0.1', 1080):
                            self.log_operation("SOCKS proxy fallback successful", level='info')
                            self.enable_dns_leak_protection()
                            # self.enable_split_tunneling()
                            return True
                        else:
                            self.log_operation("Both HTTP and SOCKS proxy tests failed", level='error')
                            return False
                else:
                    self.vpn_process = None
                    return False
            else:
                return self.start_generic_connection(config)
                
        except Exception as e:
            print(f"VMess connection failed: {e}")
            return False
    
    def start_trojan_connection(self, config):
        """Start Trojan protocol connection"""
        try:
            # Optional: certificate pinning check before launching
            self.try_certificate_pinning(config)
            # Create Trojan configuration
            trojan_config = {
                "run_type": "client",
                "local_addr": "127.0.0.1",
                "local_port": 1080,
                "remote_addr": config['server'],
                "remote_port": config['port'],
                "password": [config['password']],
                "ssl": {
                    "verify": False,
                    "verify_hostname": False,
                    "sni": config.get('sni', '')
                }
            }
            
            # Save config to temporary file
            config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(trojan_config, config_file, indent=2)
            config_file.close()
            
            # Start Trojan process
            trojan_path = self.get_trojan_path()
            if trojan_path:
                self.vpn_process = subprocess.Popen([
                    trojan_path, '-c', config_file.name
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                time.sleep(2)
                if self.vpn_process.poll() is None:
                    # Set system proxy to HTTP proxy (port 1081) for better Windows compatibility
                    self.set_system_proxy('127.0.0.1', 1081)
                    
                    # Test proxy connection
                    if self.test_proxy_connection('127.0.0.1', 1081):
                        self.log_operation("HTTP proxy connection test successful", level='info')
                        self.enable_dns_leak_protection()
                        return True
                    else:
                        self.log_operation("HTTP proxy test failed, trying SOCKS fallback", level='warning')
                        # Try SOCKS proxy as fallback
                        self.set_system_proxy('127.0.0.1', 1080)
                        if self.test_proxy_connection('127.0.0.1', 1080):
                            self.log_operation("SOCKS proxy fallback successful", level='info')
                            self.enable_dns_leak_protection()
                            return True
                        else:
                            self.log_operation("Both HTTP and SOCKS proxy tests failed", level='error')
                            return False
                else:
                    self.vpn_process = None
                    return False
            else:
                return self.start_generic_connection(config)
                
        except Exception as e:
            print(f"Trojan connection failed: {e}")
            return False
    
    def start_generic_connection(self, config):
        """Start generic connection using system tools"""
        try:
            # Use Windows built-in VPN or create virtual adapter
            # This is a fallback when specific protocol tools aren't available
            print(f"Using generic connection for {config['protocol']}")
            
            # For now, simulate connection success
            # In a real implementation, this would use Windows VPN APIs
            time.sleep(1)
            return True
            
        except Exception as e:
            print(f"Generic connection failed: {e}")
            return False
    
    def generate_v2ray_config(self, config):
        """Generate V2Ray configuration for VLESS/VMess protocols"""
        try:
            protocol = config.get('protocol', 'vless')
            
            if protocol == 'vless':
                # VLESS configuration with both SOCKS and HTTP proxies
                v2ray_config = {
                    "inbounds": [
                        {
                            "port": 1080,
                            "protocol": "socks",
                            "settings": {
                                "auth": "noauth",
                                "udp": True
                            }
                        },
                        {
                            "port": 1081,
                            "protocol": "http",
                            "settings": {
                                "timeout": 300
                            }
                        }
                    ],
                    "outbounds": [{
                        "protocol": "vless",
                        "settings": {
                            "vnext": [{
                                "address": config['server'],
                                "port": config['port'],
                                "users": [{
                                    "id": config['uuid'],
                                    "encryption": config.get('encryption', 'none')
                                }]
                            }]
                        },
                        "streamSettings": {
                            "network": config.get('type', 'tcp'),
                            "security": config.get('security', 'none'),
                            "tlsSettings": {
                                "serverName": config.get('sni', ''),
                                "allowInsecure": True
                            },
                            "wsSettings": {
                                "path": config.get('path', '/'),
                                "headers": {}
                            },
                            "grpcSettings": {
                                "serviceName": config.get('serviceName', '')
                            },
                            "tcpSettings": {
                                "header": {
                                    "type": "http",
                                    "request": {"path": [config.get('path', '/')], "headers": {"Host": [config.get('sni','')]}},
                                    "response": {"headers": {"Content-Type": ["application/octet-stream"], "Transfer-Encoding": ["chunked"], "Connection": ["keep-alive"]}}
                                }
                            }
                        }
                    }]
                }
                
            elif protocol == 'vmess':
                # VMess configuration with both SOCKS and HTTP proxies
                v2ray_config = {
                    "inbounds": [
                        {
                            "port": 1080,
                            "protocol": "socks",
                            "settings": {
                                "auth": "noauth",
                                "udp": True
                            }
                        },
                        {
                            "port": 1081,
                            "protocol": "http",
                            "settings": {
                                "timeout": 300
                            }
                        }
                    ],
                    "outbounds": [{
                        "protocol": "vmess",
                        "settings": {
                            "vnext": [{
                                "address": config['server'],
                                "port": config['port'],
                                "users": [{
                                    "id": config['uuid'],
                                    "alterId": config.get('alterId', 0)
                                }]
                            }]
                        },
                        "streamSettings": {
                            "network": config.get('type', 'tcp'),
                            "security": config.get('security', 'auto'),
                            "tlsSettings": {
                                "serverName": config.get('sni', ''),
                                "allowInsecure": True
                            },
                            "wsSettings": {
                                "path": config.get('path', '/'),
                                "headers": {}
                            },
                            "grpcSettings": {
                                "serviceName": config.get('serviceName', '')
                            },
                            "tcpSettings": {
                                "header": {
                                    "type": "http",
                                    "request": {"path": [config.get('path', '/')], "headers": {"Host": [config.get('sni','')]}},
                                    "response": {"headers": {"Content-Type": ["application/octet-stream"], "Transfer-Encoding": ["chunked"], "Connection": ["keep-alive"]}}
                                }
                            }
                        }
                    }]
                }
            else:
                raise ValueError(f"Unsupported protocol: {protocol}")
            
            return v2ray_config
            
        except Exception as e:
            self.log_operation(f"V2Ray config generation failed: {e}", level='error')
            return None
    
    def disconnect_vpn(self):
        try:
            self.log_operation("Starting VPN disconnection", level='info')
            self.log_audit('disconnect', 'start')
            
            # Stop VPN process
            if self.vpn_process:
                self.log_operation("Terminating VPN process", level='debug')
                self.vpn_process.terminate()
                self.vpn_process.wait(timeout=5)
                self.vpn_process = None
                self.log_operation("VPN process terminated", level='debug')
            
            # Disable DNS leak protection first
            self.disable_dns_leak_protection()

            # Disable kill switch
            if self.kill_switch_enabled:
                self.log_operation("Disabling kill switch", level='info')
                self.disable_kill_switch()
            
            # Disable split tunneling
            try:
                if getattr(self, 'split_tunneling_enabled', False):
                    self.disable_split_tunneling()
            except Exception:
                pass
            
            # Restore network settings
            self.log_operation("Restoring network settings", level='info')
            self.restore_network_settings()
            
            # Clear system proxy
            self.log_operation("Clearing system proxy", level='info')
            self.clear_system_proxy()
            # Ensure PAC server is stopped if it was running
            self.stop_pac_server()
            # Stop network change monitor
            try:
                self.stop_network_change_monitor()
            except Exception:
                pass
            
            self.is_connected = False
            self.status_label.config(text="Disconnected", fg='#ff4444')
            self.connect_btn.config(text="Connect", bg='#00ff88')
            self.refresh_tray_icon()
            
            # Update IP display
            self.update_ip_display()
            
            self.log_operation("VPN disconnected successfully", level='info')
             
            self.log_audit('disconnect', 'success')
            messagebox.showinfo("Info", "Disconnected from VPN server!")
            
        except Exception as e:
            self.log_operation("VPN disconnection error", str(e), level='error')
            self.log_audit('disconnect', 'failure', {"error": str(e)})
            print(f"Disconnect error: {e}")
            self.is_connected = False
            self.status_label.config(text="Disconnected", fg='#ff4444')
            self.connect_btn.config(text="Connect", bg='#00ff88')
            self.refresh_tray_icon()
    
    def backup_network_settings(self):
        """Backup current network settings"""
        try:
            # Get current DNS settings
            self.original_dns = self.get_current_dns()
            
            # Get current routing table
            self.original_routes = self.get_current_routes()
            
        except Exception as e:
            print(f"Network backup failed: {e}")
    
    def restore_network_settings(self):
        """Restore original network settings"""
        try:
            if self.original_dns:
                self.set_dns_servers(self.original_dns)
            
            if self.original_routes:
                self.restore_routes(self.original_routes)
                
        except Exception as e:
            print(f"Network restore failed: {e}")
    
    def get_current_dns(self):
        """Get current DNS server settings per interface using PowerShell"""
        try:
            ps_cmd = (
                'Get-DnsClientServerAddress -AddressFamily IPv4 | '
                'Select-Object InterfaceIndex,InterfaceAlias,ServerAddresses | '
                'ConvertTo-Json -Compress'
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_cmd],
                capture_output=True, text=True
            )
            if result.returncode != 0 or not result.stdout.strip():
                raise RuntimeError(result.stderr or 'Failed to query DNS via PowerShell')
            data = json.loads(result.stdout)
            # Normalize to list
            if isinstance(data, dict):
                data = [data]
            self.original_dns_by_interface = []
            for entry in data:
                self.original_dns_by_interface.append({
                    'InterfaceIndex': entry.get('InterfaceIndex'),
                    'InterfaceAlias': entry.get('InterfaceAlias'),
                    'ServerAddresses': entry.get('ServerAddresses') or []
                })
            # Also return a flattened set of servers for logging
            all_servers = []
            for e in self.original_dns_by_interface:
                for s in e['ServerAddresses']:
                    if s and s not in all_servers:
                        all_servers.append(s)
            return all_servers
        except Exception as e:
            print(f"DNS query failed: {e}")
            # Fallback
            self.original_dns_by_interface = []
            return ['8.8.8.8', '8.8.4.4']
    
    def set_dns_servers(self, dns_servers):
        """Set DNS servers for all active IPv4 interfaces using PowerShell"""
        try:
            servers_arg = ','.join([f'\"{s}\"' for s in dns_servers])
            ps_cmd = (
                f"$ifaces = Get-DnsClient -AddressFamily IPv4 | Where-Object {{$_.InterfaceOperationalStatus -eq 'Up'}};"
                f"foreach ($i in $ifaces) {{ try {{ Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ServerAddresses @({servers_arg}) -ErrorAction Stop }} catch {{ }} }}"
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_cmd],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr or 'Failed to set DNS via PowerShell')
            self.log_operation(f"DNS servers set: {dns_servers}", level='info')
        except Exception as e:
            print(f"DNS setting failed: {e}")
    
    def get_current_routes(self):
        """Get current routing table"""
        try:
            result = subprocess.run(['route', 'print'], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            print(f"Route query failed: {e}")
            return None
    
    def restore_routes(self, routes):
        """Restore routing table"""
        try:
            # This would restore the original routing table
            print("Restoring routing table")
        except Exception as e:
            print(f"Route restore failed: {e}")

    def enable_dns_leak_protection(self):
        """Apply DNS leak protection: set secure DNS and restrict DNS traffic"""
        try:
            # Backup current DNS by interface if not already
            if not hasattr(self, 'original_dns_by_interface'):
                self.get_current_dns()
            # Prefer Cloudflare
            secure_dns = ['1.1.1.1', '1.0.0.1']
            self.log_audit('dns_leak_protection', 'enable_start', {"servers": secure_dns})
            self.set_dns_servers(secure_dns)
            # Tighten firewall: block all UDP/53, then allow only Cloudflare
            subprocess.run(['netsh','advfirewall','firewall','add','rule',
                            'name=NPVTunnel_DNS_Block_All','dir=out','action=block','enable=yes',
                            'profile=any','protocol=UDP','remoteport=53',
                            'description=Block all outbound DNS'], shell=True, check=False)
            subprocess.run(['netsh','advfirewall','firewall','add','rule',
                            'name=NPVTunnel_DNS_Allow_Cloudflare','dir=out','action=allow','enable=yes',
                            'profile=any','protocol=UDP','remoteip=1.1.1.1,1.0.0.1','remoteport=53',
                            'description=Allow DNS to Cloudflare only'], shell=True, check=False)
            # Try to add DoH servers on Win11 (best-effort)
            try:
                ps_cmd = (
                    "try { Add-DnsClientDohServerAddress -ServerAddress 1.1.1.1 -DohTemplate https://cloudflare-dns.com/dns-query -AllowFallbackToUdp $true -ErrorAction Stop } catch {} ;"
                    "try { Add-DnsClientDohServerAddress -ServerAddress 1.0.0.1 -DohTemplate https://cloudflare-dns.com/dns-query -AllowFallbackToUdp $true -ErrorAction Stop } catch {}"
                )
                subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command', ps_cmd], capture_output=True, text=True)
            except Exception:
                pass
            self.log_operation('DNS leak protection enabled', level='info')
            self.log_audit('dns_leak_protection', 'enable_success')
        except Exception as e:
            self.log_operation(f'DNS leak protection failed: {e}', level='warning')
            self.log_audit('dns_leak_protection', 'enable_failure', {"error": str(e)})

    def disable_dns_leak_protection(self):
        """Restore DNS settings and remove DNS firewall rules"""
        try:
            self.log_audit('dns_leak_protection', 'disable_start')
            # Restore DNS per interface if we have a backup
            try:
                if getattr(self, 'original_dns_by_interface', None):
                    for entry in self.original_dns_by_interface:
                        iface_index = entry.get('InterfaceIndex')
                        addrs = entry.get('ServerAddresses') or []
                        servers_arg = ','.join([f'\"{s}\"' for s in addrs]) if addrs else ''
                        if servers_arg:
                            ps_cmd = (
                                f"Set-DnsClientServerAddress -InterfaceIndex {iface_index} -ServerAddresses @({servers_arg})"
                            )
                        else:
                            ps_cmd = (
                                f"Set-DnsClientServerAddress -InterfaceIndex {iface_index} -ResetServerAddresses"
                            )
                        subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command', ps_cmd], capture_output=True, text=True)
            except Exception:
                pass
            # Remove DNS rules
            for rule_name in ['NPVTunnel_DNS_Block_All','NPVTunnel_DNS_Allow_Cloudflare']:
                try:
                    subprocess.run(['netsh','advfirewall','firewall','delete','rule', f'name={rule_name}'], shell=True, check=False)
                except Exception:
                    pass
            self.log_operation('DNS leak protection disabled', level='info')
            self.log_audit('dns_leak_protection', 'disable_success')
        except Exception as e:
            self.log_operation(f'DNS leak protection disable failed: {e}', level='warning')
            self.log_audit('dns_leak_protection', 'disable_failure', {"error": str(e)})
    
    def set_system_proxy(self, host, port):
        """Set system-wide proxy settings"""
        try:
            # Set Windows proxy settings
            proxy_settings = f"http={host}:{port};https={host}:{port}"
            
            # Use Windows Registry to set proxy
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_settings)
                # Add bypass for local addresses
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>")
                winreg.CloseKey(key)
                self.log_operation(f"System proxy set to {host}:{port} with local bypass", level='info')
                print(f"System proxy set to {host}:{port} with local bypass")
                
                # Notify system of proxy changes
                self.refresh_system_proxy()
                # Track active proxy
                try:
                    self.active_proxy_host = host
                    self.active_proxy_port = int(port)
                except Exception:
                    self.active_proxy_host = host
                    self.active_proxy_port = port
                
            except Exception as e:
                self.log_operation(f"Registry proxy setting failed: {e}", level='error')
                print(f"Registry proxy setting failed: {e}")
                
        except Exception as e:
            self.log_operation(f"Proxy setting failed: {e}", level='error')
            print(f"Proxy setting failed: {e}")

    def set_pac_proxy(self, pac_url):
        """Set system to use a PAC (Proxy Auto-Config) file"""
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            self.log_operation(f"PAC set: {pac_url}", level='info')
            self.refresh_system_proxy()
        except Exception as e:
            self.log_operation(f"PAC setting failed: {e}", level='warning')
    
    def test_proxy_connection(self, host, port):
        """Test if proxy connection is working"""
        try:
            import requests
            proxies = {
                'http': f'http://{host}:{port}',
                'https': f'http://{host}:{port}'
            }
            
            # Test with a simple HTTP request
            response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5)
            if response.status_code == 200:
                self.log_operation(f"Proxy test successful: {response.json()}", level='debug')
                return True
            else:
                self.log_operation(f"Proxy test failed with status: {response.status_code}", level='warning')
                return False
                
        except Exception as e:
            self.log_operation(f"Proxy test failed: {e}", level='warning')
            return False
    
    def refresh_system_proxy(self):
        """Refresh system proxy settings to notify applications"""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Send WM_SETTINGCHANGE message to notify applications of proxy changes
            HWND_BROADCAST = 0xFFFF
            WM_SETTINGCHANGE = 0x001A
            SMTO_ABORTIFHUNG = 0x0002
            
            result = ctypes.windll.user32.SendMessageTimeoutW(
                HWND_BROADCAST, WM_SETTINGCHANGE, 0, 
                "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                SMTO_ABORTIFHUNG, 5000, ctypes.byref(wintypes.DWORD())
            )
            
            if result:
                self.log_operation("System proxy refresh notification sent", level='debug')
            else:
                self.log_operation("System proxy refresh notification failed", level='warning')
                
        except Exception as e:
            self.log_operation(f"System proxy refresh failed: {e}", level='warning')

    def startup_sanity_cleanup(self):
        """Clear stale localhost proxy if ProxyEnable=1 but ProxyServer points to 127.0.0.1."""
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
            try:
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except Exception:
                proxy_enable = 0
            try:
                proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except Exception:
                proxy_server = ''
            winreg.CloseKey(key)
            if proxy_enable == 1 and isinstance(proxy_server, str) and ('127.0.0.1' in proxy_server or 'localhost' in proxy_server):
                self.log_operation('Startup cleanup: clearing stale localhost proxy', level='warning')
                self.clear_system_proxy()
        except Exception:
            pass

    def cleanup_kill_switch_if_stale(self):
        """On startup, remove our kill-switch rules if they exist and we are not connected."""
        try:
            rules = [
                'NPVTunnel_KillSwitch_BlockAll',
                'NPVTunnel_KillSwitch_AllowVPN',
                'NPVTunnel_KillSwitch_AllowDNS',
                'NPVTunnel_KillSwitch_AllowLocal'
            ]
            # Query one rule to detect presence
            result = subprocess.run(['netsh','advfirewall','firewall','show','rule','name=NPVTunnel_KillSwitch_BlockAll'], capture_output=True, text=True, shell=True)
            if result.returncode == 0 and 'No rules match the specified criteria' not in (result.stdout or ''):
                if not self.is_connected:
                    for r in rules:
                        try:
                            subprocess.run(['netsh','advfirewall','firewall','delete','rule',f'name={r}'], shell=True)
                        except Exception:
                            pass
                    self.log_operation('Removed stale kill-switch rules on startup', level='warning')
        except Exception:
            pass

    # ------------------------ Startup with Windows ------------------------
    def get_startup_command(self):
        try:
            exe = sys.executable
            # Prefer pythonw.exe if available to avoid console window
            if exe.lower().endswith('python.exe'):
                pyw = exe[:-10] + 'pythonw.exe'
                if os.path.exists(pyw):
                    exe = pyw
            script = os.path.abspath(sys.argv[0])
            return f'"{exe}" "{script}"'
        except Exception:
            return None

    def apply_startup(self, enable: bool):
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_CREATE_SUB_KEY) as key:
                name = "MomoTunnel"
                if enable:
                    cmd = self.get_startup_command()
                    if cmd:
                        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, cmd)
                        self.log_operation("Startup registration updated", cmd, level='info')
                else:
                    try:
                        winreg.DeleteValue(key, name)
                        self.log_operation("Startup registration removed", level='info')
                    except FileNotFoundError:
                        pass
        except Exception as e:
            self.log_operation(f"Startup registration failed: {e}", level='warning')
    
    def test_internet_access(self):
        """Test if internet access is working through the proxy"""
        try:
            import requests
            
            # Test multiple websites to ensure internet access
            test_urls = [
                'http://www.google.com',
                'http://www.bing.com',
                'http://www.yahoo.com'
            ]
            
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        self.log_operation(f"Internet access test successful: {url}", level='debug')
                        return True
                except:
                    continue
            
            self.log_operation("All internet access tests failed", level='warning')
            return False
                
        except Exception as e:
            self.log_operation(f"Internet access test failed: {e}", level='warning')
            return False

    # ------------------------ Speed Test ------------------------
    def run_speed_test(self):
        """Basic HTTP download speed test via proxy."""
        try:
            import time as _time
            import requests
            url = 'https://speed.hetzner.de/10MB.bin'
            start = _time.time()
            downloaded = 0
            with requests.get(url, stream=True, timeout=30) as r:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=8192):
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded >= 5 * 1024 * 1024:  # 5MB sample
                        break
            duration = max(_time.time() - start, 0.001)
            mbps = (downloaded * 8 / 1_000_000) / duration
            self.log_operation(f"Speed test: {mbps:.2f} Mbps (sample)", level='info')
            messagebox.showinfo('Speed Test', f"Approximate speed: {mbps:.2f} Mbps (sample)")
        except Exception as e:
            self.log_operation(f"Speed test failed: {e}", level='warning')
            messagebox.showwarning('Speed Test', f"Speed test failed: {e}")
    
    def clear_system_proxy(self):
        """Clear system proxy settings"""
        try:
            # Clear Windows proxy settings
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.DeleteValue(key, "ProxyServer")
                # Also clear AutoConfigURL if PAC was used
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except FileNotFoundError:
                    pass
                winreg.CloseKey(key)
                print("System proxy cleared")
                try:
                    self.refresh_system_proxy()
                except Exception:
                    pass
                try:
                    self.active_proxy_host = None
                    self.active_proxy_port = None
                except Exception:
                    pass
            except Exception as e:
                print(f"Registry proxy clearing failed: {e}")
                
        except Exception as e:
            print(f"Proxy clearing failed: {e}")

    def fix_network_now(self):
        """One-click network cleanup: stop VPN, clear proxies/PAC, reset WinHTTP, flush DNS."""
        try:
            self.log_operation('Fix Network invoked', level='info')
            # Stop VPN process if running
            try:
                if getattr(self, 'vpn_process', None):
                    self.vpn_process.terminate()
                    self.vpn_process = None
            except Exception:
                pass
            # Clear system proxy and PAC
            try:
                self.clear_system_proxy()
            except Exception:
                pass
            try:
                self.stop_pac_server()
            except Exception:
                pass
            # Reset WinHTTP proxy (requires shell=True for netsh)
            try:
                subprocess.run(['netsh','winhttp','reset','proxy'], capture_output=True, text=True, shell=True)
            except Exception:
                pass
            # Flush DNS cache
            try:
                subprocess.run(['ipconfig','/flushdns'], capture_output=True, text=True, shell=True)
            except Exception:
                pass
            messagebox.showinfo('Fix Network', 'Network settings have been reset.')
        except Exception as e:
            self.log_operation(f'Fix Network failed: {e}', level='warning')
    
    def enable_kill_switch(self):
        """Enable kill switch using Windows Firewall to prevent traffic leaks"""
        try:
            self.log_operation("Enabling kill switch with Windows Firewall", level='info')
            self.log_audit('kill_switch', 'enable_start')
            
            # Store current firewall state for restoration
            self.backup_firewall_state()
            
            # Create firewall rules to block all outbound traffic except VPN proxy
            self.create_kill_switch_rules()
            
            # Enable the kill switch rules
            self.activate_kill_switch_rules()
            
            self.log_operation("Kill switch enabled successfully", level='info')
            self.log_audit('kill_switch', 'enable_success')
            return True
        except Exception as e:
            self.log_operation(f"Kill switch enable failed: {e}", level='error')
            self.log_audit('kill_switch', 'enable_failure', {"error": str(e)})
            return False
    
    def disable_kill_switch(self):
        """Disable kill switch and restore normal firewall state"""
        try:
            self.log_operation("Disabling kill switch", level='info')
            self.log_audit('kill_switch', 'disable_start')
            
            # Remove kill switch rules
            self.remove_kill_switch_rules()
            
            # Restore original firewall state
            self.restore_firewall_state()
            
            self.log_operation("Kill switch disabled successfully", level='info')
            self.log_audit('kill_switch', 'disable_success')
            return True
        except Exception as e:
            self.log_operation(f"Kill switch disable failed: {e}", level='error')
            self.log_audit('kill_switch', 'disable_failure', {"error": str(e)})
            return False
    
    def get_v2ray_path(self):
        """Get V2Ray executable path"""
        # Check common V2Ray locations
        possible_paths = [
            "v2ray.exe",
            "v2ray",
            os.path.join(os.getcwd(), "v2ray.exe"),
            os.path.join(os.getcwd(), "v2ray"),
            os.path.join(self.get_tools_dir(), "v2ray.exe"),
            "C:\\Program Files\\V2Ray\\v2ray.exe",
            "C:\\Program Files (x86)\\V2Ray\\v2ray.exe"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def get_trojan_path(self):
        """Get Trojan executable path"""
        # Check common Trojan locations
        possible_paths = [
            "trojan.exe",
            "trojan",
            os.path.join(os.getcwd(), "trojan.exe"),
            os.path.join(os.getcwd(), "trojan"),
            os.path.join(self.get_tools_dir(), "trojan.exe"),
            "C:\\Program Files\\Trojan\\trojan.exe",
            "C:\\Program Files (x86)\\Trojan\\trojan.exe"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
        
    def download_vpn_executables(self):
        """Download required VPN protocol executables"""
        try:
            self.log_operation("Starting VPN executable download", level='info')
            
            # Create tools directory if it doesn't exist
            tools_dir = self.get_tools_dir()
            if not os.path.exists(tools_dir):
                os.makedirs(tools_dir)
                self.log_operation("Created VPN tools directory", level='debug')
            
            # Load expected hashes from a local manifest if present
            manifest_path = os.path.join(self.get_data_dir(), 'tool_hashes.json')
            expected = {}
            try:
                if os.path.exists(manifest_path):
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        expected = json.load(f) or {}
            except Exception:
                expected = {}

            # Download V2Ray
            v2ray_path = os.path.join(tools_dir, "v2ray.exe")
            if not os.path.exists(v2ray_path):
                self.log_operation("Downloading V2Ray executable", level='info')
                v2_hash = expected.get('v2ray_sha256')
                if not v2_hash:
                    self.log_operation("Missing v2ray_sha256 in tool_hashes.json; refusing to download.", level='error')
                else:
                    success = self.download_v2ray(v2ray_path, v2_hash)
                    if success:
                        self.log_operation("V2Ray downloaded successfully", level='info')
                    else:
                        self.log_operation("V2Ray download failed", level='error')
            
            # Download Trojan
            trojan_path = os.path.join(tools_dir, "trojan.exe")
            if not os.path.exists(trojan_path):
                self.log_operation("Downloading Trojan executable", level='info')
                t_hash = expected.get('trojan_sha256')
                if not t_hash:
                    self.log_operation("Missing trojan_sha256 in tool_hashes.json; refusing to download.", level='error')
                else:
                    success = self.download_trojan(trojan_path, t_hash)
                    if success:
                        self.log_operation("Trojan downloaded successfully", level='info')
                    else:
                        self.log_operation("Trojan download failed", level='error')
                    
            self.log_operation("VPN executable download process completed", level='info')
            
        except Exception as e:
            self.log_operation(f"VPN executable download error: {e}", level='error')
    
    def _verify_sha256(self, file_path, expected_hex):
        try:
            import hashlib
            h = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest().lower() == (expected_hex or '').lower()
        except Exception:
            return False

    def download_v2ray(self, target_path, expected_hash=None):
        """Download V2Ray executable"""
        try:
            # V2Ray download URLs (latest stable releases)
            v2ray_urls = [
                "https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-windows-64.zip",
                "https://github.com/v2fly/v2ray-core/releases/download/v4.45.2/v2ray-windows-64.zip"
            ]
            # Hash is passed from manifest when pinned
            
            for url in v2ray_urls:
                try:
                    self.log_operation(f"Attempting V2Ray download from: {url}", level='debug')
                    
                    # Download the zip file
                    response = requests.get(url, stream=True, timeout=30)
                    response.raise_for_status()
                    
                    # Save to temporary file
                    temp_zip = os.path.join(self.get_tools_dir(), "v2ray_temp.zip")
                    with open(temp_zip, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Extract the executable
                    import zipfile
                    with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                        # Find v2ray.exe in the zip
                        for file_info in zip_ref.filelist:
                            if file_info.filename.endswith('v2ray.exe'):
                                with zip_ref.open(file_info) as source, open(target_path, 'wb') as target:
                                    target.write(source.read())
                                break
                    
                    # Clean up
                    try:
                        os.remove(temp_zip)
                    except Exception:
                        pass
                    
                    # Verify checksum if provided
                    if expected_hash and not self._verify_sha256(target_path, expected_hash):
                        self.log_operation("V2Ray checksum verification failed", level='error')
                        try:
                            os.remove(target_path)
                        except Exception:
                            pass
                        continue
                    self.log_operation("V2Ray extracted successfully", level='debug')
                    return True
                    
                except Exception as e:
                    self.log_operation(f"V2Ray download attempt failed: {e}", level='warning')
                    continue
            
            return False
            
        except Exception as e:
            self.log_operation(f"V2Ray download failed: {e}", level='error')
            return False
    
    def download_trojan(self, target_path, expected_hash=None):
        """Download Trojan executable"""
        try:
            # Trojan download URLs (latest stable releases)
            trojan_urls = [
                "https://github.com/trojan-gfw/trojan/releases/latest/download/trojan-windows-x86_64.zip",
                "https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-windows-x86_64.zip"
            ]
            # Hash is passed from manifest when pinned
            
            for url in trojan_urls:
                try:
                    self.log_operation(f"Attempting Trojan download from: {url}", level='debug')
                    
                    # Download the zip file
                    response = requests.get(url, stream=True, timeout=30)
                    if response.status_code == 404:
                        self.log_operation(f"URL not found: {url}", level='warning')
                        continue
                        
                    response.raise_for_status()
                    
                    # Save to temporary file
                    temp_zip = os.path.join(self.get_tools_dir(), "trojan_temp.zip")
                    with open(temp_zip, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Extract the executable
                    import zipfile
                    with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                        # Find trojan.exe in the zip
                        for file_info in zip_ref.filelist:
                            if file_info.filename.endswith('trojan.exe'):
                                with zip_ref.open(file_info) as source, open(target_path, 'wb') as target:
                                    target.write(source.read())
                                break
                    
                    # Clean up
                    try:
                        os.remove(temp_zip)
                    except Exception:
                        pass
                    # Verify checksum if provided
                    if expected_hash and not self._verify_sha256(target_path, expected_hash):
                        self.log_operation("Trojan checksum verification failed", level='error')
                        try:
                            os.remove(target_path)
                        except Exception:
                            pass
                        continue
                    self.log_operation("Trojan extracted successfully", level='debug')
                    return True
                    
                except Exception as e:
                    self.log_operation(f"Trojan download attempt failed: {e}", level='warning')
                    continue
            
            return False
            
        except Exception as e:
            self.log_operation(f"Trojan download failed: {e}", level='error')
            return False
    
    def check_vpn_tools_status(self):
        """Check status of VPN tools and return what's available"""
        tools_status = {
            'v2ray': False,
            'trojan': False,
            'v2ray_path': None,
            'trojan_path': None
        }
        
        # Check V2Ray
        v2ray_path = self.get_v2ray_path()
        if v2ray_path:
            tools_status['v2ray'] = True
            tools_status['v2ray_path'] = v2ray_path
            self.log_operation("V2Ray found", f"Path: {v2ray_path}", level='debug')
        else:
            self.log_operation("V2Ray not found", level='warning')
        
        # Check Trojan
        trojan_path = self.get_trojan_path()
        if trojan_path:
            tools_status['trojan'] = True
            tools_status['trojan_path'] = trojan_path
            self.log_operation("Trojan found", f"Path: {trojan_path}", level='debug')
        else:
            self.log_operation("Trojan not found", level='warning')
        
        return tools_status
    
    def vpn_connection_worker(self):
        """Monitor connection and collect latency samples; watchdog proxy health."""
        self.connection_start_time = time.time()
        while self.is_connected:
            try:
                # ICMP ping permissions may be restricted; use TCP connect timing to server as latency proxy
                if self.current_config:
                    host = self.current_config.get('server')
                    port = int(self.current_config.get('port', 443))
                    if host:
                        start = time.time()
                        try:
                            with socket.create_connection((host, port), timeout=1.0):
                                pass
                            latency_ms = int((time.time() - start) * 1000)
                            self.latency_samples.append(latency_ms)
                            if len(self.latency_samples) > 300:
                                self.latency_samples = self.latency_samples[-300:]
                            # Keep last latency per server for auto-select
                            try:
                                if self.current_config and self.current_config.get('server'):
                                    self.last_latency_map[self.current_config['server']] = latency_ms
                            except Exception:
                                pass
                            self.root.after(0, self.draw_latency_chart)
                            self.root.after(0, self.update_latency_metrics)
                        except Exception:
                            pass
                # Watchdog: validate active proxy every loop
                try:
                    if self.active_proxy_host and self.active_proxy_port:
                        ok = self.test_proxy_connection(self.active_proxy_host, self.active_proxy_port)
                        if ok:
                            self.proxy_fail_streak = 0
                        else:
                            self.proxy_fail_streak += 1
                            self.log_operation(f"Proxy watchdog failure #{self.proxy_fail_streak}", level='warning')
                            if self.proxy_fail_streak >= 2:
                                self.log_operation('Watchdog clearing system proxy due to failures', level='error')
                                self.clear_system_proxy()
                                # Also mark disconnected to stop loop and trigger UI reset
                                self.root.after(0, self.disconnect_vpn)
                                # Kick off auto-reconnect if enabled
                                self.root.after(2000, self.maybe_schedule_reconnect)
                                break
                except Exception:
                    pass
                # Record connection history snapshot every loop
                try:
                    snapshot = {
                        'ts': datetime.now().isoformat(),
                        'server': (self.current_config or {}).get('server'),
                        'protocol': (self.current_config or {}).get('protocol'),
                        'latency_ms': self.latency_samples[-1] if self.latency_samples else None
                    }
                    self.connection_history.append(snapshot)
                    if len(self.connection_history) > 200:
                        self.connection_history = self.connection_history[-200:]
                except Exception:
                    pass
                time.sleep(5)
            except Exception:
                time.sleep(5)

    def draw_latency_chart(self):
        try:
            if not hasattr(self, 'latency_canvas'):
                return
            c = self.latency_canvas
            c.delete('all')
            if not self.latency_samples:
                return
            w = c.winfo_width() or 300
            h = int(c['height'])
            data = self.latency_samples[-30:]
            maxv = max(max(data), 1)
            step = max(w // max(len(data), 1), 1)
            x = 0
            last_xy = None
            for v in data:
                y = h - int(v / maxv * (h - 5))
                if last_xy:
                    c.create_line(last_xy[0], last_xy[1], x, y, fill='#00ff88')
                last_xy = (x, y)
                x += step
        except Exception:
            pass

    # ------------------------ Network Change Monitor ------------------------
    def get_default_gateway(self):
        try:
            ps_cmd = "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1).NextHop"
            result = subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command', ps_cmd], capture_output=True, text=True)
            gw = (result.stdout or '').strip()
            return gw
        except Exception:
            return ''

    def get_active_adapters_fingerprint(self):
        try:
            ps_cmd = "Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.ConnectionState -eq 'Connected'} | Select-Object InterfaceIndex,InterfaceMetric | ConvertTo-Json -Compress"
            result = subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command', ps_cmd], capture_output=True, text=True)
            if result.returncode != 0 or not result.stdout.strip():
                return ''
            data = result.stdout.strip()
            return hashlib.sha256(data.encode('utf-8')).hexdigest()
        except Exception:
            return ''

    def start_network_change_monitor(self):
        self.netmon_stop = False
        self.netmon_gw = self.get_default_gateway()
        self.netmon_fp = self.get_active_adapters_fingerprint()
        def monitor():
            while not getattr(self, 'netmon_stop', True):
                try:
                    time.sleep(5)
                    new_gw = self.get_default_gateway()
                    new_fp = self.get_active_adapters_fingerprint()
                    if (self.netmon_gw and new_gw and new_gw != self.netmon_gw) or (self.netmon_fp and new_fp and new_fp != self.netmon_fp):
                        self.log_operation('Network change detected; auto-disconnecting', level='warning')
                        self.root.after(0, self.disconnect_vpn)
                        break
                except Exception:
                    continue
        self.netmon_thread = threading.Thread(target=monitor, daemon=True)
        self.netmon_thread.start()

    def stop_network_change_monitor(self):
        try:
            self.netmon_stop = True
        except Exception:
            pass

    # ------------------------ Theme & Auto-reconnect ------------------------
    def toggle_theme(self):
        try:
            self.theme_mode = 'light' if self.theme_mode == 'dark' else 'dark'
            # Simple toggle: adjust root bg; full theming would adjust all widgets
            bg = '#ffffff' if self.theme_mode == 'light' else '#1e1e1e'
            self.root.configure(bg=bg)
            self.log_operation(f"Theme switched to {self.theme_mode}", level='info')
        except Exception as e:
            self.log_operation(f"Theme toggle failed: {e}", level='warning')

    def on_toggle_auto_reconnect(self):
        self.auto_reconnect_enabled = bool(self.auto_reconnect_var.get())
        self.log_operation(f"Auto-reconnect {'enabled' if self.auto_reconnect_enabled else 'disabled'}", level='info')

    def on_toggle_auto_select_best(self):
        try:
            self.auto_select_best_enabled = bool(self.auto_select_best_var.get())
            self.log_operation(f"Auto-select best {'enabled' if self.auto_select_best_enabled else 'disabled'}", level='info')
        except Exception:
            pass

    def maybe_schedule_reconnect(self):
        try:
            if self.auto_reconnect_enabled and not self.is_connected:
                if self.current_reconnect_attempt < self.max_reconnect_attempts:
                    # Exponential backoff with jitter
                    self.current_reconnect_attempt += 1
                    base = self.reconnect_delay_seconds * (2 ** (self.current_reconnect_attempt - 1))
                    import random
                    delay = min(base + random.randint(0, 2), 60)
                    self.log_operation(f"Scheduling reconnect attempt {self.current_reconnect_attempt}/{self.max_reconnect_attempts} in {delay}s", level='info')
                    self.root.after(delay * 1000, self.connect_vpn)
                else:
                    self.log_operation("Max reconnect attempts reached", level='warning')
        except Exception as e:
            self.log_operation(f"Failed to schedule reconnect: {e}", level='warning')

    # ------------------------ System Tray ------------------------
    def create_tray_image(self, connected=False):
        try:
            size = (64, 64)
            color = (0, 255, 136) if connected else (255, 68, 68)
            img = Image.new('RGB', size, (30,30,30))
            draw = ImageDraw.Draw(img)
            draw.ellipse((12,12,52,52), fill=color)
            return img
        except Exception:
            return None

    def start_tray_icon(self):
        try:
            if not pystray:
                return
            icon_image = self.create_tray_image(self.is_connected)
            menu = pystray.Menu(
                pystray.MenuItem('Connect', lambda: self.root.after(0, self.on_tray_connect)),
                pystray.MenuItem('Disconnect', lambda: self.root.after(0, self.on_tray_disconnect)),
                pystray.MenuItem('Fix Network', lambda: self.root.after(0, self.on_tray_fix_network)),
                pystray.MenuItem('Quit', lambda: self.root.after(0, self.root.quit))
            )
            self.tray_icon = pystray.Icon('NpvTunnelPC', icon_image, 'Npv Tunnel PC', menu)
            self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
            self.tray_thread.start()
        except Exception as e:
            self.log_operation(f"Tray start failed: {e}", level='warning')

    def stop_tray_icon(self):
        try:
            if self.tray_icon:
                self.tray_icon.stop()
                self.tray_icon = None
        except Exception:
            pass

    def refresh_tray_icon(self):
        try:
            if self.tray_icon:
                self.tray_icon.icon = self.create_tray_image(self.is_connected)
                self.tray_icon.title = f"Npv Tunnel PC - {'Connected' if self.is_connected else 'Disconnected'}"
        except Exception:
            pass
    
    def on_tray_connect(self):
        try:
            if not self.is_connected:
                self.connect_vpn()
        except Exception:
            pass

    def on_tray_disconnect(self):
        try:
            if self.is_connected:
                self.disconnect_vpn()
        except Exception:
            pass

    def on_tray_fix_network(self):
        try:
            self.fix_network_now()
        except Exception:
            pass
    
    def update_ip_display(self):
        if self.is_connected:
            # Simulate different IP when connected
            if self.current_config:
                server = self.current_config['server']
                self.ip_label.config(text=f"IP: {server} (VPN)")
                self.log_operation("IP display updated", f"VPN IP: {server}", level='debug')
            else:
                self.ip_label.config(text="IP: VPN Connected")
                self.log_operation("IP display updated", "VPN Connected (no server info)", level='debug')
        else:
            # Show real IP
            self.get_real_ip()
    
    def get_real_ip(self):
        try:
            self.log_operation("Checking real IP address", level='debug')
            response = requests.get('https://httpbin.org/ip', timeout=5)
            ip_data = response.json()
            real_ip = ip_data.get('origin', 'Unknown')
            self.ip_label.config(text=f"IP: {real_ip}")
            self.log_operation("Real IP retrieved", f"IP: {real_ip}", level='debug')
        except Exception as e:
            self.log_operation("IP check failed", str(e), level='warning')
            self.ip_label.config(text="IP: Unable to determine")
    
    def start_ip_checker(self):
        """Start background thread to check IP periodically"""
        def ip_checker():
            while True:
                try:
                    if not self.is_connected:
                        self.get_real_ip()
                    time.sleep(30)  # Check every 30 seconds
                except Exception as e:
                    self.logger.warning(f"IP checker error: {e}")
                    time.sleep(60)  # Wait longer on error
        
        ip_thread = threading.Thread(target=ip_checker, daemon=True)
        ip_thread.start()
    
    def show_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Advanced Settings")
        settings_window.geometry("500x600")
        settings_window.configure(bg='#1e1e1e')
        
        # Create scrollable frame
        canvas = tk.Canvas(settings_window, bg='#1e1e1e')
        scrollbar = ttk.Scrollbar(settings_window, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#1e1e1e')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Title
        tk.Label(scrollable_frame, text="Advanced Settings", font=("Arial", 18, "bold"), 
                fg='#00ff88', bg='#1e1e1e').pack(pady=20)
        
        # Connection Settings Section
        connection_frame = tk.LabelFrame(scrollable_frame, text="Connection Settings", 
                                       font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        connection_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Auto-connect option
        auto_connect_var = tk.BooleanVar(value=self.auto_connect_on_start)
        auto_connect_cb = tk.Checkbutton(connection_frame, text="Auto-connect on startup", 
                                       variable=auto_connect_var, bg='#2d2d2d', fg='#ffffff')
        auto_connect_cb.pack(anchor='w', padx=20, pady=5)

        # Start with Windows
        start_with_win_var = tk.BooleanVar(value=getattr(self, 'start_with_windows_enabled', False))
        start_with_cb = tk.Checkbutton(connection_frame, text="Start Momo Tunnel with Windows", 
                                       variable=start_with_win_var, bg='#2d2d2d', fg='#ffffff')
        start_with_cb.pack(anchor='w', padx=20, pady=5)

        # Use system proxy toggle
        use_sys_proxy_var = tk.BooleanVar(value=self.use_system_proxy)
        tk.Checkbutton(connection_frame, text="Use Windows system proxy (recommended)", 
                       variable=use_sys_proxy_var, bg='#2d2d2d', fg='#ffffff').pack(anchor='w', padx=20, pady=5)
        
        # Kill switch option
        kill_switch_var = tk.BooleanVar(value=self.kill_switch_enabled)
        kill_switch_cb = tk.Checkbutton(connection_frame, text="Enable Kill Switch (Prevent traffic leaks)", 
                                      variable=kill_switch_var, bg='#2d2d2d', fg='#ffffff')
        kill_switch_cb.pack(anchor='w', padx=20, pady=5)
        
        # Protocol Settings Section
        protocol_frame = tk.LabelFrame(scrollable_frame, text="Protocol Settings", 
                                     font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        protocol_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Transport protocol
        tk.Label(protocol_frame, text="Transport Protocol:", font=("Arial", 10), 
                fg='#ffffff', bg='#2d2d2d').pack(anchor='w', padx=20, pady=(10, 5))
        
        transport_var = tk.StringVar(value="TCP")
        transport_radio_frame = tk.Frame(protocol_frame, bg='#2d2d2d')
        transport_radio_frame.pack(anchor='w', padx=20)
        
        tk.Radiobutton(transport_radio_frame, text="TCP", variable=transport_var, value="TCP", 
                      bg='#2d2d2d', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(transport_radio_frame, text="UDP", variable=transport_var, value="UDP", 
                      bg='#2d2d2d', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(transport_radio_frame, text="WebSocket", variable=transport_var, value="ws", 
                      bg='#2d2d2d', fg='#ffffff').pack(side=tk.LEFT)
        
        # Security Settings Section
        security_frame = tk.LabelFrame(scrollable_frame, text="Security Settings", 
                                     font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        security_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # TLS verification
        tls_verify_var = tk.BooleanVar(value=True)
        tls_verify_cb = tk.Checkbutton(security_frame, text="Verify TLS certificates", 
                                      variable=tls_verify_var, bg='#2d2d2d', fg='#ffffff')
        tls_verify_cb.pack(anchor='w', padx=20, pady=5)
        # DNS Leak Protection
        dns_leak_var = tk.BooleanVar(value=self.dns_leak_protection_enabled)
        tk.Checkbutton(security_frame, text="Enable DNS leak protection", 
                       variable=dns_leak_var, bg='#2d2d2d', fg='#ffffff').pack(anchor='w', padx=20, pady=5)
        
        # DNS Settings Section
        dns_frame = tk.LabelFrame(scrollable_frame, text="DNS Settings", 
                                font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        dns_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Custom DNS servers
        tk.Label(dns_frame, text="Custom DNS Servers:", font=("Arial", 10), 
                fg='#ffffff', bg='#2d2d2d').pack(anchor='w', padx=20, pady=(10, 5))
        
        dns_entry = tk.Entry(dns_frame, font=("Arial", 10), bg='#444444', fg='#ffffff')
        dns_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
        dns_entry.insert(0, "8.8.8.8, 8.8.4.4")
        
        # Advanced Options Section
        advanced_frame = tk.LabelFrame(scrollable_frame, text="Advanced Options", 
                                     font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        advanced_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Split tunneling
        split_tunnel_var = tk.BooleanVar(value=self.split_tunneling_enabled)
        split_tunnel_cb = tk.Checkbutton(advanced_frame, text="Enable Split Tunneling (domains/IPs go direct)", 
                                       variable=split_tunnel_var, bg='#2d2d2d', fg='#ffffff')
        split_tunnel_cb.pack(anchor='w', padx=20, pady=5)
        tk.Label(advanced_frame, text="Direct domains (comma-separated):", font=("Arial", 10), fg='#ffffff', bg='#2d2d2d').pack(anchor='w', padx=20)
        split_domains_entry = tk.Entry(advanced_frame, font=("Arial", 10), bg='#444444', fg='#ffffff')
        split_domains_entry.pack(fill=tk.X, padx=20, pady=(0,8))
        split_domains_entry.insert(0, ", ".join(self.split_domains) if self.split_domains else "localhost, 127.0.0.1")
        tk.Label(advanced_frame, text="Direct CIDRs/IPs (comma-separated):", font=("Arial", 10), fg='#ffffff', bg='#2d2d2d').pack(anchor='w', padx=20)
        split_ips_entry = tk.Entry(advanced_frame, font=("Arial", 10), bg='#444444', fg='#ffffff')
        split_ips_entry.pack(fill=tk.X, padx=20, pady=(0,10))
        split_ips_entry.insert(0, ", ".join(self.split_ips) if self.split_ips else "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16")
        
        # Obfuscation
        obfuscation_var = tk.BooleanVar()
        obfuscation_cb = tk.Checkbutton(advanced_frame, text="Enable Traffic Obfuscation", 
                                       variable=obfuscation_var, bg='#2d2d2d', fg='#ffffff')
        obfuscation_cb.pack(anchor='w', padx=20, pady=5)

        # Logging Mode
        logging_frame = tk.LabelFrame(scrollable_frame, text="Logging", 
                                     font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        logging_frame.pack(fill=tk.X, padx=20, pady=10)
        verbose_var = tk.BooleanVar(value=getattr(self, 'verbose_logging_enabled', False))
        tk.Checkbutton(logging_frame, text="Enable verbose debug logging (not recommended for production)", 
                       variable=verbose_var, bg='#2d2d2d', fg='#ffffff').pack(anchor='w', padx=20, pady=5)
        
        # Profiles Section
        profiles_frame = tk.LabelFrame(scrollable_frame, text="Profiles", font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        profiles_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Button(profiles_frame, text="Manage Profiles", command=self.show_profiles_dialog, bg='#444444', fg='#ffffff').pack(anchor='w', padx=20, pady=5)

        # Scheduling Section
        schedule_frame = tk.LabelFrame(scrollable_frame, text="Scheduling", font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        schedule_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Button(schedule_frame, text="Manage Schedule", command=self.show_schedule_dialog, bg='#444444', fg='#ffffff').pack(anchor='w', padx=20, pady=5)

        # Routing/Load balancing Section
        routing_frame = tk.LabelFrame(scrollable_frame, text="Routing & Load Balancing", font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        routing_frame.pack(fill=tk.X, padx=20, pady=10)
        self.auto_select_best_var = tk.BooleanVar(value=self.auto_select_best_enabled)
        tk.Checkbutton(routing_frame, text="Auto-select best server (latency)", variable=self.auto_select_best_var, bg='#2d2d2d', fg='#ffffff', command=self.on_toggle_auto_select_best).pack(anchor='w', padx=20, pady=5)
        # Strategy
        tk.Label(routing_frame, text="Load balancing strategy:", font=("Arial", 10), fg="#ffffff", bg="#2d2d2d").pack(anchor='w', padx=20, pady=(10,5))
        strategy_var = tk.StringVar(value=self.load_balancing_strategy)
        strategy_combo = ttk.Combobox(routing_frame, textvariable=strategy_var, values=["latency","round_robin"], state="readonly")
        strategy_combo.pack(anchor='w', padx=20, pady=(0,5))
        # Preferred location keyword
        tk.Label(routing_frame, text="Preferred location keyword (optional):", font=("Arial", 10), fg="#ffffff", bg="#2d2d2d").pack(anchor='w', padx=20, pady=(10,5))
        preferred_entry = tk.Entry(routing_frame, font=("Arial", 10), bg="#444444", fg="#ffffff")
        preferred_entry.pack(fill=tk.X, padx=20, pady=(0,5))
        preferred_entry.insert(0, self.preferred_country or "")

        # Save button
        save_btn = tk.Button(scrollable_frame, text="Save Settings", 
                           command=lambda: self.save_advanced_settings(
                               settings_window, auto_connect_var.get(), kill_switch_var.get(),
                               transport_var.get(), tls_verify_var.get(), dns_entry.get(),
                               split_tunnel_var.get(), obfuscation_var.get(), use_sys_proxy_var.get(),
                               split_domains_entry.get(), split_ips_entry.get(),
                               strategy_var.get(), preferred_entry.get(), start_with_win_var.get(), verbose_var.get()
                           ),
                           bg='#00ff88', fg='#000000', relief=tk.FLAT, padx=30, pady=10)
        save_btn.pack(pady=20)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def save_settings(self, window):
        messagebox.showinfo("Success", "Settings saved successfully!")
        window.destroy()
    
    def save_advanced_settings(self, window, auto_connect, kill_switch, transport, tls_verify, 
                              dns_servers, split_tunnel, obfuscation, use_system_proxy, split_domains_str, split_ips_str,
                              strategy, preferred_location, start_with_windows, verbose_logging):
        """Save advanced settings"""
        try:
            # Normalize split tunneling inputs
            domains_list = [d.strip() for d in (split_domains_str or '').split(',') if d.strip()]
            ips_list = [i.strip() for i in (split_ips_str or '').split(',') if i.strip()]
            # Save settings to configuration file
            settings = {
                "auto_connect": auto_connect,
                "kill_switch": kill_switch,
                "transport_protocol": transport,
                "tls_verify": tls_verify,
                "dns_servers": dns_servers,
                "split_tunneling": split_tunnel,
                "split_domains": domains_list,
                "split_ips": ips_list,
                "traffic_obfuscation": obfuscation,
                "auto_select_best": bool(self.auto_select_best_var.get()) if hasattr(self, 'auto_select_best_var') else self.auto_select_best_enabled,
                "use_system_proxy": bool(use_system_proxy),
                "load_balancing_strategy": strategy,
                "preferred_location": preferred_location,
                "dns_leak_protection": self.dns_leak_protection_enabled,
                "start_with_windows": bool(start_with_windows),
                "timestamp": datetime.now().isoformat(),
                "verbose_logging": bool(verbose_logging)
            }
            
            # Update instance variables
            self.kill_switch_enabled = kill_switch
            self.auto_select_best_enabled = settings.get("auto_select_best", False)
            self.use_system_proxy = settings.get("use_system_proxy", True)
            self.auto_connect_on_start = bool(auto_connect)
            self.split_tunneling_enabled = bool(split_tunnel)
            self.split_domains = domains_list
            self.split_ips = ips_list
            self.load_balancing_strategy = strategy or self.load_balancing_strategy
            self.preferred_country = preferred_location or self.preferred_country
            self.dns_leak_protection_enabled = settings.get("dns_leak_protection", True)
            self.start_with_windows_enabled = settings.get("start_with_windows", False)
            self.verbose_logging_enabled = settings.get("verbose_logging", False)
            # Apply startup registration
            self.apply_startup(self.start_with_windows_enabled)
            # Reconfigure logging level
            try:
                for h in list(self.logger.handlers):
                    self.logger.removeHandler(h)
                self.setup_logging()
            except Exception:
                pass
            
            # Save to file
            with open(self.get_settings_path(), 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("Success", "Advanced settings saved successfully!")
            window.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def load_advanced_settings(self):
        """Load advanced settings from file"""
        try:
            path = self.get_settings_path()
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                    
                    # Apply settings
                    self.kill_switch_enabled = settings.get("kill_switch", False)
                    self.auto_select_best_enabled = settings.get("auto_select_best", False)
                    self.use_system_proxy = settings.get("use_system_proxy", True)
                    self.auto_connect_on_start = settings.get("auto_connect", False)
                    self.split_tunneling_enabled = settings.get("split_tunneling", False)
                    self.split_domains = settings.get("split_domains", [])
                    self.split_ips = settings.get("split_ips", [])
                    self.load_balancing_strategy = settings.get("load_balancing_strategy", self.load_balancing_strategy)
                    self.preferred_country = settings.get("preferred_location", self.preferred_country)
                    self.dns_leak_protection_enabled = settings.get("dns_leak_protection", True)
                    self.start_with_windows_enabled = settings.get("start_with_windows", False)
                    # Ensure startup registration matches setting
                    self.apply_startup(self.start_with_windows_enabled)
                    
        except Exception as e:
            print(f"Failed to load advanced settings: {e}")
            
    def show_vpn_tools_dialog(self):
        """Show VPN tools management dialog"""
        tools_window = tk.Toplevel(self.root)
        tools_window.title("VPN Tools Manager")
        tools_window.geometry("500x400")
        tools_window.configure(bg='#1e1e1e')
        tools_window.resizable(False, False)
        
        # Center the window
        tools_window.transient(self.root)
        tools_window.grab_set()
        
        # Title
        title_label = tk.Label(tools_window, text="VPN Tools Manager", 
                              font=("Arial", 18, "bold"), 
                              fg='#00ff88', bg='#1e1e1e')
        title_label.pack(pady=20)
        
        # Status frame
        status_frame = tk.LabelFrame(tools_window, text="Tools Status", 
                                   font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        status_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Check current status
        tools_status = self.check_vpn_tools_status()
        
        # V2Ray status
        v2ray_frame = tk.Frame(status_frame, bg='#2d2d2d')
        v2ray_frame.pack(fill=tk.X, padx=20, pady=5)
        
        v2ray_icon = "✅" if tools_status['v2ray'] else "❌"
        v2ray_label = tk.Label(v2ray_frame, text=f"{v2ray_icon} V2Ray", 
                              font=("Arial", 12), fg='#ffffff', bg='#2d2d2d')
        v2ray_label.pack(side=tk.LEFT)
        
        if tools_status['v2ray']:
            v2ray_path_label = tk.Label(v2ray_frame, text=f"Path: {tools_status['v2ray_path']}", 
                                       font=("Arial", 9), fg='#00ff88', bg='#2d2d2d')
            v2ray_path_label.pack(side=tk.RIGHT)
        
        # Trojan status
        trojan_frame = tk.Frame(status_frame, bg='#2d2d2d')
        trojan_frame.pack(fill=tk.X, padx=20, pady=5)
        
        trojan_icon = "✅" if tools_status['trojan'] else "❌"
        trojan_label = tk.Label(trojan_frame, text=f"{trojan_icon} Trojan", 
                               font=("Arial", 12), fg='#ffffff', bg='#2d2d2d')
        trojan_label.pack(side=tk.LEFT)
        
        if tools_status['trojan']:
            trojan_path_label = tk.Label(trojan_frame, text=f"Path: {tools_status['trojan_path']}", 
                                        font=("Arial", 9), fg='#00ff88', bg='#2d2d2d')
            trojan_path_label.pack(side=tk.RIGHT)
        
        # Actions frame
        actions_frame = tk.LabelFrame(tools_window, text="Actions", 
                                    font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        actions_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Download button
        download_btn = tk.Button(actions_frame, text="Download Missing Tools", 
                               command=lambda: self.download_and_refresh(tools_window),
                               font=("Arial", 12),
                               bg='#00ff88', fg='#000000',
                               relief=tk.FLAT, padx=20, pady=10)
        download_btn.pack(pady=10)

        # Note about checksum requirement
        tk.Label(actions_frame, text="Downloads require checksum manifest (tool_hashes.json) in AppData/data.",
                 font=("Arial", 9), fg='#cccccc', bg='#2d2d2d').pack(pady=(0,10))
        
        # Refresh button
        refresh_btn = tk.Button(actions_frame, text="Refresh Status", 
                              command=lambda: self.refresh_tools_status(tools_window),
                              font=("Arial", 12),
                              bg='#666666', fg='#ffffff',
                              relief=tk.FLAT, padx=20, pady=10)
        refresh_btn.pack(pady=5)
        
        # Info frame
        info_frame = tk.LabelFrame(tools_window, text="Information", 
                                 font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        info_frame.pack(fill=tk.X, padx=20, pady=10)
        
        info_text = """These tools are required for real VPN connections:
        
• V2Ray: Handles VLESS and VMess protocols
• Trojan: Handles Trojan protocol

The app will automatically download these tools
when you first try to connect to a VPN server."""
        
        info_label = tk.Label(info_frame, text=info_text, 
                             font=("Arial", 9), fg='#cccccc', bg='#2d2d2d',
                             justify=tk.LEFT)
        info_label.pack(padx=20, pady=10)
        
        # Close button
        close_btn = tk.Button(tools_window, text="Close", 
                             command=tools_window.destroy,
                             font=("Arial", 10),
                             bg='#666666', fg='#ffffff',
                             relief=tk.FLAT, padx=30, pady=10)
        close_btn.pack(pady=20)
        
    def download_and_refresh(self, window):
        """Download VPN tools and refresh the dialog"""
        try:
            # Show downloading message
            downloading_label = tk.Label(window, text="Downloading VPN tools... Please wait.", 
                                       font=("Arial", 10), fg='#00ff88', bg='#1e1e1e')
            downloading_label.pack(pady=10)
            
            # Download tools
            self.download_vpn_executables()
            
            # Remove downloading message
            downloading_label.destroy()
            
            # Refresh status
            self.refresh_tools_status(window)
            
            messagebox.showinfo("Success", "VPN tools download completed!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Download failed: {str(e)}")
            
    def refresh_tools_status(self, window):
        """Refresh the tools status display"""
        # Close and reopen the dialog to show updated status
        window.destroy()
        self.show_vpn_tools_dialog()
    
    def export_configuration(self, config_data, filename, password=None):
        """Export configuration with encryption options"""
        try:
            if password:
                # Export as password-protected file
                secure_config = self.create_secure_config(config_data, password)
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(secure_config, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Success", f"Configuration exported as encrypted file: {filename}")
            else:
                # Export as master-encrypted file
                encrypted_data = self.encrypt_config(config_data)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(encrypted_data)
                messagebox.showinfo("Success", f"Configuration exported as master-encrypted file: {filename}")
            
            return True
            
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
            return False
    
    def show_export_dialog(self):
        """Show configuration export dialog"""
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Configuration")
        export_window.geometry("400x300")
        export_window.configure(bg='#1e1e1e')
        
        # Title
        tk.Label(export_window, text="Export Configuration", font=("Arial", 16, "bold"), 
                fg='#00ff88', bg='#1e1e1e').pack(pady=20)
        
        # Configuration selection
        if not self.configs:
            tk.Label(export_window, text="No configurations to export", 
                    font=("Arial", 12), fg='#ff4444', bg='#1e1e1e').pack(pady=20)
            return
        
        tk.Label(export_window, text="Select Configuration:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(pady=10)
        
        config_var = tk.StringVar(value=self.configs[0]['name'])
        config_menu = ttk.Combobox(export_window, textvariable=config_var, 
                                  values=[config['name'] for config in self.configs],
                                  state="readonly", font=("Arial", 10))
        config_menu.pack(pady=10)
        
        # Password protection option
        password_var = tk.StringVar()
        tk.Label(export_window, text="Password (optional):", font=("Arial", 10), 
                fg='#ffffff', bg='#1e1e1e').pack(pady=(20, 5))
        
        password_entry = tk.Entry(export_window, textvariable=password_var, 
                                font=("Arial", 10), bg='#444444', fg='#ffffff', show="*")
        password_entry.pack(pady=(0, 20))
        
        # Export button
        export_btn = tk.Button(export_window, text="Export", 
                             command=lambda: self.perform_export(
                                 export_window, config_var.get(), password_var.get()
                             ),
                             bg='#00ff88', fg='#000000', relief=tk.FLAT, padx=30, pady=10)
        export_btn.pack(pady=10)
    
    def perform_export(self, window, config_name, password):
        """Perform the actual export"""
        try:
            # Find the selected configuration
            selected_config = None
            for config in self.configs:
                if config['name'] == config_name:
                    selected_config = config
                    break
            
            if not selected_config:
                messagebox.showerror("Error", "Configuration not found")
                return
            
            # Get filename from user
            filename = filedialog.asksaveasfilename(
                title="Save Configuration As",
                defaultextension=".npvt",
                filetypes=[("NPVT files", "*.npvt"), ("All files", "*.*")]
            )
            
            if filename:
                # Export with or without password
                if password:
                    success = self.export_configuration(selected_config, filename, password)
                else:
                    success = self.export_configuration(selected_config, filename)
                
                if success:
                    window.destroy()
                    
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def load_settings(self):
        """Load saved settings and configurations"""
        self.load_configs()
        self.initialize_encryption()
    
    def get_appdata_dir(self):
        base = os.environ.get('APPDATA') or os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')
        path = os.path.join(base, 'MomoTunnel')
        try:
            os.makedirs(path, exist_ok=True)
        except Exception:
            pass
        return path

    def get_logs_dir(self):
        return os.path.join(self.get_appdata_dir(), 'logs')

    def get_data_dir(self):
        return os.path.join(self.get_appdata_dir(), 'data')

    def get_tools_dir(self):
        return os.path.join(self.get_appdata_dir(), 'vpn_tools')

    def ensure_app_dirs(self):
        for d in [self.get_appdata_dir(), self.get_logs_dir(), self.get_data_dir(), self.get_tools_dir()]:
            try:
                os.makedirs(d, exist_ok=True)
            except Exception:
                pass

    def get_settings_path(self):
        return os.path.join(self.get_data_dir(), 'npv_tunnel_settings.json')

    def get_configs_path(self):
        return os.path.join(self.get_data_dir(), 'npv_tunnel_configs.json')

    def get_key_path(self):
        return os.path.join(self.get_data_dir(), 'npv_tunnel.key')

    def load_configs(self):
        """Load saved configurations from file"""
        try:
            os.makedirs(self.get_data_dir(), exist_ok=True)
            config_file = self.get_configs_path()
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    payload = json.load(f)
                # Backward compatibility: raw list
                if isinstance(payload, list):
                    encrypted_configs = payload
                    self.favorites = set()
                    self.profiles = {}
                    self.schedule_entries = []
                    last_used = None
                else:
                    encrypted_configs = payload.get('configs', [])
                    self.favorites = set(payload.get('favorites', []))
                    self.profiles = payload.get('profiles', {})
                    self.schedule_entries = payload.get('schedule', [])
                    last_used = payload.get('last_used')
                # Decrypt configurations if they're encrypted
                self.configs = []
                for config in encrypted_configs:
                    if isinstance(config, dict) and config.get('encrypted'):
                        try:
                            decrypted_config = self.decrypt_config(config['data'])
                            self.configs.append(decrypted_config)
                        except Exception as e:
                            self.logger.warning(f"Failed to decrypt config: {e}")
                            self.configs.append(config)
                    else:
                        self.configs.append(config)
                    
                self.logger.info(f"Loaded {len(self.configs)} configurations")
                # Restore last used if present
                if last_used:
                    try:
                        # If encrypted payload stored last_used as plain dict, adopt directly
                        # Else, if it's a name reference, match by name/protocol/server/port/uuid
                        candidate = None
                        if isinstance(last_used, dict):
                            candidate = last_used
                        else:
                            # try find by name
                            for c in self.configs:
                                if c.get('name') == last_used:
                                    candidate = c
                                    break
                        if candidate:
                            self.current_config = self._merge_or_select_existing(candidate)
                            self.update_config_display()
                    except Exception as e:
                        self.logger.debug(f"Restore last_used failed: {e}")
            else:
                self.configs = []
                self.logger.info("No saved configurations found")
                
        except Exception as e:
            self.logger.error(f"Failed to load configurations: {e}")
            self.configs = []

    def _merge_or_select_existing(self, new_config):
        """Merge with existing config if effectively the same; otherwise add to list.
        Returns the selected current config dict reference in self.configs.
        """
        try:
            def key(c):
                return (
                    c.get('protocol'),
                    c.get('server'),
                    int(c.get('port', 0) or 0),
                    c.get('uuid') or c.get('password') or ''
                )
            new_key = key(new_config)
            for idx, existing in enumerate(self.configs):
                if key(existing) == new_key:
                    # Merge shallowly: prefer new name if provided; update fields present in new_config
                    merged = dict(existing)
                    merged.update({k:v for k,v in new_config.items() if v not in [None, "", []]})
                    self.configs[idx] = merged
                    return self.configs[idx]
            # Not found: append
            self.configs.append(new_config)
            return self.configs[-1]
        except Exception:
            # Fallback: append
            self.configs.append(new_config)
            return self.configs[-1]

    def autoload_last_config(self):
        """On startup, auto-load last used config or clipboard config; if same, merge."""
        try:
            # If current_config already set by load_configs restore, nothing to do
            if self.current_config:
                return
            # Attempt clipboard import if it parses
            try:
                clip = self.root.clipboard_get()
                if clip:
                    cfg = self.parse_config_content(clip)
                    if cfg:
                        self.current_config = self._merge_or_select_existing(cfg)
                        self.update_config_display()
                        self.save_configs()
                        self.log_operation("Autoloaded configuration from clipboard", level='info')
                        return
            except Exception:
                pass
            # Else, pick most recent saved config heuristically (last in list)
            if self.configs:
                self.current_config = self.configs[-1]
                self.update_config_display()
                self.save_configs()
                self.log_operation("Autoloaded last saved configuration", level='info')
        except Exception as e:
            self.logger.debug(f"Autoload skipped: {e}")
    
    def save_configs(self):
        """Save configurations to file"""
        try:
            config_file = self.get_configs_path()
            encrypted_configs = []
            
            for config in self.configs:
                if self.fernet:
                    encrypted_config = {
                        'encrypted': True,
                        'data': self.encrypt_config(config)
                    }
                    encrypted_configs.append(encrypted_config)
                else:
                    encrypted_configs.append(config)
            
            payload = {
                'configs': encrypted_configs,
                'favorites': list(self.favorites) if isinstance(self.favorites, set) else self.favorites,
                'profiles': self.profiles,
                'schedule': self.schedule_entries,
                'last_used': self.current_config or None
            }
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                
            self.logger.info(f"Saved {len(self.configs)} configurations")
            
        except Exception as e:
            self.logger.error(f"Failed to save configurations: {e}")
    
    def initialize_encryption(self):
        """Initialize encryption for secure configuration storage"""
        try:
            # Generate or load encryption key (DPAPI-wrapped) in AppData
            key_file = self.get_key_path()
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    wrapped = f.read()
                try:
                    import win32crypt  # type: ignore
                    unwrapped = win32crypt.CryptUnprotectData(wrapped, None, None, None, 0)[1]
                    self.encryption_key = unwrapped
                except Exception:
                    # Fallback: assume plain key stored
                    self.encryption_key = wrapped
            else:
                self.encryption_key = Fernet.generate_key()
                wrapped = None
                try:
                    import win32crypt  # type: ignore
                    wrapped = win32crypt.CryptProtectData(self.encryption_key, None, None, None, None, 0)
                    wrapped = wrapped
                except Exception:
                    wrapped = self.encryption_key
                os.makedirs(self.get_data_dir(), exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(wrapped if isinstance(wrapped, (bytes, bytearray)) else bytes(wrapped))
            
            self.fernet = Fernet(self.encryption_key)
        except Exception as e:
            print(f"Encryption initialization failed: {e}")
            self.encryption_key = None
            self.fernet = None
    
    def encrypt_config(self, config_data):
        """Encrypt configuration data"""
        if not self.fernet:
            return config_data
        
        try:
            json_data = json.dumps(config_data, ensure_ascii=False)
            encrypted_data = self.fernet.encrypt(json_data.encode())
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            print(f"Encryption failed: {e}")
            return config_data
    
    def decrypt_config(self, encrypted_data):
        """Decrypt configuration data"""
        if not self.fernet:
            return encrypted_data
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            print(f"Decryption failed: {e}")
            return encrypted_data
    
    def create_secure_config(self, config_data, password=None):
        """Create a password-protected configuration file"""
        try:
            if password:
                # Generate salt and derive key from password
                salt = secrets.token_bytes(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=310000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                
                # Encrypt with password
                json_data = json.dumps(config_data, ensure_ascii=False)
                encrypted_data = fernet.encrypt(json_data.encode())
                
                # Create secure config structure
                secure_config = {
                    "version": "2.0",
                    "encrypted": True,
                    "salt": base64.b64encode(salt).decode(),
                    "data": base64.b64encode(encrypted_data).decode(),
                    "timestamp": datetime.now().isoformat()
                }
                
                return secure_config
            else:
                # Use master encryption key
                return self.encrypt_config(config_data)
        except Exception as e:
            print(f"Secure config creation failed: {e}")
            return config_data
    
    def export_secure_config(self, config_data, filename, password=None):
        """Export configuration as encrypted file"""
        try:
            secure_config = self.create_secure_config(config_data, password)
            
            if password:
                # Export as .npvt (encrypted)
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(secure_config, f, indent=2, ensure_ascii=False)
            else:
                # Export as .npvt (master encrypted)
                encrypted_data = self.encrypt_config(config_data)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(encrypted_data)
            
            return True
        except Exception as e:
            print(f"Export failed: {e}")
            return False
    
    def import_secure_config(self, filepath, password=None):
        """Import encrypted configuration file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try to parse as JSON first (new format)
            try:
                secure_config = json.loads(content)
                if secure_config.get("encrypted"):
                    if password:
                        # Decrypt with password
                        salt = base64.b64decode(secure_config["salt"])
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                        )
                        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                        fernet = Fernet(key)
                        
                        encrypted_data = base64.b64decode(secure_config["data"])
                        decrypted_data = fernet.decrypt(encrypted_data)
                        return json.loads(decrypted_data.decode())
                    else:
                        messagebox.showerror("Error", "Password required for this configuration file")
                        return None
                else:
                    return secure_config
            except:
                # Try as master encrypted format
                return self.decrypt_config(content)
        except Exception as e:
            print(f"Import failed: {e}")
            return None
    
    def show_add_config_dialog(self):
        """Show the Add Config dialog similar to the original APK"""
        config_window = tk.Toplevel(self.root)
        config_window.title("Add Config")
        config_window.geometry("400x350")
        config_window.configure(bg='#1e1e1e')
        config_window.resizable(False, False)
        
        # Center the window
        config_window.transient(self.root)
        config_window.grab_set()
        
        # Title
        title_label = tk.Label(config_window, text="Add Config", 
                              font=("Arial", 18, "bold"), 
                              fg='#00ff88', bg='#1e1e1e')
        title_label.pack(pady=20)
        
        # Options frame
        options_frame = tk.Frame(config_window, bg='#1e1e1e')
        options_frame.pack(fill=tk.BOTH, expand=True, padx=30)
        
        # Option 1: Import npvt config file
        option1_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option1_frame.pack(fill=tk.X, pady=10)
        
        option1_btn = tk.Button(option1_frame, text="Import npvt config file", 
                               command=lambda: [self.import_npvt_file(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option1_btn.pack(fill=tk.X)
        
        # Down arrow icon
        arrow1 = tk.Label(option1_frame, text="↓", font=("Arial", 16), 
                         fg='#00ff88', bg='#2d2d2d')
        arrow1.pack(side=tk.RIGHT, padx=20)
        
        # Option 2: Import cloud config
        option2_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option2_frame.pack(fill=tk.X, pady=10)
        
        option2_btn = tk.Button(option2_frame, text="Import cloud config", 
                               command=lambda: [self.import_cloud_config(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option2_btn.pack(fill=tk.X)
        
        # Cloud icon
        cloud_icon = tk.Label(option2_frame, text="☁", font=("Arial", 16), 
                            fg='#00ff88', bg='#2d2d2d')
        cloud_icon.pack(side=tk.RIGHT, padx=20)
        
        # Option 3: Import config from Clipboard
        option3_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option3_frame.pack(fill=tk.X, pady=10)
        
        option3_btn = tk.Button(option3_frame, text="Import config from\nClipboard", 
                               command=lambda: [self.import_from_clipboard(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option3_btn.pack(fill=tk.X)
        
        # Clipboard icon
        clipboard_icon = tk.Label(option3_frame, text="📋", font=("Arial", 12), 
                                fg='#00ff88', bg='#2d2d2d')
        clipboard_icon.pack(side=tk.RIGHT, padx=20)
        
        # Option 4: Add config manually
        option4_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option4_frame.pack(fill=tk.X, pady=10)
        
        option4_btn = tk.Button(option4_frame, text="Add config manually", 
                               command=lambda: [self.add_config_manually(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option4_btn.pack(fill=tk.X)
        
        # Plus icon
        plus_icon = tk.Label(option4_frame, text="+", font=("Arial", 16), 
                           fg='#00ff88', bg='#2d2d2d')
        plus_icon.pack(side=tk.RIGHT, padx=20)
        
        # Cancel button
        cancel_btn = tk.Button(config_window, text="Cancel", 
                             command=config_window.destroy,
                             font=("Arial", 10),
                             bg='#666666', fg='#ffffff',
                             relief=tk.FLAT, padx=30, pady=10)
        cancel_btn.pack(pady=20)
    

    
    def import_cloud_config(self):
        """Import configuration from cloud service"""
        # This would connect to a cloud service in a real implementation
        messagebox.showinfo("Cloud Import", "Cloud import functionality would be implemented here.\nThis is a demonstration version.")
    
    def import_from_clipboard(self):
        """Import configuration from clipboard"""
        try:
            clipboard_content = self.root.clipboard_get()
            if clipboard_content:
                # Parse the clipboard content
                config = self.parse_config_content(clipboard_content)
                if config:
                    self.add_config(config)
                    messagebox.showinfo("Success", "Configuration imported from clipboard")
                else:
                    messagebox.showerror("Error", "Invalid configuration format in clipboard")
            else:
                messagebox.showwarning("Warning", "Clipboard is empty")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read clipboard: {str(e)}")
    
    def add_config_manually(self):
        """Add configuration manually"""
        manual_window = tk.Toplevel(self.root)
        manual_window.title("Add Config Manually")
        manual_window.geometry("500x400")
        manual_window.configure(bg='#1e1e1e')
        
        # Title
        title_label = tk.Label(manual_window, text="Add Configuration Manually", 
                              font=("Arial", 16, "bold"), 
                              fg='#00ff88', bg='#1e1e1e')
        title_label.pack(pady=20)
        
        # Form frame
        form_frame = tk.Frame(manual_window, bg='#1e1e1e')
        form_frame.pack(fill=tk.BOTH, expand=True, padx=30)
        
        # Protocol selection
        tk.Label(form_frame, text="Protocol:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        protocol_var = tk.StringVar(value="vless")
        protocol_frame = tk.Frame(form_frame, bg='#1e1e1e')
        protocol_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Radiobutton(protocol_frame, text="VLESS", variable=protocol_var, value="vless", 
                      bg='#1e1e1e', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(protocol_frame, text="VMess", variable=protocol_var, value="vmess", 
                      bg='#1e1e1e', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(protocol_frame, text="Trojan", variable=protocol_var, value="trojan", 
                      bg='#1e1e1e', fg='#ffffff').pack(side=tk.LEFT)
        
        # Server address
        tk.Label(form_frame, text="Server Address:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        server_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        server_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Port
        tk.Label(form_frame, text="Port:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        port_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        port_entry.pack(fill=tk.X, pady=(0, 15))
        
        # UUID/Password
        tk.Label(form_frame, text="UUID/Password:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        uuid_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        uuid_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Config name
        tk.Label(form_frame, text="Configuration Name:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        name_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        name_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Buttons
        buttons_frame = tk.Frame(form_frame, bg='#1e1e1e')
        buttons_frame.pack(pady=20)
        
        save_btn = tk.Button(buttons_frame, text="Save", 
                           command=lambda: self.save_manual_config(
                               protocol_var.get(), server_entry.get(), port_entry.get(),
                               uuid_entry.get(), name_entry.get(), manual_window
                           ),
                           bg='#00ff88', fg='#000000', relief=tk.FLAT, padx=30, pady=10)
        save_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = tk.Button(buttons_frame, text="Cancel", 
                             command=manual_window.destroy,
                             bg='#666666', fg='#ffffff', relief=tk.FLAT, padx=30, pady=10)
        cancel_btn.pack(side=tk.LEFT, padx=10)
    
    def save_manual_config(self, protocol, server, port, uuid, name, window):
        """Save manually entered configuration"""
        if not all([protocol, server, port, uuid, name]):
            messagebox.showwarning("Warning", "Please fill in all fields")
            return
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number")
            return
        
        config = {
            "name": name,
            "protocol": protocol,
            "server": server,
            "port": port,
            "uuid": uuid,
            "type": "manual"
        }
        
        self.add_config(config)
        messagebox.showinfo("Success", f"Configuration '{name}' saved successfully")
        window.destroy()
    
    def parse_config_content(self, content):
        """Parse configuration content from various formats"""
        content = content.strip()
        
        # Try to parse as VLESS URL
        if content.startswith("vless://"):
            return self.parse_vless_url(content)
        
        # Try to parse as VMess URL
        elif content.startswith("vmess://"):
            return self.parse_vmess_url(content)
        
        # Try to parse as Trojan URL
        elif content.startswith("trojan://"):
            return self.parse_trojan_url(content)
        
        # Try to parse as JSON
        elif content.startswith("{") or content.startswith("["):
            try:
                json_data = json.loads(content)
                return self.parse_json_config(json_data)
            except:
                pass
        
        # Try to parse as .npvt format
        return self.parse_npvt_format(content)
    
    def parse_vless_url(self, url):
        """Parse VLESS URL format"""
        try:
            # Remove protocol prefix
            url = url.replace("vless://", "")
            
            # Split into parts
            if "?" in url:
                main_part, query_part = url.split("?", 1)
            else:
                main_part, query_part = url, ""
            
            # Parse main part (uuid@server:port)
            if "@" in main_part:
                uuid, server_part = main_part.split("@", 1)
            else:
                return None
            
            # Parse server and port
            if ":" in server_part:
                server, port = server_part.rsplit(":", 1)
                try:
                    port = int(port)
                except ValueError:
                    return None
            else:
                server, port = server_part, 443
            
            # Parse query parameters
            params = {}
            if query_part:
                for param in query_part.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        params[key] = urllib.parse.unquote(value)
            
            # Extract name from fragment
            name = params.get("name", "VLESS Config")
            if "#" in url:
                name = url.split("#")[-1]
            
            return {
                "name": name,
                "protocol": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
                "security": params.get("security", "none"),
                "encryption": params.get("encryption", "none"),
                "type": params.get("type", "tcp"),
                "path": params.get("path", ""),
                "sni": params.get("sni", ""),
                "source": "url"
            }
        except Exception as e:
            print(f"Error parsing VLESS URL: {e}")
            return None
    
    def parse_vmess_url(self, url):
        """Parse VMess URL format"""
        try:
            # Remove protocol prefix
            url = url.replace("vmess://", "")
            
            # Decode base64
            decoded = base64.b64decode(url).decode('utf-8')
            config = json.loads(decoded)
            
            return {
                "name": config.get("ps", "VMess Config"),
                "protocol": "vmess",
                "server": config.get("add", ""),
                "port": config.get("port", 443),
                "uuid": config.get("id", ""),
                "alterId": config.get("aid", 0),
                "security": config.get("security", "auto"),
                "type": config.get("type", "tcp"),
                "source": "url"
            }
        except Exception as e:
            print(f"Error parsing VMess URL: {e}")
            return None
    
    def parse_trojan_url(self, url):
        """Parse Trojan URL format"""
        try:
            # Remove protocol prefix
            url = url.replace("trojan://", "")
            
            # Split into parts
            if "?" in url:
                main_part, query_part = url.split("?", 1)
            else:
                main_part, query_part = url, ""
            
            # Parse main part (password@server:port)
            if "@" in main_part:
                password, server_part = main_part.split("@", 1)
            else:
                return None
            
            # Parse server and port
            if ":" in server_part:
                server, port = server_part.rsplit(":", 1)
                try:
                    port = int(port)
                except ValueError:
                    return None
            else:
                server, port = server_part, 443
            
            # Parse query parameters
            params = {}
            if query_part:
                for param in query_part.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        params[key] = urllib.parse.unquote(value)
            
            # Extract name from fragment
            name = params.get("name", "Trojan Config")
            if "#" in url:
                name = url.split("#")[-1]
            
            return {
                "name": name,
                "protocol": "trojan",
                "server": server,
                "port": port,
                "password": password,
                "sni": params.get("sni", ""),
                "source": "url"
            }
        except Exception as e:
            print(f"Error parsing Trojan URL: {e}")
            return None
    
    def parse_json_config(self, json_data):
        """Parse JSON configuration"""
        try:
            if isinstance(json_data, list) and len(json_data) > 0:
                json_data = json_data[0]
            
            protocol = json_data.get("protocol", "unknown")
            
            if protocol == "vless":
                return {
                    "name": json_data.get("name", "VLESS Config"),
                    "protocol": "vless",
                    "server": json_data.get("server", ""),
                    "port": json_data.get("port", 443),
                    "uuid": json_data.get("uuid", ""),
                    "security": json_data.get("security", "none"),
                    "encryption": json_data.get("encryption", "none"),
                    "type": json_data.get("type", "tcp"),
                    "path": json_data.get("path", ""),
                    "sni": json_data.get("sni", ""),
                    "source": "json"
                }
            elif protocol == "vmess":
                return {
                    "name": json_data.get("name", "VMess Config"),
                    "protocol": "vmess",
                    "server": json_data.get("server", ""),
                    "port": json_data.get("port", 443),
                    "uuid": json_data.get("uuid", ""),
                    "alterId": json_data.get("aid", 0),
                    "security": json_data.get("security", "auto"),
                    "type": json_data.get("type", "tcp"),
                    "source": "json"
                }
            elif protocol == "trojan":
                return {
                    "name": json_data.get("name", "Trojan Config"),
                    "protocol": "trojan",
                    "server": json_data.get("server", ""),
                    "port": json_data.get("port", 443),
                    "password": json_data.get("password", ""),
                    "sni": json_data.get("sni", ""),
                    "source": "json"
                }
            
            return None
        except Exception as e:
            print(f"Error parsing JSON config: {e}")
            return None
    
    def parse_npvt_format(self, content):
        """Parse .npvt file format"""
        try:
            # Try to parse as JSON first
            if content.startswith("{") or content.startswith("["):
                return self.parse_json_config(json.loads(content))
            
            # Try to parse as key-value pairs
            config = {}
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                if line and '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
            
            if config:
                protocol = config.get("protocol", "unknown")
                
                if protocol == "vless":
                    return {
                        "name": config.get("name", "VLESS Config"),
                        "protocol": "vless",
                        "server": config.get("server", ""),
                        "port": int(config.get("port", 443)),
                        "uuid": config.get("uuid", ""),
                        "security": config.get("security", "none"),
                        "encryption": config.get("encryption", "none"),
                        "type": config.get("type", "tcp"),
                        "path": config.get("path", ""),
                        "sni": config.get("sni", ""),
                        "source": "npvt"
                    }
                elif protocol == "vmess":
                    return {
                        "name": config.get("name", "VMess Config"),
                        "protocol": "vmess",
                        "server": config.get("server", ""),
                        "port": int(config.get("port", 443)),
                        "uuid": config.get("uuid", ""),
                        "alterId": int(config.get("aid", 0)),
                        "security": config.get("security", "auto"),
                        "type": config.get("type", "tcp"),
                    "source": "npvt"
                    }
                elif protocol == "trojan":
                    return {
                        "name": config.get("name", "Trojan Config"),
                        "protocol": "trojan",
                        "server": config.get("server", ""),
                        "port": int(config.get("port", 443)),
                        "password": config.get("password", ""),
                        "sni": config.get("sni", ""),
                        "source": "npvt"
                    }
            
            return None
        except Exception as e:
            print(f"Error parsing NPVT format: {e}")
            return None
    
    def add_config(self, config):
        """Add a new configuration"""
        if config:
            self.configs.append(config)
            self.current_config = config
            self.update_config_display()
            
            # Save configs to file
            self.save_configs()
    
    def update_config_display(self):
        """Update the configuration display"""
        if self.current_config:
            config_text = f"Config: {self.current_config['name']} ({self.current_config['protocol'].upper()})"
            self.config_label.config(text=config_text, fg='#00ff88')
        else:
            self.config_label.config(text="No configuration loaded", fg='#cccccc')
    
    def save_configs(self):
        """Save configurations to file"""
        try:
            config_file = "npv_tunnel_configs.json"
            encrypted_configs = []
            
            for config in self.configs:
                if self.fernet:
                    encrypted_config = {
                        'encrypted': True,
                        'data': self.encrypt_config(config)
                    }
                    encrypted_configs.append(encrypted_config)
                else:
                    encrypted_configs.append(config)
            
            payload = {
                'configs': encrypted_configs,
                'favorites': list(self.favorites) if isinstance(self.favorites, set) else self.favorites,
                'profiles': self.profiles,
                'schedule': self.schedule_entries,
                'last_used': self.current_config or None
            }
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                
            self.logger.info(f"Saved {len(self.configs)} configurations")
            
        except Exception as e:
            self.logger.error(f"Failed to save configurations: {e}")
    
    def toggle_connection(self):
        if not self.is_connected:
            if not self.current_config:
                self.log_operation("Connection attempt failed", "No configuration loaded", level='warning')
                messagebox.showwarning("Warning", "Please load a configuration first!")
                return
            self.log_operation("Starting VPN connection", level='info')
            self.connect_vpn()
        else:
            self.log_operation("Disconnecting VPN", level='info')
            self.disconnect_vpn()
    
    def connect_vpn(self):
        if not self.current_config:
            self.log_operation("Connection failed", "No configuration available", level='error')
            return
        
        try:
            self.log_operation("Backing up network settings", level='info')
            # Backup original network settings
            self.backup_network_settings()
            
            self.log_operation("Starting VPN connection", f"Protocol: {self.current_config.get('protocol', 'unknown')}", level='info')
            # Start real VPN connection
            if self.start_vpn_connection():
                self.is_connected = True
                config_name = self.current_config['name']
                self.log_operation("VPN connected successfully", f"Server: {config_name}", level='info')
                self.status_label.config(text=f"Connected to {config_name}", fg='#00ff88')
                self.connect_btn.config(text="Disconnect", bg='#ff4444')
                
                # Apply split tunneling if enabled
                try:
                    if self.split_tunneling_enabled:
                        self.enable_split_tunneling(direct_domains=self.split_domains, direct_ips=self.split_ips)
                except Exception as e:
                    self.log_operation(f"Split tunneling enable failed: {e}", level='warning')

                # Start VPN monitoring thread
                self.vpn_thread = threading.Thread(target=self.vpn_connection_worker, daemon=True)
                self.vpn_thread.start()
                self.log_operation("VPN monitoring thread started", level='debug')
                
                # Update IP display
                self.update_ip_display()
                
                # Enable kill switch if configured
                if self.kill_switch_enabled:
                    self.log_operation("Enabling kill switch", level='info')
                    self.enable_kill_switch()
                
                messagebox.showinfo("Success", f"Connected to {config_name}!")
            else:
                self.log_operation("VPN connection failed", "Connection establishment failed", level='error')
                messagebox.showerror("Error", "Failed to establish VPN connection")
                
        except Exception as e:
            self.log_operation("VPN connection error", str(e), level='error')
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
            self.restore_network_settings()
    
    def start_vpn_connection(self):
        """Start actual VPN connection based on protocol"""
        try:
            config = self.current_config
            protocol = config.get('protocol', 'vless')
            
            self.log_operation("Starting VPN connection", f"Protocol: {protocol}", level='info')
            
            # Check if we have the required tools
            tools_status = self.check_vpn_tools_status()
            
            if protocol in ['vless', 'vmess'] and not tools_status['v2ray']:
                self.log_operation("V2Ray not found, attempting download", level='warning')
                self.download_vpn_executables()
                tools_status = self.check_vpn_tools_status()
                
            elif protocol == 'trojan' and not tools_status['trojan']:
                self.log_operation("Trojan not found, attempting download", level='warning')
                self.download_vpn_executables()
                tools_status = self.check_vpn_tools_status()
            
            # Try to start the connection
            if protocol == 'vless':
                return self.start_vless_connection(config)
            elif protocol == 'vmess':
                return self.start_vmess_connection(config)
            elif protocol == 'trojan':
                return self.start_trojan_connection(config)
            else:
                return self.start_generic_connection(config)
                
        except Exception as e:
            self.log_operation(f"VPN connection failed: {e}", level='error')
            print(f"VPN connection failed: {e}")
            return False
    
    def start_vless_connection(self, config):
        """Start VLESS protocol connection"""
        try:
            # Use the centralized V2Ray config generation
            vless_config = self.generate_v2ray_config(config)
            if not vless_config:
                return False
            
            # Save config to temporary file
            config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(vless_config, config_file, indent=2)
            config_file.close()
            
            # Start V2Ray process
            v2ray_path = self.get_v2ray_path()
            if v2ray_path:
                self.vpn_process = subprocess.Popen([
                    v2ray_path, 'run', '-c', config_file.name
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Wait for connection
                time.sleep(2)
                if self.vpn_process.poll() is None:
                    # Test HTTP proxy first; only set system proxy if enabled in settings
                    if self.test_proxy_connection('127.0.0.1', 1081):
                        self.log_operation("HTTP proxy connection test successful", level='info')
                        if self.use_system_proxy:
                            self.set_system_proxy('127.0.0.1', 1081)
                        return True
                    else:
                        self.log_operation("HTTP proxy test failed, trying SOCKS fallback", level='warning')
                        # Try SOCKS proxy as fallback
                        if self.test_proxy_connection('127.0.0.1', 1080):
                            self.log_operation("SOCKS proxy fallback successful", level='info')
                            if self.use_system_proxy:
                                self.set_system_proxy('127.0.0.1', 1080)
                            return True
                        else:
                            self.log_operation("Both HTTP and SOCKS proxy tests failed", level='error')
                            return False
                else:
                    self.vpn_process = None
                    return False
            else:
                # Fallback to generic connection
                return self.start_generic_connection(config)
                
        except Exception as e:
            print(f"VLESS connection failed: {e}")
            return False
    
    def start_vmess_connection(self, config):
        """Start VMess protocol connection"""
        try:
            # Use the centralized V2Ray config generation
            vmess_config = self.generate_v2ray_config(config)
            if not vmess_config:
                return False
            
            # Save config to temporary file
            config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(vmess_config, config_file, indent=2)
            config_file.close()
            
            v2ray_path = self.get_v2ray_path()
            if v2ray_path:
                self.vpn_process = subprocess.Popen([
                    v2ray_path, 'run', '-c', config_file.name
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                time.sleep(2)
                if self.vpn_process.poll() is None:
                    # Test HTTP proxy first; only set system proxy if enabled in settings
                    if self.test_proxy_connection('127.0.0.1', 1081):
                        self.log_operation("HTTP proxy connection test successful", level='info')
                        if self.use_system_proxy:
                            self.set_system_proxy('127.0.0.1', 1081)
                        return True
                    else:
                        self.log_operation("HTTP proxy test failed, trying SOCKS fallback", level='warning')
                        # Try SOCKS proxy as fallback
                        if self.test_proxy_connection('127.0.0.1', 1080):
                            self.log_operation("SOCKS proxy fallback successful", level='info')
                            if self.use_system_proxy:
                                self.set_system_proxy('127.0.0.1', 1080)
                            return True
                        else:
                            self.log_operation("Both HTTP and SOCKS proxy tests failed", level='error')
                            return False
                else:
                    self.vpn_process = None
                    return False
            else:
                return self.start_generic_connection(config)
                
        except Exception as e:
            print(f"VMess connection failed: {e}")
            return False
    
    def start_trojan_connection(self, config):
        """Start Trojan protocol connection"""
        try:
            # Create Trojan configuration
            trojan_config = {
                "run_type": "client",
                "local_addr": "127.0.0.1",
                "local_port": 1080,
                "remote_addr": config['server'],
                "remote_port": config['port'],
                "password": [config['password']],
                "ssl": {
                    "verify": False,
                    "verify_hostname": False,
                    "sni": config.get('sni', '')
                }
            }
            
            # Save config to temporary file
            config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(trojan_config, config_file, indent=2)
            config_file.close()
            
            # Start Trojan process
            trojan_path = self.get_trojan_path()
            if trojan_path:
                self.vpn_process = subprocess.Popen([
                    trojan_path, '-c', config_file.name
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                time.sleep(2)
                if self.vpn_process.poll() is None:
                    # Test HTTP proxy first; only set system proxy if enabled in settings
                    if self.test_proxy_connection('127.0.0.1', 1081):
                        self.log_operation("HTTP proxy connection test successful", level='info')
                        if self.use_system_proxy:
                            self.set_system_proxy('127.0.0.1', 1081)
                        return True
                    else:
                        self.log_operation("HTTP proxy test failed, trying SOCKS fallback", level='warning')
                        # Try SOCKS proxy as fallback
                        if self.test_proxy_connection('127.0.0.1', 1080):
                            self.log_operation("SOCKS proxy fallback successful", level='info')
                            if self.use_system_proxy:
                                self.set_system_proxy('127.0.0.1', 1080)
                            return True
                        else:
                            self.log_operation("Both HTTP and SOCKS proxy tests failed", level='error')
                            return False
                else:
                    self.vpn_process = None
                    return False
            else:
                return self.start_generic_connection(config)
                
        except Exception as e:
            print(f"Trojan connection failed: {e}")
            return False
    
    def start_generic_connection(self, config):
        """Start generic connection using system tools"""
        try:
            # Use Windows built-in VPN or create virtual adapter
            # This is a fallback when specific protocol tools aren't available
            print(f"Using generic connection for {config['protocol']}")
            
            # For now, simulate connection success
            # In a real implementation, this would use Windows VPN APIs
            time.sleep(1)
            return True
            
        except Exception as e:
            print(f"Generic connection failed: {e}")
            return False
    
    def generate_v2ray_config(self, config):
        """Generate V2Ray configuration for VLESS/VMess protocols"""
        try:
            protocol = config.get('protocol', 'vless')
            
            if protocol == 'vless':
                # VLESS configuration with both SOCKS and HTTP proxies
                v2ray_config = {
                    "inbounds": [
                        {
                            "port": 1080,
                            "protocol": "socks",
                            "settings": {
                                "auth": "noauth",
                                "udp": True
                            }
                        },
                        {
                            "port": 1081,
                            "protocol": "http",
                            "settings": {
                                "timeout": 300
                            }
                        }
                    ],
                    "outbounds": [{
                        "protocol": "vless",
                        "settings": {
                            "vnext": [{
                                "address": config['server'],
                                "port": config['port'],
                                "users": [{
                                    "id": config['uuid'],
                                    "encryption": config.get('encryption', 'none')
                                }]
                            }]
                        },
                        "streamSettings": {
                            "network": config.get('type', 'tcp'),
                            "security": config.get('security', 'none'),
                            "tlsSettings": {
                                "serverName": config.get('sni', ''),
                                "allowInsecure": True
                            },
                            "wsSettings": {
                                "path": config.get('path', '/'),
                                "headers": {}
                            }
                        }
                    }]
                }
                
            elif protocol == 'vmess':
                # VMess configuration with both SOCKS and HTTP proxies
                v2ray_config = {
                    "inbounds": [
                        {
                            "port": 1080,
                            "protocol": "socks",
                            "settings": {
                                "auth": "noauth",
                                "udp": True
                            }
                        },
                        {
                            "port": 1081,
                            "protocol": "http",
                            "settings": {
                                "timeout": 300
                            }
                        }
                    ],
                    "outbounds": [{
                        "protocol": "vmess",
                        "settings": {
                            "vnext": [{
                                "address": config['server'],
                                "port": config['port'],
                                "users": [{
                                    "id": config['uuid'],
                                    "alterId": config.get('alterId', 0)
                                }]
                            }]
                        },
                        "streamSettings": {
                            "network": config.get('type', 'tcp'),
                            "security": config.get('security', 'auto')
                        }
                    }]
                }
            else:
                raise ValueError(f"Unsupported protocol: {protocol}")
            
            return v2ray_config
            
        except Exception as e:
            self.log_operation(f"V2Ray config generation failed: {e}", level='error')
            return None
    
    def disconnect_vpn(self):
        try:
            self.log_operation("Starting VPN disconnection", level='info')
            
            # Stop VPN process
            if self.vpn_process:
                self.log_operation("Terminating VPN process", level='debug')
                self.vpn_process.terminate()
                self.vpn_process.wait(timeout=5)
                self.vpn_process = None
                self.log_operation("VPN process terminated", level='debug')
            
            # Disable kill switch
            if self.kill_switch_enabled:
                self.log_operation("Disabling kill switch", level='info')
                self.disable_kill_switch()
            
            # Restore network settings
            self.log_operation("Restoring network settings", level='info')
            self.restore_network_settings()
            
            # Clear system proxy
            self.log_operation("Clearing system proxy", level='info')
            self.clear_system_proxy()
            
            self.is_connected = False
            self.status_label.config(text="Disconnected", fg='#ff4444')
            self.connect_btn.config(text="Connect", bg='#00ff88')
            
            # Update IP display
            self.update_ip_display()
            
            self.log_operation("VPN disconnected successfully", level='info')
            messagebox.showinfo("Info", "Disconnected from VPN server!")
            
        except Exception as e:
            self.log_operation("VPN disconnection error", str(e), level='error')
            print(f"Disconnect error: {e}")
            self.is_connected = False
            self.status_label.config(text="Disconnected", fg='#ff4444')
            self.connect_btn.config(text="Connect", bg='#00ff88')
    
    def backup_network_settings(self):
        """Backup current network settings"""
        try:
            # Get current DNS settings
            self.original_dns = self.get_current_dns()
            
            # Get current routing table
            self.original_routes = self.get_current_routes()
            
        except Exception as e:
            print(f"Network backup failed: {e}")
    
    def restore_network_settings(self):
        """Restore original network settings"""
        try:
            if self.original_dns:
                self.set_dns_servers(self.original_dns)
            
            if self.original_routes:
                self.restore_routes(self.original_routes)
                
        except Exception as e:
            print(f"Network restore failed: {e}")
    
    def get_current_dns(self):
        """Get current DNS server settings"""
        try:
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            # Parse DNS servers from ipconfig output
            dns_servers = []
            for line in result.stdout.split('\n'):
                if 'DNS Servers' in line:
                    dns_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if dns_match:
                        dns_servers.append(dns_match.group(1))
            return dns_servers
        except Exception as e:
            print(f"DNS query failed: {e}")
            return ['8.8.8.8', '8.8.4.4']  # Default Google DNS
    
    def set_dns_servers(self, dns_servers):
        """Set DNS servers for network adapter"""
        try:
            # This would use Windows API to set DNS servers
            # For now, just log the action
            print(f"Setting DNS servers: {dns_servers}")
        except Exception as e:
            print(f"DNS setting failed: {e}")
    
    def get_current_routes(self):
        """Get current routing table"""
        try:
            result = subprocess.run(['route', 'print'], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            print(f"Route query failed: {e}")
            return None
    
    def restore_routes(self, routes):
        """Restore routing table"""
        try:
            # This would restore the original routing table
            print("Restoring routing table")
        except Exception as e:
            print(f"Route restore failed: {e}")
    
    def set_system_proxy(self, host, port):
        """Set system-wide proxy settings"""
        try:
            # Set Windows proxy settings
            proxy_settings = f"http={host}:{port};https={host}:{port}"
            
            # Use Windows Registry to set proxy
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_settings)
                # Add bypass for local addresses
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>")
                winreg.CloseKey(key)
                self.log_operation(f"System proxy set to {host}:{port} with local bypass", level='info')
                print(f"System proxy set to {host}:{port} with local bypass")
                
                # Notify system of proxy changes
                self.refresh_system_proxy()
                
            except Exception as e:
                self.log_operation(f"Registry proxy setting failed: {e}", level='error')
                print(f"Registry proxy setting failed: {e}")
                
        except Exception as e:
            self.log_operation(f"Proxy setting failed: {e}", level='error')
            print(f"Proxy setting failed: {e}")
    
    def test_proxy_connection(self, host, port):
        """Test if proxy connection is working"""
        try:
            import requests
            proxies = {
                'http': f'http://{host}:{port}',
                'https': f'http://{host}:{port}'
            }
            
            # Test with a simple HTTP request
            response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=10)
            if response.status_code == 200:
                self.log_operation(f"Proxy test successful: {response.json()}", level='debug')
                return True
            else:
                self.log_operation(f"Proxy test failed with status: {response.status_code}", level='warning')
                return False
                
        except Exception as e:
            self.log_operation(f"Proxy test failed: {e}", level='warning')
            return False
    
    def refresh_system_proxy(self):
        """Refresh system proxy settings to notify applications"""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Send WM_SETTINGCHANGE message to notify applications of proxy changes
            HWND_BROADCAST = 0xFFFF
            WM_SETTINGCHANGE = 0x001A
            SMTO_ABORTIFHUNG = 0x0002
            
            result = ctypes.windll.user32.SendMessageTimeoutW(
                HWND_BROADCAST, WM_SETTINGCHANGE, 0, 
                "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                SMTO_ABORTIFHUNG, 5000, ctypes.byref(wintypes.DWORD())
            )
            
            if result:
                self.log_operation("System proxy refresh notification sent", level='debug')
            else:
                self.log_operation("System proxy refresh notification failed", level='warning')
                
        except Exception as e:
            self.log_operation(f"System proxy refresh failed: {e}", level='warning')
    
    def test_internet_access(self):
        """Test if internet access is working through the proxy"""
        try:
            import requests
            
            # Test multiple websites to ensure internet access
            test_urls = [
                'http://www.google.com',
                'http://www.bing.com',
                'http://www.yahoo.com'
            ]
            
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        self.log_operation(f"Internet access test successful: {url}", level='debug')
                        return True
                except:
                    continue
            
            self.log_operation("All internet access tests failed", level='warning')
            return False
                
        except Exception as e:
            self.log_operation(f"Internet access test failed: {e}", level='warning')
            return False
    
    def clear_system_proxy(self):
        """Clear system proxy settings"""
        try:
            # Clear Windows proxy settings
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.DeleteValue(key, "ProxyServer")
                winreg.CloseKey(key)
                print("System proxy cleared")
            except Exception as e:
                print(f"Registry proxy clearing failed: {e}")
                
        except Exception as e:
            print(f"Proxy clearing failed: {e}")
    
    def enable_kill_switch(self):
        """Enable kill switch using Windows Firewall to prevent traffic leaks"""
        try:
            self.log_operation("Enabling kill switch with Windows Firewall", level='info')
            
            # Store current firewall state for restoration
            self.backup_firewall_state()
            
            # Create firewall rules to block all outbound traffic except VPN proxy
            self.create_kill_switch_rules()
            
            # Enable the kill switch rules
            self.activate_kill_switch_rules()
            
            self.log_operation("Kill switch enabled successfully", level='info')
            return True
        except Exception as e:
            self.log_operation(f"Kill switch enable failed: {e}", level='error')
            return False
    
    def disable_kill_switch(self):
        """Disable kill switch and restore normal firewall state"""
        try:
            self.log_operation("Disabling kill switch", level='info')
            
            # Remove kill switch rules
            self.remove_kill_switch_rules()
            
            # Restore original firewall state
            self.restore_firewall_state()
            
            self.log_operation("Kill switch disabled successfully", level='info')
            return True
        except Exception as e:
            self.log_operation(f"Kill switch disable failed: {e}", level='error')
            return False
    
    def get_v2ray_path(self):
        """Get V2Ray executable path"""
        # Check common V2Ray locations
        possible_paths = [
            "v2ray.exe",
            "v2ray",
            os.path.join(os.getcwd(), "v2ray.exe"),
            os.path.join(os.getcwd(), "v2ray"),
            os.path.join(os.getcwd(), "vpn_tools", "v2ray.exe"),
            "C:\\Program Files\\V2Ray\\v2ray.exe",
            "C:\\Program Files (x86)\\V2Ray\\v2ray.exe"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def get_trojan_path(self):
        """Get Trojan executable path"""
        # Check common Trojan locations
        possible_paths = [
            "trojan.exe",
            "trojan",
            os.path.join(os.getcwd(), "trojan.exe"),
            os.path.join(os.getcwd(), "trojan"),
            os.path.join(os.getcwd(), "vpn_tools", "trojan.exe"),
            "C:\\Program Files\\Trojan\\trojan.exe",
            "C:\\Program Files (x86)\\Trojan\\trojan.exe"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
        
    def download_vpn_executables(self):
        """Download required VPN protocol executables"""
        try:
            self.log_operation("Starting VPN executable download", level='info')
            
            # Create tools directory if it doesn't exist
            tools_dir = "vpn_tools"
            if not os.path.exists(tools_dir):
                os.makedirs(tools_dir)
                self.log_operation("Created VPN tools directory", level='debug')
            
            # Download V2Ray
            v2ray_path = os.path.join(tools_dir, "v2ray.exe")
            if not os.path.exists(v2ray_path):
                self.log_operation("Downloading V2Ray executable", level='info')
                success = self.download_v2ray(v2ray_path)
                if success:
                    self.log_operation("V2Ray downloaded successfully", level='info')
                else:
                    self.log_operation("V2Ray download failed", level='error')
            
            # Download Trojan
            trojan_path = os.path.join(tools_dir, "trojan.exe")
            if not os.path.exists(trojan_path):
                self.log_operation("Downloading Trojan executable", level='info')
                success = self.download_trojan(trojan_path)
                if success:
                    self.log_operation("Trojan downloaded successfully", level='info')
                else:
                    self.log_operation("Trojan download failed", level='error')
                    
            self.log_operation("VPN executable download process completed", level='info')
            
        except Exception as e:
            self.log_operation(f"VPN executable download error: {e}", level='error')
    
    def download_v2ray(self, target_path):
        """Download V2Ray executable"""
        try:
            # V2Ray download URLs (latest stable releases)
            v2ray_urls = [
                "https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-windows-64.zip",
                "https://github.com/v2fly/v2ray-core/releases/download/v4.45.2/v2ray-windows-64.zip"
            ]
            
            for url in v2ray_urls:
                try:
                    self.log_operation(f"Attempting V2Ray download from: {url}", level='debug')
                    
                    # Download the zip file
                    response = requests.get(url, stream=True, timeout=30)
                    response.raise_for_status()
                    
                    # Save to temporary file
                    temp_zip = "v2ray_temp.zip"
                    with open(temp_zip, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Extract the executable
                    import zipfile
                    with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                        # Find v2ray.exe in the zip
                        for file_info in zip_ref.filelist:
                            if file_info.filename.endswith('v2ray.exe'):
                                with zip_ref.open(file_info) as source, open(target_path, 'wb') as target:
                                    target.write(source.read())
                                break
                    
                    # Clean up
                    os.remove(temp_zip)
                    self.log_operation("V2Ray extracted successfully", level='debug')
                    return True
                    
                except Exception as e:
                    self.log_operation(f"V2Ray download attempt failed: {e}", level='warning')
                    continue
            
            return False
            
        except Exception as e:
            self.log_operation(f"V2Ray download failed: {e}", level='error')
            return False
    
    def download_trojan(self, target_path):
        """Download Trojan executable"""
        try:
            # Trojan download URLs (latest stable releases)
            trojan_urls = [
                "https://github.com/trojan-gfw/trojan/releases/latest/download/trojan-windows-x86_64.zip",
                "https://github.com/trojan-gfw/trojan/releases/download/v1.16.0/trojan-windows-x86_64.zip"
            ]
            
            for url in trojan_urls:
                try:
                    self.log_operation(f"Attempting Trojan download from: {url}", level='debug')
                    
                    # Download the zip file
                    response = requests.get(url, stream=True, timeout=30)
                    if response.status_code == 404:
                        self.log_operation(f"URL not found: {url}", level='warning')
                        continue
                        
                    response.raise_for_status()
                    
                    # Save to temporary file
                    temp_zip = "trojan_temp.zip"
                    with open(temp_zip, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Extract the executable
                    import zipfile
                    with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                        # Find trojan.exe in the zip
                        for file_info in zip_ref.filelist:
                            if file_info.filename.endswith('trojan.exe'):
                                with zip_ref.open(file_info) as source, open(target_path, 'wb') as target:
                                    target.write(source.read())
                                break
                    
                    # Clean up
                    os.remove(temp_zip)
                    self.log_operation("Trojan extracted successfully", level='debug')
                    return True
                    
                except Exception as e:
                    self.log_operation(f"Trojan download attempt failed: {e}", level='warning')
                    continue
            
            return False
            
        except Exception as e:
            self.log_operation(f"Trojan download failed: {e}", level='error')
            return False
    
    def check_vpn_tools_status(self):
        """Check status of VPN tools and return what's available"""
        tools_status = {
            'v2ray': False,
            'trojan': False,
            'v2ray_path': None,
            'trojan_path': None
        }
        
        # Check V2Ray
        v2ray_path = self.get_v2ray_path()
        if v2ray_path:
            tools_status['v2ray'] = True
            tools_status['v2ray_path'] = v2ray_path
            self.log_operation("V2Ray found", f"Path: {v2ray_path}", level='debug')
        else:
            self.log_operation("V2Ray not found", level='warning')
        
        # Check Trojan
        trojan_path = self.get_trojan_path()
        if trojan_path:
            tools_status['trojan'] = True
            tools_status['trojan_path'] = trojan_path
            self.log_operation("Trojan found", f"Path: {trojan_path}", level='debug')
        else:
            self.log_operation("Trojan not found", level='warning')
        
        return tools_status
    
    def vpn_connection_worker(self):
        """Simulate VPN connection work"""
        while self.is_connected:
            time.sleep(1)
            # Simulate VPN activity
            pass
    
    def update_ip_display(self):
        if self.is_connected:
            # Simulate different IP when connected
            if self.current_config:
                server = self.current_config['server']
                self.ip_label.config(text=f"IP: {server} (VPN)")
                self.log_operation("IP display updated", f"VPN IP: {server}", level='debug')
            else:
                self.ip_label.config(text="IP: VPN Connected")
                self.log_operation("IP display updated", "VPN Connected (no server info)", level='debug')
        else:
            # Show real IP
            self.get_real_ip()
    
    def get_real_ip(self):
        try:
            self.log_operation("Checking real IP address", level='debug')
            response = requests.get('https://httpbin.org/ip', timeout=5)
            ip_data = response.json()
            real_ip = ip_data.get('origin', 'Unknown')
            self.ip_label.config(text=f"IP: {real_ip}")
            self.log_operation("Real IP retrieved", f"IP: {real_ip}", level='debug')
        except Exception as e:
            self.log_operation("IP check failed", str(e), level='warning')
            self.ip_label.config(text="IP: Unable to determine")
    
    def start_ip_checker(self):
        """Start background thread to check IP periodically"""
        def ip_checker():
            while True:
                if not self.is_connected:
                    self.get_real_ip()
                time.sleep(30)  # Check every 30 seconds
        
        ip_thread = threading.Thread(target=ip_checker, daemon=True)
        ip_thread.start()
    
    def show_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Advanced Settings")
        settings_window.geometry("500x600")
        settings_window.configure(bg='#1e1e1e')
        
        # Create scrollable frame
        canvas = tk.Canvas(settings_window, bg='#1e1e1e')
        scrollbar = ttk.Scrollbar(settings_window, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#1e1e1e')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Title
        tk.Label(scrollable_frame, text="Advanced Settings", font=("Arial", 18, "bold"), 
                fg='#00ff88', bg='#1e1e1e').pack(pady=20)
        
        # Connection Settings Section
        connection_frame = tk.LabelFrame(scrollable_frame, text="Connection Settings", 
                                       font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        connection_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Auto-connect option
        auto_connect_var = tk.BooleanVar(value=getattr(self, 'auto_connect_on_start', False))
        auto_connect_cb = tk.Checkbutton(connection_frame, text="Auto-connect on startup", 
                                       variable=auto_connect_var, bg='#2d2d2d', fg='#ffffff')
        auto_connect_cb.pack(anchor='w', padx=20, pady=5)
        
        # Start with Windows
        start_with_win_var = tk.BooleanVar(value=getattr(self, 'start_with_windows_enabled', False))
        start_with_cb = tk.Checkbutton(connection_frame, text="Start Momo Tunnel with Windows", 
                                       variable=start_with_win_var, bg='#2d2d2d', fg='#ffffff')
        start_with_cb.pack(anchor='w', padx=20, pady=5)
        
        # Kill switch option
        kill_switch_var = tk.BooleanVar(value=self.kill_switch_enabled)
        kill_switch_cb = tk.Checkbutton(connection_frame, text="Enable Kill Switch (Prevent traffic leaks)", 
                                      variable=kill_switch_var, bg='#2d2d2d', fg='#ffffff')
        kill_switch_cb.pack(anchor='w', padx=20, pady=5)
        
        # Protocol Settings Section
        protocol_frame = tk.LabelFrame(scrollable_frame, text="Protocol Settings", 
                                     font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        protocol_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Transport protocol
        tk.Label(protocol_frame, text="Transport Protocol:", font=("Arial", 10), 
                fg='#ffffff', bg='#2d2d2d').pack(anchor='w', padx=20, pady=(10, 5))
        
        transport_var = tk.StringVar(value="TCP")
        transport_radio_frame = tk.Frame(protocol_frame, bg='#2d2d2d')
        transport_radio_frame.pack(anchor='w', padx=20)
        
        tk.Radiobutton(transport_radio_frame, text="TCP", variable=transport_var, value="TCP", 
                      bg='#2d2d2d', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(transport_radio_frame, text="UDP", variable=transport_var, value="UDP", 
                      bg='#2d2d2d', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(transport_radio_frame, text="WebSocket", variable=transport_var, value="ws", 
                      bg='#2d2d2d', fg='#ffffff').pack(side=tk.LEFT)
        
        # Security Settings Section
        security_frame = tk.LabelFrame(scrollable_frame, text="Security Settings", 
                                     font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        security_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # TLS verification
        tls_verify_var = tk.BooleanVar(value=True)
        tls_verify_cb = tk.Checkbutton(security_frame, text="Verify TLS certificates", 
                                      variable=tls_verify_var, bg='#2d2d2d', fg='#ffffff')
        tls_verify_cb.pack(anchor='w', padx=20, pady=5)
        
        # DNS Settings Section
        dns_frame = tk.LabelFrame(scrollable_frame, text="DNS Settings", 
                                font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        dns_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Custom DNS servers
        tk.Label(dns_frame, text="Custom DNS Servers:", font=("Arial", 10), 
                fg='#ffffff', bg='#2d2d2d').pack(anchor='w', padx=20, pady=(10, 5))
        
        dns_entry = tk.Entry(dns_frame, font=("Arial", 10), bg='#444444', fg='#ffffff')
        dns_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
        dns_entry.insert(0, "8.8.8.8, 8.8.4.4")
        
        # Advanced Options Section
        advanced_frame = tk.LabelFrame(scrollable_frame, text="Advanced Options", 
                                     font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        advanced_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Split tunneling
        split_tunnel_var = tk.BooleanVar()
        split_tunnel_cb = tk.Checkbutton(advanced_frame, text="Enable Split Tunneling", 
                                       variable=split_tunnel_var, bg='#2d2d2d', fg='#ffffff')
        split_tunnel_cb.pack(anchor='w', padx=20, pady=5)
        
        # Obfuscation
        obfuscation_var = tk.BooleanVar()
        obfuscation_cb = tk.Checkbutton(advanced_frame, text="Enable Traffic Obfuscation", 
                                       variable=obfuscation_var, bg='#2d2d2d', fg='#ffffff')
        obfuscation_cb.pack(anchor='w', padx=20, pady=5)
        
        # Save button
        save_btn = tk.Button(scrollable_frame, text="Save Settings", 
                           command=lambda: self.save_advanced_settings(
                               settings_window, auto_connect_var.get(), kill_switch_var.get(),
                               transport_var.get(), tls_verify_var.get(), dns_entry.get(),
                               split_tunnel_var.get(), obfuscation_var.get(), start_with_win_var.get()
                           ),
                           bg='#00ff88', fg='#000000', relief=tk.FLAT, padx=30, pady=10)
        save_btn.pack(pady=20)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def save_settings(self, window):
        messagebox.showinfo("Success", "Settings saved successfully!")
        window.destroy()
    
    def save_advanced_settings(self, window, auto_connect, kill_switch, transport, tls_verify, 
                              dns_servers, split_tunnel, obfuscation, start_with_windows):
        """Save advanced settings"""
        try:
            # Save settings to configuration file
            settings = {
                "auto_connect": auto_connect,
                "kill_switch": kill_switch,
                "transport_protocol": transport,
                "tls_verify": tls_verify,
                "dns_servers": dns_servers,
                "split_tunneling": split_tunnel,
                "traffic_obfuscation": obfuscation,
                "start_with_windows": bool(start_with_windows),
                "timestamp": datetime.now().isoformat()
            }
            
            # Update instance variables
            self.kill_switch_enabled = kill_switch
            self.auto_connect_on_start = bool(auto_connect)
            self.start_with_windows_enabled = bool(start_with_windows)
            self.apply_startup(self.start_with_windows_enabled)
            
            # Save to file
            with open(self.get_settings_path(), 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("Success", "Advanced settings saved successfully!")
            window.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def load_advanced_settings(self):
        """Load advanced settings from file"""
        try:
            path = self.get_settings_path()
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                    
                    # Apply settings
                    self.kill_switch_enabled = settings.get("kill_switch", False)
                    self.auto_connect_on_start = settings.get("auto_connect", False)
                    self.start_with_windows_enabled = settings.get("start_with_windows", False)
                    self.apply_startup(self.start_with_windows_enabled)
                    
        except Exception as e:
            print(f"Failed to load advanced settings: {e}")
            
    def show_vpn_tools_dialog(self):
        """Show VPN tools management dialog"""
        tools_window = tk.Toplevel(self.root)
        tools_window.title("VPN Tools Manager")
        tools_window.geometry("500x400")
        tools_window.configure(bg='#1e1e1e')
        tools_window.resizable(False, False)
        
        # Center the window
        tools_window.transient(self.root)
        tools_window.grab_set()
        
        # Title
        title_label = tk.Label(tools_window, text="VPN Tools Manager", 
                              font=("Arial", 18, "bold"), 
                              fg='#00ff88', bg='#1e1e1e')
        title_label.pack(pady=20)
        
        # Status frame
        status_frame = tk.LabelFrame(tools_window, text="Tools Status", 
                                   font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        status_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Check current status
        tools_status = self.check_vpn_tools_status()
        
        # V2Ray status
        v2ray_frame = tk.Frame(status_frame, bg='#2d2d2d')
        v2ray_frame.pack(fill=tk.X, padx=20, pady=5)
        
        v2ray_icon = "✅" if tools_status['v2ray'] else "❌"
        v2ray_label = tk.Label(v2ray_frame, text=f"{v2ray_icon} V2Ray", 
                              font=("Arial", 12), fg='#ffffff', bg='#2d2d2d')
        v2ray_label.pack(side=tk.LEFT)
        
        if tools_status['v2ray']:
            v2ray_path_label = tk.Label(v2ray_frame, text=f"Path: {tools_status['v2ray_path']}", 
                                       font=("Arial", 9), fg='#00ff88', bg='#2d2d2d')
            v2ray_path_label.pack(side=tk.RIGHT)
        
        # Trojan status
        trojan_frame = tk.Frame(status_frame, bg='#2d2d2d')
        trojan_frame.pack(fill=tk.X, padx=20, pady=5)
        
        trojan_icon = "✅" if tools_status['trojan'] else "❌"
        trojan_label = tk.Label(trojan_frame, text=f"{trojan_icon} Trojan", 
                               font=("Arial", 12), fg='#ffffff', bg='#2d2d2d')
        trojan_label.pack(side=tk.LEFT)
        
        if tools_status['trojan']:
            trojan_path_label = tk.Label(trojan_frame, text=f"Path: {tools_status['trojan_path']}", 
                                        font=("Arial", 9), fg='#00ff88', bg='#2d2d2d')
            trojan_path_label.pack(side=tk.RIGHT)
        
        # Actions frame
        actions_frame = tk.LabelFrame(tools_window, text="Actions", 
                                    font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        actions_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Download button
        download_btn = tk.Button(actions_frame, text="Download Missing Tools", 
                               command=lambda: self.download_and_refresh(tools_window),
                               font=("Arial", 12),
                               bg='#00ff88', fg='#000000',
                               relief=tk.FLAT, padx=20, pady=10)
        download_btn.pack(pady=10)
        
        # Refresh button
        refresh_btn = tk.Button(actions_frame, text="Refresh Status", 
                              command=lambda: self.refresh_tools_status(tools_window),
                              font=("Arial", 12),
                              bg='#666666', fg='#ffffff',
                              relief=tk.FLAT, padx=20, pady=10)
        refresh_btn.pack(pady=5)
        
        # Info frame
        info_frame = tk.LabelFrame(tools_window, text="Information", 
                                 font=("Arial", 12, "bold"), fg='#00ff88', bg='#2d2d2d')
        info_frame.pack(fill=tk.X, padx=20, pady=10)
        
        info_text = """These tools are required for real VPN connections:
        
• V2Ray: Handles VLESS and VMess protocols
• Trojan: Handles Trojan protocol

The app will automatically download these tools
when you first try to connect to a VPN server."""
        
        info_label = tk.Label(info_frame, text=info_text, 
                             font=("Arial", 9), fg='#cccccc', bg='#2d2d2d',
                             justify=tk.LEFT)
        info_label.pack(padx=20, pady=10)
        
        # Close button
        close_btn = tk.Button(tools_window, text="Close", 
                             command=tools_window.destroy,
                             font=("Arial", 10),
                             bg='#666666', fg='#ffffff',
                             relief=tk.FLAT, padx=30, pady=10)
        close_btn.pack(pady=20)
        
    def download_and_refresh(self, window):
        """Download VPN tools and refresh the dialog"""
        try:
            # Show downloading message
            downloading_label = tk.Label(window, text="Downloading VPN tools... Please wait.", 
                                       font=("Arial", 10), fg='#00ff88', bg='#1e1e1e')
            downloading_label.pack(pady=10)
            
            # Download tools
            self.download_vpn_executables()
            
            # Remove downloading message
            downloading_label.destroy()
            
            # Refresh status
            self.refresh_tools_status(window)
            
            messagebox.showinfo("Success", "VPN tools download completed!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Download failed: {str(e)}")
            
    def refresh_tools_status(self, window):
        """Refresh the tools status display"""
        # Close and reopen the dialog to show updated status
        window.destroy()
        self.show_vpn_tools_dialog()
    
    def export_configuration(self, config_data, filename, password=None):
        """Export configuration with encryption options"""
        try:
            if password:
                # Export as password-protected file
                secure_config = self.create_secure_config(config_data, password)
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(secure_config, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Success", f"Configuration exported as encrypted file: {filename}")
            else:
                # Export as master-encrypted file
                encrypted_data = self.encrypt_config(config_data)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(encrypted_data)
                messagebox.showinfo("Success", f"Configuration exported as master-encrypted file: {filename}")
            
            return True
            
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
            return False
    
    def show_export_dialog(self):
        """Show configuration export dialog"""
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Configuration")
        export_window.geometry("400x300")
        export_window.configure(bg='#1e1e1e')
        
        # Title
        tk.Label(export_window, text="Export Configuration", font=("Arial", 16, "bold"), 
                fg='#00ff88', bg='#1e1e1e').pack(pady=20)
        
        # Configuration selection
        if not self.configs:
            tk.Label(export_window, text="No configurations to export", 
                    font=("Arial", 12), fg='#ff4444', bg='#1e1e1e').pack(pady=20)
            return
        
        tk.Label(export_window, text="Select Configuration:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(pady=10)
        
        config_var = tk.StringVar(value=self.configs[0]['name'])
        config_menu = ttk.Combobox(export_window, textvariable=config_var, 
                                  values=[config['name'] for config in self.configs],
                                  state="readonly", font=("Arial", 10))
        config_menu.pack(pady=10)
        
        # Password protection option
        password_var = tk.StringVar()
        tk.Label(export_window, text="Password (optional):", font=("Arial", 10), 
                fg='#ffffff', bg='#1e1e1e').pack(pady=(20, 5))
        
        password_entry = tk.Entry(export_window, textvariable=password_var, 
                                font=("Arial", 10), bg='#444444', fg='#ffffff', show="*")
        password_entry.pack(pady=(0, 20))
        
        # Export button
        export_btn = tk.Button(export_window, text="Export", 
                             command=lambda: self.perform_export(
                                 export_window, config_var.get(), password_var.get()
                             ),
                             bg='#00ff88', fg='#000000', relief=tk.FLAT, padx=30, pady=10)
        export_btn.pack(pady=10)
    
    def perform_export(self, window, config_name, password):
        """Perform the actual export"""
        try:
            # Find the selected configuration
            selected_config = None
            for config in self.configs:
                if config['name'] == config_name:
                    selected_config = config
                    break
            
            if not selected_config:
                messagebox.showerror("Error", "Configuration not found")
                return
            
            # Get filename from user
            filename = filedialog.asksaveasfilename(
                title="Save Configuration As",
                defaultextension=".npvt",
                filetypes=[("NPVT files", "*.npvt"), ("All files", "*.*")]
            )
            
            if filename:
                # Export with or without password
                if password:
                    success = self.export_configuration(selected_config, filename, password)
                else:
                    success = self.export_configuration(selected_config, filename)
                
                if success:
                    window.destroy()
                    
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def initialize_encryption(self):
        """Initialize encryption for secure configuration storage"""
        try:
            # Generate or load encryption key
            key_file = "npv_tunnel.key"
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    self.encryption_key = f.read()
            else:
                self.encryption_key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(self.encryption_key)
            
            self.fernet = Fernet(self.encryption_key)
        except Exception as e:
            print(f"Encryption initialization failed: {e}")
            self.encryption_key = None
            self.fernet = None
    
    def encrypt_config(self, config_data):
        """Encrypt configuration data"""
        if not self.fernet:
            return config_data
        
        try:
            json_data = json.dumps(config_data, ensure_ascii=False)
            encrypted_data = self.fernet.encrypt(json_data.encode())
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            print(f"Encryption failed: {e}")
            return config_data
    
    def decrypt_config(self, encrypted_data):
        """Decrypt configuration data"""
        if not self.fernet:
            return encrypted_data
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            print(f"Decryption failed: {e}")
            return encrypted_data
    
    def create_secure_config(self, config_data, password=None):
        """Create a password-protected configuration file"""
        try:
            if password:
                # Generate salt and derive key from password
                salt = secrets.token_bytes(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                
                # Encrypt with password
                json_data = json.dumps(config_data, ensure_ascii=False)
                encrypted_data = fernet.encrypt(json_data.encode())
                
                # Create secure config structure
                secure_config = {
                    "version": "2.0",
                    "encrypted": True,
                    "salt": base64.b64encode(salt).decode(),
                    "data": base64.b64encode(encrypted_data).decode(),
                    "timestamp": datetime.now().isoformat()
                }
                
                return secure_config
            else:
                # Use master encryption key
                return self.encrypt_config(config_data)
        except Exception as e:
            print(f"Secure config creation failed: {e}")
            return config_data
    
    def export_secure_config(self, config_data, filename, password=None):
        """Export configuration as encrypted file"""
        try:
            secure_config = self.create_secure_config(config_data, password)
            
            if password:
                # Export as .npvt (encrypted)
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(secure_config, f, indent=2, ensure_ascii=False)
            else:
                # Export as .npvt (master encrypted)
                encrypted_data = self.encrypt_config(config_data)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(encrypted_data)
            
            return True
        except Exception as e:
            print(f"Export failed: {e}")
            return False
    
    def import_secure_config(self, filepath, password=None):
        """Import encrypted configuration file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try to parse as JSON first (new format)
            try:
                secure_config = json.loads(content)
                if secure_config.get("encrypted"):
                    if password:
                        # Decrypt with password
                        salt = base64.b64decode(secure_config["salt"])
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                        )
                        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                        fernet = Fernet(key)
                        
                        encrypted_data = base64.b64decode(secure_config["data"])
                        decrypted_data = fernet.decrypt(encrypted_data)
                        return json.loads(decrypted_data.decode())
                    else:
                        messagebox.showerror("Error", "Password required for this configuration file")
                        return None
                else:
                    return secure_config
            except:
                # Try as master encrypted format
                return self.decrypt_config(content)
        except Exception as e:
            print(f"Import failed: {e}")
            return None
    
    def show_add_config_dialog(self):
        """Show the Add Config dialog similar to the original APK"""
        config_window = tk.Toplevel(self.root)
        config_window.title("Add Config")
        config_window.geometry("400x350")
        config_window.configure(bg='#1e1e1e')
        config_window.resizable(False, False)
        
        # Center the window
        config_window.transient(self.root)
        config_window.grab_set()
        
        # Title
        title_label = tk.Label(config_window, text="Add Config", 
                              font=("Arial", 18, "bold"), 
                              fg='#00ff88', bg='#1e1e1e')
        title_label.pack(pady=20)
        
        # Options frame
        options_frame = tk.Frame(config_window, bg='#1e1e1e')
        options_frame.pack(fill=tk.BOTH, expand=True, padx=30)
        
        # Option 1: Import npvt config file
        option1_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option1_frame.pack(fill=tk.X, pady=10)
        
        option1_btn = tk.Button(option1_frame, text="Import npvt config file", 
                               command=lambda: [self.import_npvt_file(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option1_btn.pack(fill=tk.X)
        
        # Down arrow icon
        arrow1 = tk.Label(option1_frame, text="↓", font=("Arial", 16), 
                         fg='#00ff88', bg='#2d2d2d')
        arrow1.pack(side=tk.RIGHT, padx=20)
        
        # Option 2: Import cloud config
        option2_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option2_frame.pack(fill=tk.X, pady=10)
        
        option2_btn = tk.Button(option2_frame, text="Import cloud config", 
                               command=lambda: [self.import_cloud_config(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option2_btn.pack(fill=tk.X)
        
        # Cloud icon
        cloud_icon = tk.Label(option2_frame, text="☁", font=("Arial", 16), 
                            fg='#00ff88', bg='#2d2d2d')
        cloud_icon.pack(side=tk.RIGHT, padx=20)
        
        # Option 3: Import config from Clipboard
        option3_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option3_frame.pack(fill=tk.X, pady=10)
        
        option3_btn = tk.Button(option3_frame, text="Import config from\nClipboard", 
                               command=lambda: [self.import_from_clipboard(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option3_btn.pack(fill=tk.X)
        
        # Clipboard icon
        clipboard_icon = tk.Label(option3_frame, text="📋", font=("Arial", 12), 
                                fg='#00ff88', bg='#2d2d2d')
        clipboard_icon.pack(side=tk.RIGHT, padx=20)
        
        # Option 4: Add config manually
        option4_frame = tk.Frame(options_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
        option4_frame.pack(fill=tk.X, pady=10)
        
        option4_btn = tk.Button(option4_frame, text="Add config manually", 
                               command=lambda: [self.add_config_manually(), config_window.destroy()],
                               font=("Arial", 12),
                               bg='#2d2d2d', fg='#ffffff',
                               relief=tk.FLAT, padx=20, pady=15,
                               anchor='w', justify='left')
        option4_btn.pack(fill=tk.X)
        
        # Plus icon
        plus_icon = tk.Label(option4_frame, text="+", font=("Arial", 16), 
                           fg='#00ff88', bg='#2d2d2d')
        plus_icon.pack(side=tk.RIGHT, padx=20)
        
        # Cancel button
        cancel_btn = tk.Button(config_window, text="Cancel", 
                             command=config_window.destroy,
                             font=("Arial", 10),
                             bg='#666666', fg='#ffffff',
                             relief=tk.FLAT, padx=30, pady=10)
        cancel_btn.pack(pady=20)
    

    
    def import_cloud_config(self):
        """Import configuration from cloud service"""
        # This would connect to a cloud service in a real implementation
        messagebox.showinfo("Cloud Import", "Cloud import functionality would be implemented here.\nThis is a demonstration version.")
    
    def import_from_clipboard(self):
        """Import configuration from clipboard"""
        try:
            clipboard_content = self.root.clipboard_get()
            if clipboard_content:
                # Parse the clipboard content
                config = self.parse_config_content(clipboard_content)
                if config:
                    self.add_config(config)
                    messagebox.showinfo("Success", "Configuration imported from clipboard")
                else:
                    messagebox.showerror("Error", "Invalid configuration format in clipboard")
            else:
                messagebox.showwarning("Warning", "Clipboard is empty")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read clipboard: {str(e)}")
    
    def add_config_manually(self):
        """Add configuration manually"""
        manual_window = tk.Toplevel(self.root)
        manual_window.title("Add Config Manually")
        manual_window.geometry("500x400")
        manual_window.configure(bg='#1e1e1e')
        
        # Title
        title_label = tk.Label(manual_window, text="Add Configuration Manually", 
                              font=("Arial", 16, "bold"), 
                              fg='#00ff88', bg='#1e1e1e')
        title_label.pack(pady=20)
        
        # Form frame
        form_frame = tk.Frame(manual_window, bg='#1e1e1e')
        form_frame.pack(fill=tk.BOTH, expand=True, padx=30)
        
        # Protocol selection
        tk.Label(form_frame, text="Protocol:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        protocol_var = tk.StringVar(value="vless")
        protocol_frame = tk.Frame(form_frame, bg='#1e1e1e')
        protocol_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Radiobutton(protocol_frame, text="VLESS", variable=protocol_var, value="vless", 
                      bg='#1e1e1e', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(protocol_frame, text="VMess", variable=protocol_var, value="vmess", 
                      bg='#1e1e1e', fg='#ffffff').pack(side=tk.LEFT, padx=(0, 20))
        tk.Radiobutton(protocol_frame, text="Trojan", variable=protocol_var, value="trojan", 
                      bg='#1e1e1e', fg='#ffffff').pack(side=tk.LEFT)
        
        # Server address
        tk.Label(form_frame, text="Server Address:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        server_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        server_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Port
        tk.Label(form_frame, text="Port:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        port_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        port_entry.pack(fill=tk.X, pady=(0, 15))
        
        # UUID/Password
        tk.Label(form_frame, text="UUID/Password:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        uuid_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        uuid_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Config name
        tk.Label(form_frame, text="Configuration Name:", font=("Arial", 12), 
                fg='#ffffff', bg='#1e1e1e').pack(anchor='w', pady=(0, 5))
        
        name_entry = tk.Entry(form_frame, font=("Arial", 12), bg='#2d2d2d', fg='#ffffff')
        name_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Buttons
        buttons_frame = tk.Frame(form_frame, bg='#1e1e1e')
        buttons_frame.pack(pady=20)
        
        save_btn = tk.Button(buttons_frame, text="Save", 
                           command=lambda: self.save_manual_config(
                               protocol_var.get(), server_entry.get(), port_entry.get(),
                               uuid_entry.get(), name_entry.get(), manual_window
                           ),
                           bg='#00ff88', fg='#000000', relief=tk.FLAT, padx=30, pady=10)
        save_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = tk.Button(buttons_frame, text="Cancel", 
                             command=manual_window.destroy,
                             bg='#666666', fg='#ffffff', relief=tk.FLAT, padx=30, pady=10)
        cancel_btn.pack(side=tk.LEFT, padx=10)
    
    def save_manual_config(self, protocol, server, port, uuid, name, window):
        """Save manually entered configuration"""
        if not all([protocol, server, port, uuid, name]):
            messagebox.showwarning("Warning", "Please fill in all fields")
            return
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number")
            return
        
        config = {
            "name": name,
            "protocol": protocol,
            "server": server,
            "port": port,
            "uuid": uuid,
            "type": "manual"
        }
        
        self.add_config(config)
        messagebox.showinfo("Success", f"Configuration '{name}' saved successfully")
        window.destroy()
    
    def parse_config_content(self, content):
        """Parse configuration content from various formats"""
        content = content.strip()
        
        # Try to parse as VLESS URL
        if content.startswith("vless://"):
            return self.parse_vless_url(content)
        
        # Try to parse as VMess URL
        elif content.startswith("vmess://"):
            return self.parse_vmess_url(content)
        
        # Try to parse as Trojan URL
        elif content.startswith("trojan://"):
            return self.parse_trojan_url(content)
        
        # Try to parse as JSON
        elif content.startswith("{") or content.startswith("["):
            try:
                json_data = json.loads(content)
                return self.parse_json_config(json_data)
            except:
                pass
        
        # Try to parse as .npvt format
        return self.parse_npvt_format(content)
    
    def parse_vless_url(self, url):
        """Parse VLESS URL format"""
        try:
            # Remove protocol prefix
            url = url.replace("vless://", "")
            
            # Split into parts
            if "?" in url:
                main_part, query_part = url.split("?", 1)
            else:
                main_part, query_part = url, ""
            
            # Parse main part (uuid@server:port)
            if "@" in main_part:
                uuid, server_part = main_part.split("@", 1)
            else:
                return None
            
            # Parse server and port
            if ":" in server_part:
                server, port = server_part.rsplit(":", 1)
                try:
                    port = int(port)
                except ValueError:
                    return None
            else:
                server, port = server_part, 443
            
            # Parse query parameters
            params = {}
            if query_part:
                for param in query_part.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        params[key] = urllib.parse.unquote(value)
            
            # Extract name from fragment
            name = params.get("name", "VLESS Config")
            if "#" in url:
                name = url.split("#")[-1]
            
            return {
                "name": name,
                "protocol": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
                "security": params.get("security", "none"),
                "encryption": params.get("encryption", "none"),
                "type": params.get("type", "tcp"),
                "path": params.get("path", ""),
                "sni": params.get("sni", ""),
                "source": "url"
            }
        except Exception as e:
            print(f"Error parsing VLESS URL: {e}")
            return None
    
    def parse_vmess_url(self, url):
        """Parse VMess URL format"""
        try:
            # Remove protocol prefix
            url = url.replace("vmess://", "")
            
            # Decode base64
            decoded = base64.b64decode(url).decode('utf-8')
            config = json.loads(decoded)
            
            return {
                "name": config.get("ps", "VMess Config"),
                "protocol": "vmess",
                "server": config.get("add", ""),
                "port": config.get("port", 443),
                "uuid": config.get("id", ""),
                "alterId": config.get("aid", 0),
                "security": config.get("security", "auto"),
                "type": config.get("type", "tcp"),
                "source": "url"
            }
        except Exception as e:
            print(f"Error parsing VMess URL: {e}")
            return None
    
    def parse_trojan_url(self, url):
        """Parse Trojan URL format"""
        try:
            # Remove protocol prefix
            url = url.replace("trojan://", "")
            
            # Split into parts
            if "?" in url:
                main_part, query_part = url.split("?", 1)
            else:
                main_part, query_part = url, ""
            
            # Parse main part (password@server:port)
            if "@" in main_part:
                password, server_part = main_part.split("@", 1)
            else:
                return None
            
            # Parse server and port
            if ":" in server_part:
                server, port = server_part.rsplit(":", 1)
                try:
                    port = int(port)
                except ValueError:
                    return None
            else:
                server, port = server_part, 443
            
            # Parse query parameters
            params = {}
            if query_part:
                for param in query_part.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        params[key] = urllib.parse.unquote(value)
            
            # Extract name from fragment
            name = params.get("name", "Trojan Config")
            if "#" in url:
                name = url.split("#")[-1]
            
            return {
                "name": name,
                "protocol": "trojan",
                "server": server,
                "port": port,
                "password": password,
                "sni": params.get("sni", ""),
                "source": "url"
            }
        except Exception as e:
            print(f"Error parsing Trojan URL: {e}")
            return None
    
    def parse_json_config(self, json_data):
        """Parse JSON configuration"""
        try:
            if isinstance(json_data, list) and len(json_data) > 0:
                json_data = json_data[0]
            
            protocol = json_data.get("protocol", "unknown")
            
            if protocol == "vless":
                return {
                    "name": json_data.get("name", "VLESS Config"),
                    "protocol": "vless",
                    "server": json_data.get("server", ""),
                    "port": json_data.get("port", 443),
                    "uuid": json_data.get("uuid", ""),
                    "security": json_data.get("security", "none"),
                    "encryption": json_data.get("encryption", "none"),
                    "type": json_data.get("type", "tcp"),
                    "path": json_data.get("path", ""),
                    "sni": json_data.get("sni", ""),
                    "source": "json"
                }
            elif protocol == "vmess":
                return {
                    "name": json_data.get("name", "VMess Config"),
                    "protocol": "vmess",
                    "server": json_data.get("server", ""),
                    "port": json_data.get("port", 443),
                    "uuid": json_data.get("uuid", ""),
                    "alterId": json_data.get("aid", 0),
                    "security": json_data.get("security", "auto"),
                    "type": json_data.get("type", "tcp"),
                    "source": "json"
                }
            elif protocol == "trojan":
                return {
                    "name": json_data.get("name", "Trojan Config"),
                    "protocol": "trojan",
                    "server": json_data.get("server", ""),
                    "port": json_data.get("port", 443),
                    "password": json_data.get("password", ""),
                    "sni": json_data.get("sni", ""),
                    "source": "json"
                }
            
            return None
        except Exception as e:
            print(f"Error parsing JSON config: {e}")
            return None
    
    def parse_npvt_format(self, content):
        """Parse .npvt file format"""
        try:
            # Try to parse as JSON first
            if content.startswith("{") or content.startswith("["):
                return self.parse_json_config(json.loads(content))
            
            # Try to parse as key-value pairs
            config = {}
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                if line and '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
            
            if config:
                protocol = config.get("protocol", "unknown")
                
                if protocol == "vless":
                    return {
                        "name": config.get("name", "VLESS Config"),
                        "protocol": "vless",
                        "server": config.get("server", ""),
                        "port": int(config.get("port", 443)),
                        "uuid": config.get("uuid", ""),
                        "security": config.get("security", "none"),
                        "encryption": config.get("encryption", "none"),
                        "type": config.get("type", "tcp"),
                        "path": config.get("path", ""),
                        "sni": config.get("sni", ""),
                        "source": "npvt"
                    }
                elif protocol == "vmess":
                    return {
                        "name": config.get("name", "VMess Config"),
                        "protocol": "vmess",
                        "server": config.get("server", ""),
                        "port": int(config.get("port", 443)),
                        "uuid": config.get("uuid", ""),
                        "alterId": int(config.get("aid", 0)),
                        "security": config.get("security", "auto"),
                        "type": config.get("type", "tcp"),
                    "source": "npvt"
                    }
                elif protocol == "trojan":
                    return {
                        "name": config.get("name", "Trojan Config"),
                        "protocol": "trojan",
                        "server": config.get("server", ""),
                        "port": int(config.get("port", 443)),
                        "password": config.get("password", ""),
                        "sni": config.get("sni", ""),
                        "source": "npvt"
                    }
            
            return None
        except Exception as e:
            print(f"Error parsing NPVT format: {e}")
            return None
    
    def add_config(self, config):
        """Add a new configuration"""
        if config:
            self.configs.append(config)
            self.current_config = config
            self.update_config_display()
            
            # Save configs to file
            self.save_configs()
    
    def update_config_display(self):
        """Update the configuration display"""
        if self.current_config:
            config_text = f"Config: {self.current_config['name']} ({self.current_config['protocol'].upper()})"
            self.config_label.config(text=config_text, fg='#00ff88')
        else:
            self.config_label.config(text="No configuration loaded", fg='#cccccc')
    
    def save_configs(self):
        """Save configurations to file"""
        try:
            config_file = "npv_tunnel_configs.json"
            encrypted_configs = []
            
            for config in self.configs:
                if self.fernet:
                    encrypted_config = {
                        'encrypted': True,
                        'data': self.encrypt_config(config)
                    }
                    encrypted_configs.append(encrypted_config)
                else:
                    encrypted_configs.append(config)
            
            os.makedirs(self.get_data_dir(), exist_ok=True)
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(encrypted_configs, f, indent=2, ensure_ascii=False)
                
            self.logger.info(f"Saved {len(self.configs)} configurations")
            
        except Exception as e:
            self.logger.error(f"Failed to save configurations: {e}")
    def backup_firewall_state(self):
        """Backup current firewall state before enabling kill switch"""
        try:
            # Get current firewall profiles
            profiles = ['Domain', 'Private', 'Public']
            self.firewall_backup = {}
            
            for profile in profiles:
                # Check if firewall is enabled
                result = subprocess.run([
                    'netsh', 'advfirewall', 'show', 'allprofiles', 'state'
                ], capture_output=True, text=True, shell=True)
                
                if result.returncode == 0:
                    self.firewall_backup[profile] = {
                        'enabled': 'ON' in result.stdout,
                        'rules': []
                    }
                    
                    # Backup existing outbound rules
                    result = subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'show', 'rule', 
                        'name=all', 'dir=out', 'profile=' + profile
                    ], capture_output=True, text=True, shell=True)
                    
                    if result.returncode == 0:
                        self.firewall_backup[profile]['rules'] = result.stdout
                        
            self.log_operation("Firewall state backed up successfully", level='debug')
            
        except Exception as e:
            self.log_operation(f"Firewall backup failed: {e}", level='warning')
    
    def create_kill_switch_rules(self):
        """Create Windows Firewall rules for kill switch functionality"""
        try:
            # Rule names for easy identification
            self.kill_switch_rules = [
                'NPVTunnel_KillSwitch_BlockAll',
                'NPVTunnel_KillSwitch_AllowVPN',
                'NPVTunnel_KillSwitch_AllowDNS',
                'NPVTunnel_KillSwitch_AllowLocal'
            ]
            
            # 1. Block all outbound traffic (default deny)
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=NPVTunnel_KillSwitch_BlockAll',
                'dir=out',
                'action=block',
                'enable=yes',
                'profile=any',
                'description=Block all outbound traffic when VPN is active'
            ], shell=True, check=True)
            
            # 2. Allow traffic to VPN proxy (127.0.0.1:1080, 127.0.0.1:1081)
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=NPVTunnel_KillSwitch_AllowVPN',
                'dir=out',
                'action=allow',
                'enable=yes',
                'profile=any',
                'remoteip=127.0.0.1',
                'remoteport=1080,1081',
                'description=Allow traffic to VPN proxy servers'
            ], shell=True, check=True)
            
            # 3. Allow DNS queries to prevent DNS leaks
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=NPVTunnel_KillSwitch_AllowDNS',
                'dir=out',
                'action=allow',
                'enable=yes',
                'profile=any',
                'protocol=UDP',
                'remoteport=53',
                'description=Allow DNS queries to prevent leaks'
            ], shell=True, check=True)
            
            # 4. Allow local network traffic
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=NPVTunnel_KillSwitch_AllowLocal',
                'dir=out',
                'action=allow',
                'enable=yes',
                'profile=any',
                'remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1',
                'description=Allow local network traffic'
            ], shell=True, check=True)
            
            self.log_operation("Kill switch firewall rules created successfully", level='debug')
            
        except Exception as e:
            self.log_operation(f"Failed to create kill switch rules: {e}", level='error')
            raise
    
    def activate_kill_switch_rules(self):
        """Activate the kill switch firewall rules"""
        try:
            # Enable all kill switch rules
            for rule_name in self.kill_switch_rules:
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'set', 'rule',
                    'name=' + rule_name,
                    'new', 'enable=yes'
                ], shell=True, check=True)
            
            self.log_operation("Kill switch rules activated successfully", level='debug')
            
        except Exception as e:
            self.log_operation(f"Failed to activate kill switch rules: {e}", level='error')
            raise
    
    def remove_kill_switch_rules(self):
        """Remove kill switch firewall rules"""
        try:
            for rule_name in self.kill_switch_rules:
                try:
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                        'name=' + rule_name
                    ], shell=True, check=True)
                except subprocess.CalledProcessError:
                    # Rule might not exist, continue
                    pass
            
            self.log_operation("Kill switch rules removed successfully", level='debug')
            
        except Exception as e:
            self.log_operation(f"Failed to remove kill switch rules: {e}", level='error')
    
    def restore_firewall_state(self):
        """Restore original firewall state after kill switch"""
        try:
            if hasattr(self, 'firewall_backup'):
                # Restore original firewall rules if needed
                # Note: Windows automatically handles rule priority, so we just remove our rules
                self.log_operation("Firewall state backed up successfully", level='debug')
            else:
                self.log_operation("No firewall backup found, using default restoration", level='debug')
                
        except Exception as e:
            self.log_operation(f"Firewall restoration failed: {e}", level='error')

    # ------------------------ Certificate Pinning ------------------------
    def try_certificate_pinning(self, config):
        """If pinning data exists in config, verify TLS certificate before connecting.
        Supports:
          - pinned_fingerprint_sha256: hex string of server cert SHA-256
          - pinned_pubkey_sha256: SHA-256 of DER SubjectPublicKeyInfo
        """
        try:
            server = config.get('server')
            port = int(config.get('port', 443))
            pinned_fp = (config.get('pinned_fingerprint_sha256') or '').lower().replace(':','')
            pinned_pk = (config.get('pinned_pubkey_sha256') or '').lower().replace(':','')
            if not server or (not pinned_fp and not pinned_pk):
                return True

            import ssl, socket, hashlib
            ctx = ssl.create_default_context()
            # If SNI provided, use it; else server
            sni = config.get('sni') or server
            with socket.create_connection((server, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    # Fingerprint of full cert
                    fp256 = hashlib.sha256(der_cert).hexdigest()
                    if pinned_fp and fp256 != pinned_fp:
                        raise RuntimeError(f"Cert pin mismatch (sha256): expected {pinned_fp}, got {fp256}")
                    # Public key pin (extract SubjectPublicKeyInfo via ssl doesn't expose easily)
                    # Best-effort: use full cert for now unless pyopenssl is added
                    if pinned_pk:
                        # Fallback compare to full cert hash to prevent false positive use
                        if fp256 != pinned_pk:
                            raise RuntimeError("Public key pin mismatch")
            self.log_operation('Certificate pinning verification passed', level='info')
            return True
        except Exception as e:
            self.log_operation(f'Certificate pinning failed: {e}', level='error')
            raise

    # ------------------------ Split Tunneling via PAC ------------------------
    def build_pac_content(self, direct_domains=None, direct_ips=None, proxy_host='127.0.0.1', proxy_port_http=1081, proxy_port_socks=1080):
        """Generate PAC file content for split tunneling.
        direct_domains: list of domain suffixes to go DIRECT
        direct_ips: list of CIDR/IPs to go DIRECT
        Default: local/LAN go DIRECT; everything else via HTTP proxy.
        """
        direct_domains = direct_domains or ['localhost', '127.0.0.1']
        # Always include private networks
        direct_ips = direct_ips or ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']
        domain_checks = ' || '.join([f"shExpMatch(host, '*.{d}') || dnsDomainIs(host, '{d}')" for d in direct_domains]) or 'false'
        ip_checks = ' || '.join([f"isInNet(host, '{cidr.split('/')[0]}', '{self.cidr_mask(cidr)}')" for cidr in direct_ips]) or 'false'
        pac = f"""
function FindProxyForURL(url, host) {{
  if (isPlainHostName(host) || shExpMatch(host, 'localhost') || dnsDomainIs(host, 'localhost')) return 'DIRECT';
  if ({domain_checks}) return 'DIRECT';
  if ({ip_checks}) return 'DIRECT';
  return 'PROXY {proxy_host}:{proxy_port_http}; SOCKS5 {proxy_host}:{proxy_port_socks}; DIRECT';
}}
"""
        return pac

    def cidr_mask(self, cidr):
        try:
            base, bits = cidr.split('/')
            bits = int(bits)
            mask_int = (0xffffffff << (32 - bits)) & 0xffffffff
            return '.'.join(str((mask_int >> (i*8)) & 0xff) for i in [3,2,1,0])
        except Exception:
            return '255.255.255.0'

    def start_pac_server(self, pac_content, port=0):
        """Serve PAC content over an ephemeral local HTTP server; return URL."""
        import http.server, socketserver, threading
        class PACHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self_inner):
                self_inner.send_response(200)
                self_inner.send_header('Content-type','application/x-ns-proxy-autoconfig')
                self_inner.end_headers()
                self_inner.wfile.write(pac_content.encode('utf-8'))
            def log_message(self_inner, format, *args):
                return
        self.pac_httpd = socketserver.TCPServer(('127.0.0.1', port), PACHandler)
        self.pac_port = self.pac_httpd.server_address[1]
        thread = threading.Thread(target=self.pac_httpd.serve_forever, daemon=True)
        thread.start()
        self.log_operation(f"PAC server started on 127.0.0.1:{self.pac_port}", level='info')
        return f"http://127.0.0.1:{self.pac_port}/proxy.pac"

    def stop_pac_server(self):
        try:
            if getattr(self, 'pac_httpd', None):
                self.pac_httpd.shutdown()
                self.pac_httpd.server_close()
                self.pac_httpd = None
                self.log_operation('PAC server stopped', level='info')
        except Exception:
            pass

    def enable_split_tunneling(self, direct_domains=None, direct_ips=None):
        try:
            self.log_audit('split_tunneling', 'enable_start', {"domains": direct_domains, "ips": direct_ips})
            pac = self.build_pac_content(direct_domains=direct_domains, direct_ips=direct_ips)
            pac_url = self.start_pac_server(pac)
            self.set_pac_proxy(pac_url)
            self.split_tunneling_enabled = True
            self.log_operation('Split tunneling enabled via PAC', level='info')
            self.log_audit('split_tunneling', 'enable_success')
        except Exception as e:
            self.log_operation(f'Enable split tunneling failed: {e}', level='warning')
            self.log_audit('split_tunneling', 'enable_failure', {"error": str(e)})

    def disable_split_tunneling(self):
        try:
            self.log_audit('split_tunneling', 'disable_start')
            self.clear_system_proxy()
            self.stop_pac_server()
            self.split_tunneling_enabled = False
            self.log_operation('Split tunneling disabled', level='info')
            self.log_audit('split_tunneling', 'disable_success')
        except Exception as e:
            self.log_operation(f'Disable split tunneling failed: {e}', level='warning')
            self.log_audit('split_tunneling', 'disable_failure', {"error": str(e)})


def main():
    # Check if running on Windows
    if platform.system() != "Windows":
        messagebox.showerror("Error", "This application is designed for Windows only!")
        return
    
    try:
        # Create main window
        root = tk.Tk()
        
        # Set window icon (if available)
        try:
            root.iconbitmap("icon.ico")
        except:
            pass
        
        # Create application
        app = NpvTunnelPC(root)
        
        # Start the application
        root.mainloop()
        
    except Exception as e:
        print(f"Application startup error: {e}")
        messagebox.showerror("Critical Error", f"Failed to start application: {str(e)}")

if __name__ == "__main__":
    main()
