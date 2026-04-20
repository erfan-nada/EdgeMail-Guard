import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import asyncio
import time
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from datetime import datetime

# ==========================================
# PART 1: THE ML ENGINE 
# ==========================================
class SpamDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.is_trained = False
        self.train_dummy_model()

    def extract_features(self, helo_domain, mail_from, rcpt_to, raw_headers):
        hops = raw_headers.lower().count("received:")
        header_len = len(raw_headers)
        has_msg_id = 1 if "message-id:" in raw_headers.lower() else 0
        is_suspicious_domain = 1 if "spambot" in helo_domain.lower() or "temp" in mail_from.lower() else 0
        rcpt_count = rcpt_to.count(",") + 1
        return np.array([[hops, header_len, has_msg_id, is_suspicious_domain, rcpt_count]])

    def train_dummy_model(self):
        X_train = np.array([
            [1, 200, 1, 0, 1], [2, 350, 1, 0, 1], [5, 150, 0, 1, 50],
            [0, 50, 0, 1, 10], [1, 220, 1, 0, 1], [6, 800, 0, 1, 20]
        ])
        y_train = np.array([0, 0, 1, 1, 0, 1])
        self.model.fit(X_train, y_train)
        self.is_trained = True

    def predict(self, features):
        return self.model.predict(features)[0] if self.is_trained else 0

# ==========================================
# PART 2: THE ASYNCIO EDGE PROXY
# ==========================================
class AsyncEdgeServer:
    def __init__(self, host='127.0.0.1', port=2525, gui_callback=None):
        self.host = host
        self.port = port
        self.server = None
        self.loop = None
        self.gui_callback = gui_callback
        self.detector = SpamDetector()
        self.stats = {'total': 0, 'spam': 0, 'ham': 0}
        self.running = False

    def log(self, message, tag=None):
        if self.gui_callback:
            self.gui_callback(message, tag)

    def start_in_thread(self):
        """Helper to run the async loop in a separate thread so GUI doesn't freeze"""
        self.running = True
        threading.Thread(target=self._run_async_loop, daemon=True).start()

    def _run_async_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._start_server())

    async def _start_server(self):
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port)
        
        addr = self.server.sockets[0].getsockname()
        self.log(f"⚡ ASYNC SYSTEM ONLINE: {addr}", "sys")
        
        async with self.server:
            await self.server.serve_forever()

    def stop(self):
        self.running = False
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.log("🛑 SYSTEM OFFLINE", "error")

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        self.log(f"→ Async Conn: {addr[0]}", "conn")
        self.stats['total'] += 1
        
        try:
            # 1. Handshake
            writer.write(b"220 EdgeMail Guard Ready\r\n")
            await writer.drain()
            
            helo, mail_from, rcpt_to = "", "", ""
            
            while True:
                data = await reader.read(1024)
                if not data: break
                
                decoded_data = data.decode('utf-8', errors='ignore')
                cmd = decoded_data[:4].upper()
                
                if cmd.startswith("HELO") or cmd.startswith("EHLO"):
                    helo = decoded_data.split()[1] if len(decoded_data.split()) > 1 else "unknown"
                    writer.write(b"250 Hello\r\n")
                    await writer.drain()
                    
                elif cmd.startswith("MAIL"):
                    mail_from = decoded_data
                    writer.write(b"250 OK\r\n")
                    await writer.drain()
                    
                elif cmd.startswith("RCPT"):
                    rcpt_to = decoded_data
                    writer.write(b"250 OK\r\n")
                    await writer.drain()
                    
                elif cmd.startswith("DATA"):
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()
                    
                    # --- ZERO-PAYLOAD LOGIC ---
                    start_time = time.time()
                    headers_buffer = ""
                    
                    # Read loop until headers end
                    while True:
                        chunk = await reader.read(1024)
                        headers_buffer += chunk.decode('utf-8', errors='ignore')
                        if "\r\n\r\n" in headers_buffer:
                            headers_only = headers_buffer.split("\r\n\r\n")[0]
                            break
                    
                    # ML Inference
                    features = self.detector.extract_features(helo, mail_from, rcpt_to, headers_only)
                    prediction = self.detector.predict(features)
                    latency = (time.time() - start_time) * 1000
                    
                    if prediction == 1:
                        self.stats['spam'] += 1
                        self.log(f"   [!] BLOCKED SPAM | Latency: {latency:.2f}ms", "spam")
                        writer.write(b"554 Transaction Failed - Spam Detected\r\n")
                        await writer.drain()
                        writer.close()
                        return
                    else:
                        self.stats['ham'] += 1
                        self.log(f"   [✓] ALLOWED HAM  | Latency: {latency:.2f}ms", "ham")
                        writer.write(b"250 OK Message accepted\r\n")
                        await writer.drain()
                        break
                        
                elif cmd.startswith("QUIT"):
                    writer.write(b"221 Bye\r\n")
                    await writer.drain()
                    break
                    
        except Exception as e:
            self.log(f"Error: {e}", "error")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

# ==========================================
# PART 3: THE MODERN DASHBOARD GUI
# ==========================================
class ModernEdgeGuard:
    def __init__(self, root):
        self.root = root
        self.root.title("EdgeMail Guard | Zero-Payload Security")
        self.root.geometry("1000x650")
        self.root.configure(bg="#1e1e1e")
        
        self.server = None
        self.setup_ui()
        
    def setup_ui(self):
        # COLORS & STYLES (Same as before)
        BG_COLOR = "#1e1e1e"
        PANEL_COLOR = "#2d2d2d"
        TEXT_COLOR = "#e0e0e0"
        ACCENT_CYAN = "#00ffff"
        ACCENT_GREEN = "#00ff00"
        ACCENT_RED = "#ff4444"

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Card.TFrame", background=PANEL_COLOR, relief="flat")
        style.configure("TLabel", background=PANEL_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=PANEL_COLOR, foreground=ACCENT_CYAN, font=("Segoe UI", 14, "bold"))
        
        # TITLE BAR
        title_frame = tk.Frame(self.root, bg="#111111", height=50)
        title_frame.pack(fill="x")
        tk.Label(title_frame, text="🛡️ EdgeMail Guard Dashboard", bg="#111111", fg="white", font=("Segoe UI", 16, "bold")).pack(side="left", padx=20, pady=10)
        
        # MAIN CONTAINER
        main_container = tk.Frame(self.root, bg=BG_COLOR)
        main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # LEFT PANEL
        left_panel = ttk.Frame(main_container, style="Card.TFrame")
        left_panel.pack(side="left", fill="y", padx=(0, 20), ipadx=10, ipady=10)
        
        # Status Indicator
        self.canvas_status = tk.Canvas(left_panel, width=20, height=20, bg=PANEL_COLOR, highlightthickness=0)
        self.indicator = self.canvas_status.create_oval(2, 2, 18, 18, fill="#555555")
        self.canvas_status.pack(pady=(20, 5))
        
        self.lbl_status = ttk.Label(left_panel, text="SYSTEM OFFLINE", font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(pady=(0, 20))
        
        # Buttons
        self.btn_start = tk.Button(left_panel, text="INITIALIZE PROXY", bg="#005500", fg="white", font=("Consolas", 11, "bold"), 
                                   command=self.start_server, relief="flat", padx=20, pady=10)
        self.btn_start.pack(fill="x", padx=15, pady=5)
        
        self.btn_stop = tk.Button(left_panel, text="TERMINATE", bg="#550000", fg="white", font=("Consolas", 11, "bold"), 
                                  command=self.stop_server, relief="flat", padx=20, pady=10, state="disabled")
        self.btn_stop.pack(fill="x", padx=15, pady=5)
        
        # Stats
        ttk.Separator(left_panel, orient="horizontal").pack(fill="x", pady=20, padx=10)
        ttk.Label(left_panel, text="TRAFFIC METRICS", style="Header.TLabel").pack(anchor="w", padx=15)
        
        self.var_total = tk.StringVar(value="0")
        self.var_spam = tk.StringVar(value="0")
        self.var_ham = tk.StringVar(value="0")
        
        self.create_stat_card(left_panel, "Total Requests", self.var_total, "white")
        self.create_stat_card(left_panel, "Threats Blocked", self.var_spam, ACCENT_RED)
        self.create_stat_card(left_panel, "Emails Cleaned", self.var_ham, ACCENT_GREEN)

        # RIGHT PANEL
        right_panel = tk.Frame(main_container, bg=BG_COLOR)
        right_panel.pack(side="left", fill="both", expand=True)
        
        # Log
        tk.Label(right_panel, text="LIVE PACKET INSPECTION LOG", bg=BG_COLOR, fg=ACCENT_CYAN, font=("Consolas", 12)).pack(anchor="w")
        self.log_area = scrolledtext.ScrolledText(right_panel, height=20, bg="#000000", fg="#00ff00", 
                                                  font=("Consolas", 10), insertbackground="white", relief="flat")
        self.log_area.pack(fill="both", expand=True, pady=(5, 20))
        
        self.log_area.tag_config("sys", foreground="cyan")
        self.log_area.tag_config("error", foreground="red")
        self.log_area.tag_config("conn", foreground="yellow")
        self.log_area.tag_config("spam", foreground="#ff4444", background="#220000")
        self.log_area.tag_config("ham", foreground="#44ff44")

        # Simulator Bar
        sim_bar = ttk.Frame(right_panel, style="Card.TFrame")
        sim_bar.pack(fill="x", ipady=10)
        
        ttk.Label(sim_bar, text=" ATTACK SIMULATOR: ", style="Header.TLabel").pack(side="left", padx=10)
        tk.Button(sim_bar, text="Test: LEGITIMATE Email", bg=PANEL_COLOR, fg=ACCENT_GREEN, relief="solid", bd=1,
                  command=lambda: self.simulate_traffic("ham")).pack(side="left", padx=5)
        tk.Button(sim_bar, text="Test: SPAM Attack", bg=PANEL_COLOR, fg=ACCENT_RED, relief="solid", bd=1,
                  command=lambda: self.simulate_traffic("spam")).pack(side="left", padx=5)

    def create_stat_card(self, parent, title, variable, color):
        frame = tk.Frame(parent, bg="#222222", pady=5)
        frame.pack(fill="x", padx=15, pady=5)
        tk.Label(frame, text=title, bg="#222222", fg="#888888", font=("Segoe UI", 9)).pack(anchor="w", padx=5)
        tk.Label(frame, textvariable=variable, bg="#222222", fg=color, font=("Consolas", 20, "bold")).pack(anchor="e", padx=5)

    def update_log(self, message, tag=None):
        self.log_area.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.log_area.insert("end", f"[{ts}] {message}\n", tag)
        self.log_area.see("end")
        self.log_area.config(state="disabled")
        
        if self.server:
            self.var_total.set(str(self.server.stats['total']))
            self.var_spam.set(str(self.server.stats['spam']))
            self.var_ham.set(str(self.server.stats['ham']))

    def start_server(self):
        self.server = AsyncEdgeServer(gui_callback=self.update_log)
        self.server.start_in_thread()
        self.btn_start.config(state="disabled", bg="#333333")
        self.btn_stop.config(state="normal", bg="#ff4444")
        self.canvas_status.itemconfig(self.indicator, fill="#00ff00")
        self.lbl_status.config(text="SYSTEM ONLINE", foreground="#00ff00")

    def stop_server(self):
        if self.server:
            self.server.stop()
        self.btn_start.config(state="normal", bg="#005500")
        self.btn_stop.config(state="disabled", bg="#333333")
        self.canvas_status.itemconfig(self.indicator, fill="#ff0000")
        self.lbl_status.config(text="SYSTEM OFFLINE", foreground="#ff4444")

    def simulate_traffic(self, type):
        threading.Thread(target=self._run_simulation, args=(type,), daemon=True).start()

    def _run_simulation(self, type):
        try:
            import socket 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', 2525))
            s.recv(1024) 
            
            if type == "ham":
                cmds = [
                    b"HELO mail.google.com\r\n",
                    b"MAIL FROM: <user@google.com>\r\n",
                    b"RCPT TO: <user@msa.edu.eg>\r\n",
                    b"DATA\r\n",
                    b"Message-ID: <123@google.com>\r\nReceived: from Google\r\nSubject: Meeting\r\n\r\n"
                ]
            else:
                cmds = [
                    b"HELO spambot.xyz\r\n",
                    b"MAIL FROM: <hacker@bad.com>\r\n",
                    b"RCPT TO: <victim@msa.edu.eg>\r\n",
                    b"DATA\r\n",
                    b"Received: from bot\r\nReceived: from bot\r\nReceived: from bot\r\nSubject: WIN CASH\r\n\r\n"
                ]

            for cmd in cmds:
                s.send(cmd)
                time.sleep(0.01) # 10ms for realism
                resp = s.recv(1024).decode()
                if "554" in resp: break
            s.close()
        except Exception as e:
            self.update_log(f"Sim Error: {e}", "error")

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernEdgeGuard(root)
    root.mainloop()