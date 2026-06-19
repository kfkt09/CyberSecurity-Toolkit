import sqlite3
from datetime import datetime
import tkinter as tk
from scapy.all import ARP, Ether, srp
import socket
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# ================= DATABASE =================
conn = sqlite3.connect("scan_history.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,
    ip TEXT,
    mac TEXT
)
""")

conn.commit()

# ================= GLOBALS =================
target_ip = "192.168.207.0/24"

devices = []
scan_data = []

# ================= FUNCTIONS =================

def scan_network():
    global devices, scan_data

    devices.clear()
    scan_data.clear()

    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    listbox.delete(0, tk.END)
    result_text.delete("1.0", tk.END)

    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc

        devices.append(ip)
        scan_data.append((ip, mac))

        # Save to DB
        cursor.execute(
            "INSERT INTO scans (time, ip, mac) VALUES (?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, mac)
        )
        conn.commit()

        listbox.insert(tk.END, f"{ip}  |  {mac}")

    result_text.insert(tk.END, "Scan Completed!\n")


def scan_ports():
    selected = listbox.curselection()

    if not selected:
        result_text.insert(tk.END, "Select a device first!\n")
        return

    target = devices[selected[0]]

    result_text.insert(tk.END, f"\nScanning {target}...\n")

    ports = [22, 80, 443, 21, 3389, 445]

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        res = s.connect_ex((target, port))

        if res == 0:
            result_text.insert(tk.END, f"Port {port} OPEN\n")

        s.close()


def generate_pdf():
    if not scan_data:
        result_text.insert(tk.END, "No data to export!\n")
        return

    file_name = "scan_report.pdf"
    c = canvas.Canvas(file_name, pagesize=letter)

    c.setFont("Helvetica-Bold", 16)
    c.drawString(180, 750, "Network Scan Report")

    c.setFont("Helvetica", 12)
    y = 700

    for ip, mac in scan_data:
        c.drawString(50, y, f"{ip}  -  {mac}")
        y -= 20

    c.save()

    result_text.insert(tk.END, "\nPDF Generated Successfully!\n")


def show_history():
    result_text.delete("1.0", tk.END)

    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()

    result_text.insert(tk.END, "Scan History:\n\n")

    for row in rows:
        result_text.insert(tk.END, f"{row[1]} | {row[2]} | {row[3]}\n")


# ================= GUI =================

root = tk.Tk()
root.title("Cyber Security Toolkit")
root.geometry("600x500")

tk.Label(root, text="Cyber Security Toolkit", font=("Arial", 16)).pack(pady=10)

tk.Button(root, text="Scan Network", command=scan_network).pack(pady=5)
tk.Button(root, text="Scan Ports", command=scan_ports).pack(pady=5)
tk.Button(root, text="Generate PDF Report", command=generate_pdf).pack(pady=5)
tk.Button(root, text="Show History", command=show_history).pack(pady=5)

listbox = tk.Listbox(root, width=70)
listbox.pack(pady=10)

result_text = tk.Text(root, height=10)
result_text.pack(pady=10)

root.mainloop()