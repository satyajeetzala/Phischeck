import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image, ImageDraw
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
import nmap
import whois
import hashlib
import socket
import ssl
import requests
import ipaddress
import webbrowser
import sys
import os

# Assuming 'heuristics.py' exists and contains these functions
# You will need to run: pip install dnspython
from heuristics import calculate_phishing_score, fetch_openphish_feed, get_server_info

# --- Helper Function for PyInstaller ---
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- Global Variables ---
last_scan_result_text = ""
verdict_counts = {"Phishing": 0, "Safe": 0}

# --- UI Setup ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("PhishCheck - Phishing Detection Tool")
app.geometry("900x600")
app.minsize(800, 500)
app.resizable(True, True)

# --- Load Logo with Fallback ---
logo_path = resource_path("cid_logo.jpg")
try:
    logo_image = ctk.CTkImage(dark_image=Image.open(logo_path), size=(80, 80))
except Exception:
    blank = Image.new("RGB", (80, 80), color="gray")
    draw = ImageDraw.Draw(blank)
    draw.text((10, 30), "No Logo", fill="white")
    logo_image = ctk.CTkImage(dark_image=blank, size=(80, 80))

# --- Main Layout ---
main_frame = ctk.CTkFrame(app)
main_frame.pack(fill="both", expand=True, padx=10, pady=10)

# --- Left Panel ---
left_panel = ctk.CTkFrame(main_frame, width=240, corner_radius=15)
left_panel.pack(side="left", fill="y", padx=(0, 10))

logo_label = ctk.CTkLabel(left_panel, image=logo_image, text="")
logo_label.pack(pady=(15, 5))

title_label = ctk.CTkLabel(left_panel, text="PhishCheck", font=("Arial", 22, "bold"))
title_label.pack(pady=(5, 15))

url_entry = ctk.CTkEntry(left_panel, placeholder_text="Enter URL to Scan", width=200)
url_entry.pack(pady=10)

# --- Right Panel ---
right_panel = ctk.CTkFrame(main_frame, corner_radius=15)
right_panel.pack(side="left", fill="both", expand=True)

ctk.CTkLabel(right_panel, text="🔴 Unsafe Links", font=("Arial", 16, "bold"),
             text_color="white", bg_color="red").pack(fill="x", pady=(10, 0), padx=10)
details_unsafe = ctk.CTkTextbox(right_panel, height=150, wrap="word")
details_unsafe.pack(fill="both", expand=True, padx=10, pady=(0, 10))
details_unsafe.configure(state="disabled")

ctk.CTkLabel(right_panel, text="🟢 Safe Links", font=("Arial", 16, "bold"),
             text_color="white", bg_color="green").pack(fill="x", pady=(10, 0), padx=10)
details_safe = ctk.CTkTextbox(right_panel, height=150, wrap="word")
details_safe.pack(fill="both", expand=True, padx=10, pady=(0, 10))
details_safe.configure(state="disabled")

# --- WHOIS and Nmap Sections ---
whois_label = ctk.CTkLabel(right_panel, text="🔎 WHOIS Domain Information", font=("Arial", 16, "bold"))
whois_label.pack(fill="x", pady=(10, 0), padx=10)
whois_box = ctk.CTkTextbox(right_panel, height=120, wrap="word")
whois_box.pack(fill="both", expand=False, padx=10, pady=(0, 10))
whois_box.insert("end", "Run a scan to view WHOIS info.")
whois_box.configure(state="disabled")

nmap_label = ctk.CTkLabel(right_panel, text="🛡️ Nmap Scan Results", font=("Arial", 16, "bold"))
nmap_label.pack(fill="x", pady=(10, 0), padx=10)
nmap_box = ctk.CTkTextbox(right_panel, height=120, wrap="word")
nmap_box.pack(fill="both", expand=False, padx=10, pady=(0, 10))
nmap_box.insert("end", "Run a scan to view Nmap results.")
nmap_box.configure(state="disabled")

# --- UI Functions (Defined after widgets are created) ---
def reset_fields():
    url_entry.delete(0, "end")
    details_unsafe.configure(state="normal")
    details_unsafe.delete("1.0", "end")
    details_unsafe.configure(state="disabled")
    details_safe.configure(state="normal")
    details_safe.delete("1.0", "end")
    details_safe.configure(state="disabled")
    whois_box.configure(state="normal")
    whois_box.delete("1.0", "end")
    whois_box.insert("end", "Run a scan to view WHOIS info.")
    whois_box.configure(state="disabled")
    nmap_box.configure(state="normal")
    nmap_box.delete("1.0", "end")
    nmap_box.insert("end", "Run a scan to view Nmap results.")
    nmap_box.configure(state="disabled")

def show_verdict_chart():
    if verdict_counts["Phishing"] == 0 and verdict_counts["Safe"] == 0:
        messagebox.showinfo("No Data", "No scans have been performed yet.")
        return

    labels = ['Phishing', 'Safe']
    sizes = [verdict_counts["Phishing"], verdict_counts["Safe"]]
    colors = ['#E74C3C', '#2ECC71'] # Red, Green
    
    plt.style.use('dark_background')
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90,
           wedgeprops={'edgecolor': 'white'}, textprops={'color': 'white', 'weight': 'bold'})
    ax.axis('equal')
    ax.set_title("Verdict Distribution", color='white')

    chart_window = ctk.CTkToplevel(app)
    chart_window.title("Verdict Distribution")
    chart_window.geometry("400x400")
    chart_window.transient(app) # Keep chart window on top

    canvas_chart = FigureCanvasTkAgg(fig, master=chart_window)
    canvas_chart.draw()
    canvas_chart.get_tk_widget().pack(fill="both", expand=True)

# --- Backend Functions ---
def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                return (
                    f"--- SSL Certificate ---\n"
                    f"Issuer: {issuer.get('organizationName', 'N/A')}\n"
                    f"Subject: {subject.get('commonName', 'N/A')}\n"
                    f"Issued On: {cert.get('notBefore')}\n"
                    f"Expires On: {cert.get('notAfter')}\n"
                )
    except Exception as e:
        return f"--- SSL Certificate ---\nSSL info could not be retrieved: {e}\n"

def get_geolocation(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get('status') != 'success':
            return f"--- Geolocation ---\nGeolocation not available: {data.get('message', 'Unknown reason')}\n"
        return (
            f"--- Geolocation ---\n"
            f"Country: {data.get('country', 'N/A')}\n"
            f"City: {data.get('city', 'N/A')}\n"
            f"ISP: {data.get('isp', 'N/A')}\n"
            f"Latitude: {data.get('lat', 'N/A')}\n"
            f"Longitude: {data.get('lon', 'N/A')}\n"
        )
    except requests.RequestException as e:
        return f"--- Geolocation ---\nGeolocation info could not be retrieved: {e}\n"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        if not w.domain_name:
            return f"WHOIS lookup failed: No data found for {domain}."
        
        creation = w.creation_date
        exp = w.expiration_date
        if isinstance(creation, list): creation = creation[0]
        if isinstance(exp, list): exp = exp[0]

        return (
            f"WHOIS Domain Information:\n"
            f"-----------------------------\n"
            f"Domain: {w.domain_name}\n"
            f"Registrar: {w.registrar}\n"
            f"Creation Date: {creation}\n"
            f"Expiry Date: {exp}\n"
            f"Registrant Country: {w.country}\n"
        )
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

def get_nmap_info(target):
    try:
        nm = nmap.PortScanner()
        arguments = '-F'  # Fast scan
        # Check for IPv6 to add the -6 flag
        try:
            if ipaddress.ip_address(target).version == 6:
                arguments = '-6 ' + arguments
        except ValueError:
            pass # Not a valid IP, could be a domain

        nm.scan(target, arguments=arguments)
        output = f"Nmap Scan Results:\n------------------\nTarget: {target}\n"
        if not nm.all_hosts():
            return output + "Host seems down or unreachable."

        for host in nm.all_hosts():
            output += f"IP Address: {host}\n"
            if 'tcp' in nm[host]:
                output += "Open Ports:\n"
                for port, port_info in nm[host]['tcp'].items():
                    output += f"- {port}/tcp ({port_info['name']}) [{port_info['state']}]\n"
        return output
    except nmap.nmap.PortScannerError:
        return f"Nmap scan failed: Nmap not found. Please install it and ensure it's in your system's PATH."
    except Exception as e:
        return f"Nmap scan failed: {e}"

def get_hashes(text):
    text_bytes = text.encode('utf-8')
    md5 = hashlib.md5(text_bytes).hexdigest()
    sha1 = hashlib.sha1(text_bytes).hexdigest()
    sha256 = hashlib.sha256(text_bytes).hexdigest()
    return md5, sha1, sha256

def scan_url():
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL to scan.")
        return

    scan_button.configure(state="disabled", text="Scanning...")

    def process():
        global last_scan_result_text
        try:
            # Let heuristics.py handle the heavy lifting
            result = calculate_phishing_score(url, openphish_feed=global_openphish_feed)
            
            domain = url.split('//')[-1].split('/')[0]
            ip_for_extras = result['details'].get('ip_addresses', [None])[0]
            nmap_target = ip_for_extras if ip_for_extras else domain
            
            md5, sha1, sha256 = get_hashes(url)
            hash_lines = (
                f"--- Hash Values ---\n"
                f"MD5:    {md5}\n"
                f"SHA1:   {sha1}\n"
                f"SHA256: {sha256}\n"
            )

            # Gather additional info in parallel for speed
            with ThreadPoolExecutor() as executor:
                whois_future = executor.submit(get_whois_info, domain)
                nmap_future = executor.submit(get_nmap_info, nmap_target)
                ssl_future = executor.submit(get_ssl_info, domain)
                geo_future = executor.submit(get_geolocation, ip_for_extras) if ip_for_extras else None

                whois_info = whois_future.result()
                nmap_info = nmap_future.result()
                ssl_info = ssl_future.result()
                geo_info = geo_future.result() if geo_future else "--- Geolocation ---\nNot available (no IP found)\n"


            # Format the output string
            output_parts = [
                f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"URL: {url}",
                f"Verdict: {'Phishing' if result['is_phishing'] else 'Safe'}",
                f"Score: {result['score']}\n",
                f"{result['details'].get('phishing_reason', '')}\n",
                hash_lines,
                f"--- Heuristics ---\n" + "\n".join([f"- {k.replace('_', ' ').capitalize()}: {v}" for k, v in result['details'].get('heuristics', {}).items()]) + "\n",
                whois_info + "\n",
                nmap_info + "\n",
                ssl_info,
                geo_info
            ]
            output = "\n".join(part for part in output_parts if part.strip())
            
            last_scan_result_text = output

            def update_gui():
                whois_box.configure(state="normal")
                whois_box.delete("1.0", "end")
                whois_box.insert("end", whois_info)
                whois_box.configure(state="disabled")

                nmap_box.configure(state="normal")
                nmap_box.delete("1.0", "end")
                nmap_box.insert("end", nmap_info)
                nmap_box.configure(state="disabled")

                if result['is_phishing']:
                    details_unsafe.configure(state="normal")
                    details_unsafe.delete("1.0", "end")
                    details_unsafe.insert("end", output)
                    details_unsafe.configure(state="disabled")
                    verdict_counts["Phishing"] += 1
                else:
                    details_safe.configure(state="normal")
                    details_safe.delete("1.0", "end")
                    details_safe.insert("end", output)
                    details_safe.configure(state="disabled")
                    verdict_counts["Safe"] += 1
                
                scan_button.configure(state="normal", text="🔍 Scan URL")

            app.after(0, update_gui)

        except Exception as e:
            error_output = f"An unexpected error occurred for URL: {url}\nError: {e}"
            last_scan_result_text = error_output
            def update_gui_error():
                details_unsafe.configure(state="normal")
                details_unsafe.delete("1.0", "end")
                details_unsafe.insert("end", error_output)
                details_unsafe.configure(state="disabled")
                scan_button.configure(state="normal", text="🔍 Scan URL")
            app.after(0, update_gui_error)

    threading.Thread(target=process, daemon=True).start()

def scan_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if not file_path:
        return

    def process():
        global last_scan_result_text
        with open(file_path, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]

        # Clear UI for new batch
        app.after(0, lambda: [
            details_unsafe.configure(state="normal"), details_unsafe.delete("1.0", "end"),
            details_safe.configure(state="normal"), details_safe.delete("1.0", "end")
        ])

        all_results = []
        for i, url in enumerate(urls):
            try:
                result = calculate_phishing_score(url, openphish_feed=global_openphish_feed)
                summary = (
                    f"{i+1}. {url} -> {'Phishing' if result['is_phishing'] else 'Safe'} "
                    f"(Score: {result['score']})\n"
                    f"   Reason: {result['details'].get('phishing_reason', 'N/A')}\n"
                )
                
                def update_gui(res=result, s=summary):
                    if res['is_phishing']:
                        details_unsafe.insert("end", s + "\n")
                        verdict_counts["Phishing"] += 1
                    else:
                        details_safe.insert("end", s + "\n")
                        verdict_counts["Safe"] += 1

                app.after(0, update_gui)
                all_results.append(summary)

            except Exception as e:
                error_msg = f"{i+1}. {url} -> Error: {e}\n"
                app.after(0, lambda msg=error_msg: details_unsafe.insert("end", msg))
                all_results.append(error_msg)

        last_scan_result_text = "\n".join(all_results)
        app.after(0, lambda: [
            details_unsafe.configure(state="disabled"),
            details_safe.configure(state="disabled")
        ])

    threading.Thread(target=process, daemon=True).start()

def save_report_to_pdf(content, filename):
    try:
        c = canvas.Canvas(filename, pagesize=letter)
        width, height = letter
        
        y_pos = height - 50
        margin = 40
        line_height = 15

        for line in content.strip().split('\n'):
            if y_pos < margin:
                c.showPage() # Create a new page
                y_pos = height - margin
            
            c.drawString(margin, y_pos, line)
            y_pos -= line_height

        c.save()
        messagebox.showinfo("Success", f"PDF report saved as {filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save PDF: {e}")

def download_pdf():
    if not last_scan_result_text.strip():
        messagebox.showwarning("No Data", "No scan data available to export.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"phishcheck_report_{timestamp}.pdf"
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        initialfile=default_name,
        title="Save Report As"
    )
    if file_path:
        save_report_to_pdf(last_scan_result_text, file_path)

# --- Finalize Left Panel Buttons ---
scan_button = ctk.CTkButton(left_panel, text="🔍 Scan URL", command=scan_url)
scan_button.pack(pady=5)

file_button = ctk.CTkButton(left_panel, text="📂 Scan .txt File", command=scan_file)
file_button.pack(pady=5)

reset_button = ctk.CTkButton(left_panel, text="🔄 Reset", command=reset_fields,
                             fg_color="#888", hover_color="#444")
reset_button.pack(pady=10)

chart_button = ctk.CTkButton(left_panel, text="📊 Show Verdict Chart", command=show_verdict_chart)
chart_button.pack(pady=10)

pdf_button = ctk.CTkButton(left_panel, text="📄 Download as PDF", command=download_pdf)
pdf_button.pack(pady=10)

# --- Theme Switcher ---
ctk.CTkLabel(left_panel, text="Theme", font=("Arial", 14, "bold")).pack(pady=(20, 5))
theme_switch_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
theme_switch_frame.pack(pady=(0, 10))
ctk.CTkButton(theme_switch_frame, text="🌙 Dark", width=100,
              command=lambda: ctk.set_appearance_mode("Dark")).pack(side="left", padx=2)
ctk.CTkButton(theme_switch_frame, text="☀️ Light", width=100,
              command=lambda: ctk.set_appearance_mode("Light")).pack(side="left", padx=2)

# --- Fetch OpenPhish Feed on Startup ---
global_openphish_feed = fetch_openphish_feed()

# --- Run Application ---
if __name__ == "__main__":
    app.mainloop()
