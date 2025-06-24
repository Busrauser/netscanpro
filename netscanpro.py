import socket
import csv
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import smtplib
from email.message import EmailMessage
import requests

open_ports = []


def scan_ports(ip, output_box):
    global open_ports
    open_ports = []
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"Scanning target: {ip}...\n")

    for port in range(20, 1025):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                open_ports.append({"port": port, "service": service})
                output_box.insert(tk.END, f"🔓 Port {port} open ({service})\n")
            s.close()
        except Exception as e:
            output_box.insert(tk.END, f"Error: {e}\n")

    if not open_ports:
        output_box.insert(tk.END, "No open ports found.\n")


def export_results():
    if not open_ports:
        messagebox.showwarning("Warning", "You need to perform a scan first.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file_path:
        with open(file_path, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["port", "service"])
            writer.writeheader()
            writer.writerows(open_ports)
        messagebox.showinfo("Saved", "Results successfully saved.")


def send_email_with_results(sender_email, app_password, receiver_email, file_path):
    try:
        msg = EmailMessage()
        msg["Subject"] = "NetScanPro Scan Results"
        msg["From"] = sender_email
        msg["To"] = receiver_email
        msg.set_content("Attached are the scan results.")

        with open(file_path, "rb") as f:
            file_data = f.read()
            filename = file_path.split("/")[-1]
            msg.add_attachment(file_data, maintype="application", subtype="octet-stream", filename=filename)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)

        messagebox.showinfo("Email", "Email sent successfully!")
    except Exception as e:
        messagebox.showerror("Email Error", f"An error occurred:\n{str(e)}")

def send_email_prompt():
    if not open_ports:
        messagebox.showwarning("Warning", "You need to perform a scan first.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file_path:
        with open(file_path, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["port", "service"])
            writer.writeheader()
            writer.writerows(open_ports)

        sender = simple_prompt("Sender Gmail Address:")
        password = simple_prompt("App Password:")
        receiver = simple_prompt("Receiver Email:")

        if sender and password and receiver:
            send_email_with_results(sender, password, receiver, file_path)

def simple_prompt(label_text):
    popup = tk.Toplevel(app)
    popup.title(label_text)
    tk.Label(popup, text=label_text).pack()
    entry = tk.Entry(popup, show="*" if "Password" in label_text else "")
    entry.pack()
    result = []

    def get_value():
        result.append(entry.get())
        popup.destroy()

    tk.Button(popup, text="OK", command=get_value).pack()
    popup.wait_window()
    return result[0] if result else None


def get_ip_location(ip, output_box):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            location_info = (
                f"\n🌍 IP Location Info:\n"
                f"IP: {data.get('ip', 'N/A')}\n"
                f"City: {data.get('city', 'N/A')}\n"
                f"Region: {data.get('region', 'N/A')}\n"
                f"Country: {data.get('country', 'N/A')}\n"
                f"ISP (Org): {data.get('org', 'N/A')}\n"
                f"Coordinates: {data.get('loc', 'N/A')}\n"
            )
            output_box.insert(tk.END, location_info)
        else:
            output_box.insert(tk.END, f"Could not retrieve info (Status code: {response.status_code})\n")
    except Exception as e:
        output_box.insert(tk.END, f"Error: {e}\n")


def launch_gui():
    global app, ip_entry, output_box

    app = tk.Tk()
    app.title("NetScanPro")

    tk.Label(app, text="Target IP Address:").pack()
    ip_entry = tk.Entry(app)
    ip_entry.pack()

    tk.Button(app, text="Start Scan", command=lambda: scan_ports(ip_entry.get(), output_box)).pack(pady=5)
    tk.Button(app, text="Save Results", command=export_results).pack(pady=5)
    tk.Button(app, text="Send Results via Email", command=send_email_prompt).pack(pady=5)

    
    def fetch_ip_info():
        ip = ip_entry.get()
        if ip:
            output_box.insert(tk.END, "\n🔎 Fetching IP location info...\n")
            get_ip_location(ip, output_box)
        else:
            messagebox.showwarning("Warning", "Please enter a valid IP address.")

    tk.Button(app, text="IP Location Info", command=fetch_ip_info).pack(pady=5)

    output_box = scrolledtext.ScrolledText(app, width=60, height=20)
    output_box.pack(pady=10)

    app.mainloop()


if __name__ == "__main__":
    launch_gui()
