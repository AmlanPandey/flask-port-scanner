from flask import Flask, render_template, request
import socket
import os


app = Flask(__name__, template_folder=os.path.dirname(os.path.abspath(__file__)))

def scan_ports(target, protocol="tcp", scan_type="light"):
    result = []
    ports = []

    if scan_type == "light":
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
    elif scan_type == "deep":
        ports = range(1, 1025)
    elif scan_type == "custom":
        ports = range(1, 100)

    for port in ports:
        try:
            if protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.5)
                sock.sendto(b"", (target, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    result.append(f"UDP {port} OPEN (response)")
                except socket.timeout:
                    pass
            else: 
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((target, port)) == 0:
                    result.append(f"TCP {port} OPEN")
                sock.close()
        except Exception:
            pass
    return result if result else ["No open ports found."]

@app.route("/", methods=["GET", "POST"])
def index():
    scan_result = None
    if request.method == "POST":
        target = request.form["target"]
        scan_type = request.form.get("scan_type", "light")
        protocol = request.form.get("protocol", "tcp")
        scan_result = scan_ports(target, protocol, scan_type)
    return render_template("index.html", result=scan_result)

if __name__ == "__main__":
    app.run(debug=True)
