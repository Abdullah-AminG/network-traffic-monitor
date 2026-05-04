from flask import Flask, jsonify, render_template
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
import threading
import datetime

app = Flask(__name__)
CORS(app)

packets_list = []
is_monitoring = False
sniff_thread = None

PORT_SERVICES = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
    21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
    3306: "MySQL", 8080: "HTTP-ALT", 67: "DHCP", 68: "DHCP",
    123: "NTP", 161: "SNMP", 3389: "RDP", 445: "SMB"
}

def get_service(port):
    return PORT_SERVICES.get(port, f"Port {port}")

def process_packet(packet):
    global packets_list
    if not is_monitoring:
        return
    if IP not in packet:
        return

    proto = ""
    src_port = 0
    dst_port = 0
    service = "Unknown"

    # IP protocol number use karo — Windows par 100% reliable
    ip_proto = packet[IP].proto

    if ip_proto == 1:  # ICMP
        proto = "ICMP"
        service = "ICMP"
    elif ip_proto == 6:  # TCP
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        service = get_service(dst_port)
        if dst_port in (80, 8080) or src_port in (80, 8080):
            proto = "HTTP"
            service = "HTTP"
        elif dst_port == 443 or src_port == 443:
            proto = "HTTP"
            service = "HTTPS"
        else:
            proto = "TCP"
    elif ip_proto == 17:  # UDP
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        service = get_service(dst_port)
    else:
        return

    pkt_data = {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": proto,
        "size": len(packet),
        "src_port": src_port,
        "dst_port": dst_port,
        "service": service
    }
    packets_list.append(pkt_data)

def start_sniffing():
    # conf.iface = automatically sahi interface select karta hai har PC par
    sniff(prn=process_packet, store=False,
          iface=conf.iface,
          stop_filter=lambda x: not is_monitoring)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start", methods=["POST"])
def start():
    global is_monitoring, sniff_thread, packets_list
    if not is_monitoring:
        is_monitoring = True
        packets_list = []
        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
    return jsonify({"status": "started"})

@app.route("/stop", methods=["POST"])
def stop():
    global is_monitoring
    is_monitoring = False
    return jsonify({"status": "stopped"})

@app.route("/packets")
def get_packets():
    return jsonify(packets_list)

@app.route("/stats")
def get_stats():
    total = len(packets_list)
    tcp  = sum(1 for p in packets_list if p["protocol"] == "TCP")
    udp  = sum(1 for p in packets_list if p["protocol"] == "UDP")
    icmp = sum(1 for p in packets_list if p["protocol"] == "ICMP")
    http = sum(1 for p in packets_list if p["protocol"] == "HTTP")
    avg_size = round(sum(p["size"] for p in packets_list) / total, 2) if total > 0 else 0
    return jsonify({
        "total": total,
        "tcp":   tcp,
        "udp":   udp,
        "icmp":  icmp,
        "http":  http,
        "avg_size": avg_size
    })

if __name__ == "__main__":
    app.run(debug=True)