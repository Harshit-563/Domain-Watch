from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP
import tkinter as tk
from tkinter import ttk
import threading, json, math, time, os
from collections import defaultdict, deque
from ipwhois.asn import IPASN
from ipwhois.net import Net
from google import genai  # Latest 2026 SDK
from dotenv import load_dotenv

# --- Initialization ---
load_dotenv()
try:
    from ai_model import ai_predict
except ImportError:
    def ai_predict(features): return "Benign", 0.95

# ---------- Configuration & Theme ----------
BG_DARK = "#0a0a0a"      
BG_PANEL = "#161b22"     
ACCENT_GREEN = "#238636" 
ACCENT_RED = "#da3633"   
TEXT_MAIN = "#c9d1d9"    
WHITELIST_FILE = "dns_whitelist.txt"
FEATURE_NAMES = ["domain_length", "entropy", "digit_ratio", "subdomain_depth", "ttl", "unique_ip_count", "query_rate"]

domain_cache = defaultdict(lambda: {"ips": set(), "timestamps": deque(maxlen=50)})
asn_cache = {}
packet_details = {} 
MAX_ROWS = 100

# ---------- Whitelist Logic (Feedback Loop) ----------
def load_whitelist():
    if not os.path.exists(WHITELIST_FILE): return set()
    with open(WHITELIST_FILE, "r") as f:
        return set(line.strip() for line in f if line.strip())

whitelist = load_whitelist()

def add_to_whitelist(domain):
    if domain not in whitelist:
        whitelist.add(domain)
        with open(WHITELIST_FILE, "a") as f:
            f.write(f"{domain}\n")

# ---------- Logic Engines ----------
def shannon_entropy(data):
    if not data: return 0
    freq = {c: data.count(c) for c in set(data)}
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in freq.values())

def get_explanation(features):
    exps = []
    if features[1] > 4.5: exps.append("HIGH ENTROPY")
    if features[4] < 120 and features[5] > 5: exps.append("IP CHURN")
    if features[2] > 0.3: exps.append("DIGIT DENSITY")
    return " | ".join(exps) if exps else "COMPLEX BEHAVIOR"

def get_asn_diversity(ip_list):
    if not ip_list: return 0
    asns = set()
    for ip in ip_list:
        if ip in asn_cache: asns.add(asn_cache[ip]); continue
        try:
            asn = IPASN(Net(ip)).lookup().get('asn')
            asn_cache[ip] = asn
            asns.add(asn)
        except: pass
    return len(asns) / len(ip_list) if ip_list else 0

def analyze_threat_with_llm(packet_data):
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key: return "API ERROR: Check .env"
    client = genai.Client(api_key=api_key)
    prompt = f"""
    Forensic Scan: {packet_data['query_info']['domain']}. 
    1. Attack: Yes/No? 
    2. Goal: DGA/Fast-Flux/Exfil? 
    3. If No, why did the AI flag it? 
    Answer in exactly 2-3 lines.
    """
    try:
        response = client.models.generate_content(model="gemini-3-flash-preview", contents=prompt)
        return response.text
    except Exception as e: return f"Forensic Offline: {str(e)}"

# ---------- GUI Setup ----------
root = tk.Tk()
root.title("DNS SENTINEL | SOC ANALYZER")
root.geometry("1200x850")
root.configure(bg=BG_DARK)

header = tk.Frame(root, bg=BG_DARK, pady=10)
header.pack(fill="x")
tk.Label(header, text="  DNS SENTINEL", font=("Consolas", 20, "bold"), fg=ACCENT_GREEN, bg=BG_DARK).pack(side="left")

def trigger_llm():
    sel = tree.selection()
    if sel:
        detail_box.insert(tk.END, "\n\n[SYSTEM] FETCHING CLOUD FORENSICS...\n")
        detail_box.insert(tk.END, analyze_threat_with_llm(packet_details[sel[0]]) + "\n")
        detail_box.see(tk.END)

tk.Button(header, text="DEEP ANALYSIS", bg=ACCENT_GREEN, fg="white", font=("Consolas", 9, "bold"), command=trigger_llm).pack(side="right", padx=10)
tk.Label(header, text="STATUS: ACTIVE", font=("Consolas", 9), fg="#8b949e", bg=BG_DARK).pack(side="right")

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background=BG_PANEL, foreground=TEXT_MAIN, fieldbackground=BG_PANEL, rowheight=30, font=("Consolas", 10))
style.configure("Treeview.Heading", background="#21262d", foreground=ACCENT_GREEN, font=("Consolas", 10, "bold"))

tree_frame = tk.Frame(root, bg=BG_DARK)
tree_frame.pack(fill="both", expand=True, padx=10)
cols = ("src", "dst", "query", "ttl", "conf", "status")
tree = ttk.Treeview(tree_frame, columns=cols, show="headings")
for c, t in zip(cols, ("SRC", "DST", "DNS_QUERY", "TTL", "AI_CONF", "STATUS")):
    tree.heading(c, text=t)
    tree.column(c, anchor="center", width=100)
tree.column("query", width=350, anchor="w")
tree.pack(fill="both", expand=True)

tree.tag_configure("malicious", background="#3e1a19", foreground="#ff7b72")
tree.tag_configure("benign", foreground="#3fb950")

detail_box = tk.Text(root, height=12, bg="#0d1117", fg="#79c0ff", font=("Consolas", 10), borderwidth=0, padx=10, pady=10)
detail_box.pack(fill="both", padx=10, pady=10)

# ---------- Right-Click Context Menu ----------
popup_menu = tk.Menu(root, tearoff=0, bg=BG_PANEL, fg=TEXT_MAIN, font=("Consolas", 10))
def mark_false_positive():
    sel = tree.selection()
    if sel:
        item_id = sel[0]
        domain = packet_details[item_id]['query_info']['domain']
        add_to_whitelist(domain)
        tree.item(item_id, tags=("benign",))
        tree.set(item_id, column="status", value="WHITELISTED")
        detail_box.insert(tk.END, f"\n[!] FEEDBACK: {domain} Whitelisted.\n")

popup_menu.add_command(label="Mark as False Positive (Whitelist)", command=mark_false_positive)
tree.bind("<Button-3>", lambda e: tree.identify_row(e.y) and (tree.selection_set(tree.identify_row(e.y)) or popup_menu.tk_popup(e.x_root, e.y_root)))

# ---------- Packet Processing ----------
def parse_dns(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
        query = pkt[DNS].qd.qname.decode().strip(".") if pkt[DNS].qd else "-"
        ttl = pkt[DNS].an.ttl if pkt[DNS].an and hasattr(pkt[DNS].an, "ttl") else 0
        now = time.time()
        
        current_ips = [str(pkt[DNS].an[i].rdata) for i in range(pkt[DNS].ancount) if hasattr(pkt[DNS].an[i], "rdata")]
        for ip in current_ips: domain_cache[query]["ips"].add(ip)
        domain_cache[query]["timestamps"].append(now)

        features = [len(query), shannon_entropy(query), sum(c.isdigit() for c in query)/max(len(query), 1), query.count("."), ttl, len(domain_cache[query]["ips"]), len(domain_cache[query]["timestamps"])]
        ai_label, conf = ai_predict(features)
        div = get_asn_diversity(current_ips)
        
        status, tag = "Benign", "benign"
        if query in whitelist: status = "WHITELISTED"
        elif ai_label != "Benign" and conf > 0.5:
            if ai_label == "Fast-Flux" and div < 0.3: status = "Benign (CDN)"
            else: status, tag = ai_label.upper(), "malicious"

        bar = f"[{'■'*int(conf*10)}{'□'*(10-int(conf*10))}] {int(conf*100)}%"
        item_id = tree.insert("", "end", values=(src, dst, query, ttl, bar, status), tags=(tag,))
        packet_details[item_id] = {"query_info": {"domain": query, "ttl": ttl}, "network_context": {"asn_diversity": round(div, 2)}, "ai_analysis": {"label": ai_label, "confidence": conf, "explanation": get_explanation(features)}}
        if len(tree.get_children()) > MAX_ROWS: tree.delete(tree.get_children()[0])

tree.bind("<<TreeviewSelect>>", lambda e: tree.selection() and (detail_box.delete("1.0", tk.END) or detail_box.insert(tk.END, f">>> INSPECTION: {packet_details[tree.selection()[0]]['query_info']['domain']}\n" + json.dumps(packet_details[tree.selection()[0]], indent=4))))
threading.Thread(target=lambda: sniff(filter="udp port 53", prn=parse_dns, store=False), daemon=True).start()
root.mainloop()