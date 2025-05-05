import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

class WebVulnerabilityScanner:
    def __init__(self, base_url, scan_type, max_pages=50, payloads=None, login_url=None, login_data=None):
        self.base_url     = base_url
        self.scan_type    = scan_type
        self.visited      = set()
        self.to_visit     = deque([base_url])
        self.max_pages    = max_pages
        self.session      = requests.Session()
        self.login_url    = login_url
        self.login_data   = login_data or {}
        self.attempts     = []
        # default payloads and you can use a file or external DB as XSS_scanner Project in my account.
        self.payloads     = payloads or (["<script>alert('XSS')</script>"] if scan_type=='XSS'
                                         else ["' OR '1'='1"])

    def login(self, log_func):
        # optional login
        if not self.login_url or not self.login_data:
            return
        try:
            resp = self.session.post(self.login_url, data=self.login_data, timeout=10)
            log_func(f"[+] Login {'successful' if resp.status_code==200 else 'failed: HTTP ' + str(resp.status_code)}")
        except Exception as e:
            log_func(f"[!] Login exception: {e}")

    def is_valid_url(self, url):
        base_netloc = urlparse(self.base_url).netloc
        full_url    = urljoin(self.base_url, url)
        parsed      = urlparse(full_url)
        return parsed.scheme in ('http','https') and parsed.netloc.endswith(base_netloc)

    def extract_forms(self, soup):
        return soup.find_all("form")

    def get_form_details(self, form, current_url):
        action   = form.get("action") or current_url
        method   = form.get("method", "get").lower()
        form_url = urljoin(current_url, action)
        inputs   = []
        for tag in form.find_all("input"):
            name = tag.get("name")
            if name:
                inputs.append({"name": name, "type": tag.get("type","text"), "value": tag.get("value","")})
        return {"url": form_url, "method": method, "inputs": inputs}

    def test_form(self, form, payload):
        data = { fld["name"]: payload for fld in form["inputs"] }
        try:
            if form["method"]=='post':
                return self.session.post(form["url"], data=data, timeout=10)
            return self.session.get(form["url"], params=data, timeout=10)
        except:
            return None

    def is_vulnerable(self, resp, payload):
        if not resp:
            return False
        text = resp.text.lower()
        if self.scan_type=='XSS':
            return payload.lower() in text
        return (payload.lower() in text or 'sql syntax' in text)

    def extract_links(self, html, current_url):
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for a in soup.find_all('a', href=True):
            url = urljoin(current_url, a['href']).split('#')[0]
            if self.is_valid_url(url): links.add(url)
        return links

    def crawl_and_scan(self, log_func, progress_update=None):
        self.login(log_func)
        count = 0
        log_func(f"[*] Starting {self.scan_type} scan at: {self.base_url}")
        while self.to_visit and count < self.max_pages:
            url = self.to_visit.popleft()
            if url in self.visited: continue
            try:
                resp = self.session.get(url, timeout=10)
                if 'text/html' not in resp.headers.get('Content-Type',''): continue
                self.visited.add(url); count+=1
                log_func(f"[+] Scanning ({count}/{self.max_pages}): {url}")
                if progress_update: progress_update(count)
                soup = BeautifulSoup(resp.text, 'html.parser')
                for form in self.extract_forms(soup):
                    details = self.get_form_details(form, url)
                    for payload in self.payloads:
                        r = self.test_form(details, payload)
                        v = self.is_vulnerable(r, payload)
                        self.attempts.append({
                            'page': url, 'form': details['url'],
                            'method': details['method'], 'payload': payload, 'vulnerable': v
                        })
                        if v:
                            log_func(f"    [VULN] {details['url']} [{details['method'].upper()}] payload={payload}")
                for link in self.extract_links(resp.text, url):
                    if link not in self.visited and link not in self.to_visit:
                        self.to_visit.append(link)
            except Exception as e:
                log_func(f"[-] Error fetching {url}: {e}")

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.geometry("1000x700")
        self.create_ui()

    def create_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill='x')
        ttk.Label(top, text="Target URL:").grid(row=0, column=0)
        self.url_entry = ttk.Entry(top, width=40); self.url_entry.grid(row=0, column=1)
        ttk.Label(top, text="Tester Name:").grid(row=0, column=2)
        self.tester_entry = ttk.Entry(top, width=20); self.tester_entry.grid(row=0, column=3)
        ttk.Label(top, text="Scan Type:").grid(row=1, column=0)
        self.type_combo = ttk.Combobox(top, values=['XSS','SQL'], state='readonly', width=10)
        self.type_combo.set('XSS'); self.type_combo.grid(row=1, column=1)
        ttk.Label(top, text="Max Pages:").grid(row=1, column=2)
        self.max_entry = ttk.Entry(top, width=5); self.max_entry.insert(0,'30'); self.max_entry.grid(row=1, column=3)
        ttk.Button(top, text="Start Scan", command=self.start).grid(row=2, column=0, pady=5)
        ttk.Button(top, text="Save Report", command=self.save_report).grid(row=2, column=1)
        ttk.Label(top, text="Status:").grid(row=2, column=2)
        self.status = ttk.Label(top, text="Idle"); self.status.grid(row=2, column=3)

        self.progress = ttk.Progressbar(self, maximum=100, mode='determinate')
        self.progress.pack(fill='x', padx=10, pady=5)
        self.log = tk.Text(self, height=25); self.log.pack(fill='both', expand=True, padx=10)

    def log_msg(self, msg):
        self.log.insert('end', msg+'\n'); self.log.see('end')

    def update_prog(self,val): self.progress['value']=val

    def start(self):
        url = self.url_entry.get(); tester = self.tester_entry.get()
        stype = self.type_combo.get();
        try: maxp = int(self.max_entry.get())
        except: messagebox.showerror("Error","Max Pages invalid"); return
        if not url or not tester:
            messagebox.showerror("Error","URL and Tester Name required"); return
        self.status.config(text="Running")
        self.progress['value']=0; self.progress['maximum']=maxp
        self.scanner = WebVulnerabilityScanner(url, stype, max_pages=maxp)
        self.start_time = datetime.now()
        self.log.delete('1.0','end')
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        self.scanner.crawl_and_scan(log_func=self.log_msg, progress_update=self.update_prog)
        self.end_time = datetime.now()
        self.status.config(text="Completed")
        messagebox.showinfo("Done", f"Scan complete!\nStart: {self.start_time}\nEnd: {self.end_time}")

    def save_report(self):
        if not hasattr(self,'scanner'): messagebox.showwarning("No Data","Run scan first"); return
        file = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF','*.pdf'),('JSON','*.json'),('Text','*.txt')])
        if not file: return
        ext = file.split('.')[-1].lower()
        # generate simple PDF with header info
        if ext=='pdf':
            c = canvas.Canvas(file, pagesize=letter)
            c.setFont('Helvetica-Bold',14)
            c.drawString(40,750, f"Scan Report - {self.type_combo.get()} Scan")
            c.setFont('Helvetica',12)
            c.drawString(40,730, f"Tester: {self.tester_entry.get()}")
            c.drawString(300,730, f"Start: {self.start_time}")
            c.drawString(40,710, f"End: {self.end_time}")
            y=680
            for a in self.scanner.attempts:
                mark = 'VULN' if a['vulnerable'] else 'FAIL'
                text = f"[{mark}] {a['page']} -> {a['form']} ({a['method']})"
                c.drawString(40,y,text); y-=15
                c.drawString(60,y,f"Payload: {a['payload']}"); y-=20
                if y<50: c.showPage(); y=750
            c.save()
        elif ext=='json':
            with open(file,'w',encoding='utf-8') as f:
                json.dump({
                    'tester': self.tester_entry.get(), 'type': self.type_combo.get(),
                    'start': str(self.start_time),'end': str(self.end_time),
                    'attempts': self.scanner.attempts}, f, indent=2)
        else:
            with open(file,'w',encoding='utf-8') as f:
                f.write(f"Tester: {self.tester_entry.get()}\nType: {self.type_combo.get()}\nStart: {self.start_time}\nEnd: {self.end_time}\n\n")
                for a in self.scanner.attempts:
                    mark='VULN' if a['vulnerable'] else 'FAIL'
                    f.write(f"[{mark}] {a['page']} -> {a['form']} ({a['method']})\n")
                    f.write(f"  Payload: {a['payload']}\n\n")
        messagebox.showinfo("Saved", f"Report saved to {file}")

if __name__=='__main__':
    app = App(); app.mainloop()


