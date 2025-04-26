#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import datetime, threading
from tkcalendar import DateEntry
import threat_collection
from port_scanning import scan_target
from file_hashing import compute_hashes
from report_generator import PDFreport_generator

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show)
        self.widget.bind("<Leave>", self.hide)

    def show(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip, text=self.text, background="#ffffe0", relief="solid", borderwidth=1, wraplength=300)
        label.pack()

    def hide(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class HintEntry(tk.Entry):
    def __init__(self, master=None, hint="", **kwargs):
        super().__init__(master, **kwargs)
        self.hint = hint
        self.insert(0, self.hint)
        self.config(fg='grey')
        self.bind("<FocusIn>", self._remove_hint)
        self.bind("<FocusOut>", self._restore_hint)

    def _remove_hint(self, event):
        if self.get() == self.hint:
            self.delete(0, tk.END)
            self.config(fg='black')

    def _restore_hint(self, event):
        if not self.get():
            self.insert(0, self.hint)
            self.config(fg='grey')

    def get_value(self):
        val = self.get()
        return "" if val == self.hint else val

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyThreat")
        self.geometry("1000x600")
        self.configure(bg="#f3f4f6")
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.sidebar = tk.Frame(self, bg="#1F2937", width=200)
        self.sidebar.pack(side="left", fill="y")
        tk.Label(self.sidebar, text="PyThreat", bg="#1F2937", fg="white", font=("Helvetica", 24)).pack(pady=20)
        options = {
            "Threat Search": self.create_threat_search_page,
            "Port Scan": self.create_port_scan_page,
            "File Hash": self.create_file_hash_page,
            "Generate Report": self.create_generate_report_page
        }
        for option, func in options.items():
            tk.Button(self.sidebar, text=option, bg="#1F2937", fg="white", anchor="w", padx=20, pady=15, relief="flat", font=("Helvetica", 14), command=lambda f=func: self.navigate_to(f)).pack(fill="x")
        self.main_content = tk.Frame(self, bg="#f3f4f6")
        self.main_content.pack(side="right", fill="both", expand=True)
        self.create_threat_search_page()

    def navigate_to(self, page_func):
        for widget in self.main_content.winfo_children():
            widget.destroy()
        page_func()

    def _append_result(self, widget, text, clear=False):
        widget.config(state='normal')
        if clear:
            widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.config(state='disabled')
        widget.update()

    def create_threat_search_page(self):
        tk.Label(self.main_content, text="Threat Intelligence Search", bg="#f3f4f6", font=("Helvetica", 20)).pack(pady=20)
        input_frame = tk.Frame(self.main_content, bg="#f3f4f6")
        input_frame.pack(pady=10)
        dropdown_var = tk.StringVar(value="URL")
        dropdown_menu = ttk.Combobox(input_frame, textvariable=dropdown_var, values=["URL", "IP Address", "Hash Value", "Domain Name", "Whois Information", "CVE"], state='readonly')
        dropdown_menu.pack(side="left", padx=5)
        entry = HintEntry(input_frame, hint="Enter a URL to investigate", width=40)
        entry.pack(side="left", padx=5)
        def update_hint(event):
            hint_map = {
                "URL": "Enter a URL to investigate",
                "IP Address": "Enter an IP address to investigate",
                "Hash Value": "Enter a hash value to investigate",
                "Domain Name": "Enter a domain name to investigate",
                "Whois Information": "Enter a domain or IP for Whois information",
                "CVE": "Enter a CVE ID (e.g., CVE-2023-1234)"
            }
            new_hint = hint_map.get(dropdown_var.get(), "")
            entry.hint = new_hint
            entry.delete(0, tk.END)
            entry.insert(0, new_hint)
            entry.config(fg='grey')
        dropdown_menu.bind("<<ComboboxSelected>>", update_hint)
        tk.Button(input_frame, text="Search", bg="#000000", fg="white", padx=10, pady=5, command=lambda: threading.Thread(target=perform_search).start()).pack(side="left", padx=5)
        result_text = scrolledtext.ScrolledText(self.main_content, wrap=tk.WORD, width=80, height=20, state='disabled')
        result_text.pack(pady=10)
        def perform_search():
            query = entry.get_value()
            selected = dropdown_var.get()
            self.main_content.after(0, lambda: self._append_result(result_text, "", clear=True))
            if query:
                if selected == "URL":
                    self.main_content.after(0, lambda: self._append_result(result_text, "Searching URL...\n", clear=True))
                    res = threat_collection.urlhaus_url(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                    res = threat_collection.ipqualityscore_url(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                elif selected == "IP Address":
                    self.main_content.after(0, lambda: self._append_result(result_text, "Searching IP Address...\n", clear=True))
                    res = threat_collection.abuseipdb_ip(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                    res = threat_collection.virustotal_ip(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                    res = threat_collection.threatfox_ip(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                elif selected == "Hash Value":
                    self.main_content.after(0, lambda: self._append_result(result_text, "Searching Hash Value...\n", clear=True))
                    res = threat_collection.virustotal_hash(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                    res = threat_collection.malwarebazaar_hash(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                    res = threat_collection.hybrid_analysis_hash(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                elif selected == "Domain Name":
                    self.main_content.after(0, lambda: self._append_result(result_text, "Searching Domain Name...\n", clear=True))
                    res = threat_collection.virustotal_domain(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                    res = threat_collection.threatfox_domain(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                    res = threat_collection.ipqualityscore_domain(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                elif selected == "Whois Information":
                    self.main_content.after(0, lambda: self._append_result(result_text, "Fetching Whois Information...\n", clear=True))
                    res = threat_collection.whois_info(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                elif selected == "CVE":
                    self.main_content.after(0, lambda: self._append_result(result_text, "Fetching CVE Information...\n", clear=True))
                    res = threat_collection.vulncheck_cve(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
                    res = threat_collection.tenable_cve(query)
                    self.main_content.after(0, lambda: self._append_result(result_text, res + "\n"))
            else:
                self.main_content.after(0, lambda: self._append_result(result_text, "Please enter a valid query.\n", clear=True))

    def create_port_scan_page(self):
        tk.Label(self.main_content, text="Port Scan", bg="#f3f4f6", font=("Helvetica", 20)).pack(pady=20)
        input_frame = tk.Frame(self.main_content, bg="#f3f4f6")
        input_frame.pack(pady=10)
        target_entry = HintEntry(input_frame, hint="Enter a domain name or IP address", width=40)
        target_entry.pack(side="left", padx=5)
        port_entry = HintEntry(input_frame, hint="Enter port range (e.g., 80,443 or 1-1024)", width=50)
        port_entry.pack(side="left", padx=5)
        scan_type_var = tk.StringVar(value="normal")
        scan_type_menu = ttk.Combobox(input_frame, textvariable=scan_type_var, values=["normal", "aggressive"], state='readonly')
        scan_type_menu.pack(side="left", padx=5)
        tk.Button(input_frame, text="Scan", bg="#000000", fg="white", padx=10, pady=5, command=lambda: threading.Thread(target=perform_scan).start()).pack(side="left", padx=5)
        result_text = scrolledtext.ScrolledText(self.main_content, wrap=tk.WORD, width=80, height=20, state='disabled')
        result_text.pack(pady=10)
        def perform_scan():
            target = target_entry.get_value()
            port_range = port_entry.get_value()
            if target:
                self.main_content.after(0, lambda: self._append_result(result_text, f"Searching {target}...\n", clear=True))
                try:
                    scan_results = scan_target(target, scan_type_var.get(), port_range=port_range)
                    self.main_content.after(0, lambda: self._append_result(result_text, scan_results, clear=True))
                except Exception as e:
                    self.main_content.after(0, lambda: self._append_result(result_text, f"Error: {e}\n", clear=True))
            else:
                self.main_content.after(0, lambda: self._append_result(result_text, "Please enter a valid target.\n", clear=True))

    def create_file_hash_page(self):
        tk.Label(self.main_content, text="File Hash Page", bg="#f3f4f6", font=("Helvetica", 20)).pack(pady=20)
        tk.Button(self.main_content, text="Upload File", command=lambda: upload_file(), bg="#000000", fg="white", padx=10, pady=5).pack(pady=10)
        hash_frame = tk.Frame(self.main_content, bg="#f3f4f6")
        hash_frame.pack(pady=10)
        tk.Label(hash_frame, text="MD5:", bg="#f3f4f6").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        md5_hash = tk.Text(hash_frame, wrap=tk.WORD, width=50, height=2, state='disabled')
        md5_hash.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(hash_frame, text="SHA-1:", bg="#f3f4f6").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        sha1_hash = tk.Text(hash_frame, wrap=tk.WORD, width=50, height=2, state='disabled')
        sha1_hash.grid(row=1, column=1, padx=5, pady=5)
        tk.Label(hash_frame, text="SHA-256:", bg="#f3f4f6").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        sha256_hash = tk.Text(hash_frame, wrap=tk.WORD, width=50, height=2, state='disabled')
        sha256_hash.grid(row=2, column=1, padx=5, pady=5)
        tk.Label(hash_frame, text="SHA-512:", bg="#f3f4f6").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        sha512_hash = tk.Text(hash_frame, wrap=tk.WORD, width=50, height=3, state='disabled')
        sha512_hash.grid(row=3, column=1, padx=5, pady=5)
        def upload_file():
            file_path = filedialog.askopenfilename()
            if file_path:
                hashes, error = compute_hashes(file_path)
                if error:
                    messagebox.showerror("Error", error)
                else:
                    for widget, key in zip([md5_hash, sha1_hash, sha256_hash, sha512_hash], ['MD5', 'SHA-1', 'SHA-256', 'SHA-512']):
                        widget.config(state='normal')
                        widget.delete("1.0", tk.END)
                        widget.insert(tk.END, hashes.get(key, ""))
                        widget.config(state='disabled')

    def create_generate_report_page(self):
        main_frame = tk.Frame(self.main_content, bg="#f3f4f6")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        tk.Label(main_frame, text="Generate CTI Report", bg="#f3f4f6", font=("Helvetica", 20)).pack(pady=20)
        entries = {}
        row_frame = tk.Frame(main_frame, bg="#f3f4f6")
        row_frame.pack(fill=tk.X, pady=5)
        label_title = tk.Label(row_frame, text="Report Title:", bg="#f3f4f6", width=15, anchor='w')
        label_title.pack(side=tk.LEFT)
        entry_title = tk.Text(row_frame, height=1, width=60, wrap=tk.WORD)
        entry_title.pack(side=tk.LEFT, padx=5)
        entries["Report Title"] = entry_title
        row_frame = tk.Frame(main_frame, bg="#f3f4f6")
        row_frame.pack(fill=tk.X, pady=5)
        label_number = tk.Label(row_frame, text="Report Number:", bg="#f3f4f6", width=12, anchor='w')
        label_number.pack(side=tk.LEFT)
        entry_number = tk.Text(row_frame, height=1, width=15, wrap=tk.WORD)
        entry_number.pack(side=tk.LEFT, padx=25)
        entries["Report Number"] = entry_number
        hint_label_number = tk.Label(row_frame, text="?", fg="blue", cursor="question_arrow", bg="#f3f4f6")
        hint_label_number.pack(side=tk.LEFT, padx=(1, 0))
        Tooltip(hint_label_number, "Unique report identifier (e.g., CTI-2023-001)")
        label_date = tk.Label(row_frame, text="Report Date:", bg="#f3f4f6", width=12, anchor='w')
        label_date.pack(side=tk.LEFT, padx=(20, 0))
        entry_date = DateEntry(row_frame, width=15, background='darkblue', foreground='white', borderwidth=2, date_pattern='yyyy-mm-dd')
        entry_date.pack(side=tk.LEFT, padx=5)
        entries["Report Date"] = entry_date
        fields = [
            ("Criticality:", "combo", "Low: Regular monitoring\nMedium: Close monitoring\nHigh: Quick action\nCritical: Immediate action", ["Low", "Medium", "High", "Critical"]),
            ("Sensitivity:", "combo", "Traffic Light Protocol\nTLP:CLEAR: No restrictions\nTLP:GREEN: Community sharing\nTLP:AMBER: Need-to-know\nTLP:AMBER+STRICT: Limited sharing\nTLP:RED: Highly restricted", ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]),
            ("Executive Summary:", "text", "Brief overview of key findings and implications"),
            ("Key Points:", "text", "list of critical observations"),
            ("Assessment:", "text", "Detailed technical analysis and conclusions")
        ]
        for field in fields:
            row_frame = tk.Frame(main_frame, bg="#f3f4f6")
            row_frame.pack(fill=tk.X, pady=5)
            label = tk.Label(row_frame, text=field[0], bg="#f3f4f6", width=15, anchor='w')
            label.pack(side=tk.LEFT)
            if field[1] == "text":
                if field[0] in ["Executive Summary:", "Key Points:", "Assessment:"]:
                    entry = scrolledtext.ScrolledText(row_frame, height=6, width=60, wrap=tk.WORD)
                else:
                    entry = tk.Text(row_frame, height=1, width=60, wrap=tk.WORD)
                entry.pack(side=tk.LEFT, padx=5)
            else:
                entry = ttk.Combobox(row_frame, values=field[3], state="readonly", width=58)
                entry.pack(side=tk.LEFT, padx=5)
            if field[0] != "Report Title:":
                hint_label = tk.Label(row_frame, text="?", fg="blue", cursor="question_arrow", bg="#f3f4f6")
                hint_label.pack(side=tk.LEFT)
                Tooltip(hint_label, field[2])
            entries[field[0].replace(":", "").strip()] = entry
        def generate_pdf():
            data = {}
            for key, entry in entries.items():
                if isinstance(entry, tk.Text) or isinstance(entry, scrolledtext.ScrolledText):
                    data[key] = entry.get("1.0", tk.END).strip()
                else:
                    data[key] = entry.get().strip()
            if not data.get("Report Title") or not data.get("Report Number"):
                messagebox.showerror("Error", "Report Title and Number are required fields")
                return
            PDFreport_generator.generate_pdf(data, self.main_content)
        def preview_pdf():
            data = {}
            for key, entry in entries.items():
                if isinstance(entry, tk.Text) or isinstance(entry, scrolledtext.ScrolledText):
                    data[key] = entry.get("1.0", tk.END).strip()
                else:
                    data[key] = entry.get().strip()
            if not data.get("Report Title") or not data.get("Report Number"):
                messagebox.showerror("Error", "Report Title and Number are required fields")
                return
            PDFreport_generator.preview_pdf(data)
        btn_frame = tk.Frame(main_frame, bg="#f3f4f6")
        btn_frame.pack(pady=20)
        tk.Button(btn_frame, text="Preview Report", bg="#000000", fg="white", command=preview_pdf, padx=10, pady=5).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Generate PDF Report", bg="#000000", fg="white", command=generate_pdf, padx=10, pady=5).pack(side=tk.LEFT, padx=5)

if __name__ == "__main__":
    app = App()
    app.mainloop()
