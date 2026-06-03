import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import time

import sys
import os

# Add root directory to sys.path so this file can be run directly
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from app.validator import validate_password
from app.generator import generate_password
from app.utils.exporter import export_to_pdf
from app.utils.logger import log_audit

# Configure CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class SOCDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Sentinel Password Analyzer - SOC Dashboard")
        self.geometry("900x700")
        self.minsize(800, 600)
        
        # Cyberpunk / SOC Theme colors
        self.bg_color = "#0a0a0a"
        self.panel_color = "#151515"
        self.accent_color = "#00ffcc" # Neon Cyan
        self.text_color = "#e0e0e0"
        
        self.configure(fg_color=self.bg_color)
        
        # Current analysis results
        self.current_results = None
        
        self._setup_ui()
        
    def _setup_ui(self):
        # Main Layout: 2 Columns
        self.grid_columnconfigure(0, weight=2)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # --- LEFT COLUMN (Analyzer & Logs) ---
        left_frame = ctk.CTkFrame(self, fg_color="transparent")
        left_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        left_frame.grid_rowconfigure(2, weight=1)
        
        # Header
        header_lbl = ctk.CTkLabel(left_frame, text="TERMINAL UPLINK // PASSWORD AUDIT", 
                                  font=("Courier", 20, "bold"), text_color=self.accent_color)
        header_lbl.grid(row=0, column=0, pady=(0, 20), sticky="w")
        
        # Input Section
        input_panel = ctk.CTkFrame(left_frame, fg_color=self.panel_color, corner_radius=10)
        input_panel.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self.on_password_change)
        
        self.pass_entry = ctk.CTkEntry(input_panel, textvariable=self.password_var, show="*",
                                       font=("Courier", 16), width=400, height=45,
                                       placeholder_text="Enter payload...",
                                       border_color="#333333", text_color=self.accent_color)
        self.pass_entry.pack(padx=20, pady=20, side="left", fill="x", expand=True)
        
        self.show_btn = ctk.CTkButton(input_panel, text="👁", width=45, height=45,
                                      fg_color="#222222", hover_color="#333333",
                                      command=self.toggle_password)
        self.show_btn.pack(padx=(0, 20), pady=20, side="right")
        
        # Terminal Logs
        log_panel = ctk.CTkFrame(left_frame, fg_color=self.panel_color, corner_radius=10)
        log_panel.grid(row=2, column=0, sticky="nsew")
        log_panel.grid_rowconfigure(1, weight=1)
        log_panel.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(log_panel, text="> SYSTEM_LOGS", font=("Courier", 14, "bold"), text_color="#aaaaaa").grid(row=0, column=0, sticky="w", padx=15, pady=10)
        
        self.log_text = ctk.CTkTextbox(log_panel, font=("Courier", 12), fg_color="#0d0d0d", 
                                       text_color="#00ff00", wrap="word")
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        self.log_text.insert("0.0", "Initializing connection...\nConnected to local validator.\nWaiting for input...\n")
        self.log_text.configure(state="disabled")
        
        # Actions
        action_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        action_frame.grid(row=3, column=0, sticky="ew", pady=(20, 0))
        
        self.export_btn = ctk.CTkButton(action_frame, text="EXPORT PDF REPORT", 
                                        font=("Courier", 12, "bold"),
                                        fg_color="transparent", border_width=2,
                                        border_color=self.accent_color, text_color=self.accent_color,
                                        hover_color="#004d40", command=self.export_report)
        self.export_btn.pack(side="left", padx=(0, 10))
        
        # --- RIGHT COLUMN (Metrics & Generator) ---
        right_frame = ctk.CTkFrame(self, fg_color="transparent")
        right_frame.grid(row=0, column=1, padx=(0, 20), pady=20, sticky="nsew")
        
        # Metrics Panel
        metrics_panel = ctk.CTkFrame(right_frame, fg_color=self.panel_color, corner_radius=10)
        metrics_panel.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(metrics_panel, text="TELEMETRY", font=("Courier", 14, "bold"), text_color="#aaaaaa").pack(anchor="w", padx=15, pady=10)
        
        self.strength_lbl = ctk.CTkLabel(metrics_panel, text="STRENGTH: NONE", font=("Courier", 18, "bold"))
        self.strength_lbl.pack(pady=(0, 5))
        
        self.progress_bar = ctk.CTkProgressBar(metrics_panel, width=200, height=15, progress_color="#666666")
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=(0, 15))
        
        self.entropy_lbl = ctk.CTkLabel(metrics_panel, text="ENTROPY: 0.0 bits", font=("Courier", 12))
        self.entropy_lbl.pack()
        
        self.crack_lbl = ctk.CTkLabel(metrics_panel, text="CRACK TIME: N/A", font=("Courier", 12))
        self.crack_lbl.pack(pady=(0, 15))
        
        # Generator Panel
        gen_panel = ctk.CTkFrame(right_frame, fg_color=self.panel_color, corner_radius=10)
        gen_panel.pack(fill="x")
        
        ctk.CTkLabel(gen_panel, text="SECURE GENERATOR", font=("Courier", 14, "bold"), text_color="#aaaaaa").pack(anchor="w", padx=15, pady=10)
        
        self.len_var = tk.IntVar(value=16)
        len_frame = ctk.CTkFrame(gen_panel, fg_color="transparent")
        len_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(len_frame, text="Length:", font=("Courier", 12)).pack(side="left")
        self.len_slider = ctk.CTkSlider(len_frame, from_=8, to=64, variable=self.len_var, command=self.update_len_lbl)
        self.len_slider.pack(side="left", fill="x", expand=True, padx=10)
        self.len_lbl = ctk.CTkLabel(len_frame, text="16", font=("Courier", 12))
        self.len_lbl.pack(side="right")
        
        self.chk_upper = ctk.CTkCheckBox(gen_panel, text="Uppercase (A-Z)", font=("Courier", 12))
        self.chk_upper.select()
        self.chk_upper.pack(anchor="w", padx=15, pady=5)
        
        self.chk_lower = ctk.CTkCheckBox(gen_panel, text="Lowercase (a-z)", font=("Courier", 12))
        self.chk_lower.select()
        self.chk_lower.pack(anchor="w", padx=15, pady=5)
        
        self.chk_num = ctk.CTkCheckBox(gen_panel, text="Numbers (0-9)", font=("Courier", 12))
        self.chk_num.select()
        self.chk_num.pack(anchor="w", padx=15, pady=5)
        
        self.chk_sym = ctk.CTkCheckBox(gen_panel, text="Symbols (!@#$)", font=("Courier", 12))
        self.chk_sym.select()
        self.chk_sym.pack(anchor="w", padx=15, pady=5)
        
        self.gen_btn = ctk.CTkButton(gen_panel, text="GENERATE & COPY", font=("Courier", 12, "bold"),
                                     fg_color="#0066cc", hover_color="#004c99", command=self.generate_and_copy)
        self.gen_btn.pack(pady=15, padx=15, fill="x")
        
    def update_len_lbl(self, val):
        self.len_lbl.configure(text=str(int(val)))
        
    def toggle_password(self):
        current = self.pass_entry.cget("show")
        if current == "*":
            self.pass_entry.configure(show="")
            self.show_btn.configure(text="🔒")
        else:
            self.pass_entry.configure(show="*")
            self.show_btn.configure(text="👁")
            
    def on_password_change(self, *args):
        password = self.password_var.get()
        results = validate_password(password)
        self.current_results = results
        
        # Update Metrics
        self.strength_lbl.configure(text=f"STRENGTH: {results['strength'].upper()}", text_color=results['color'])
        self.entropy_lbl.configure(text=f"ENTROPY: {results['entropy']} bits")
        self.crack_lbl.configure(text=f"CRACK TIME: {results['crack_time']['display']}")
        
        # Animate progress bar (simple implementation)
        target_val = results['score'] / 5.0
        self.progress_bar.set(target_val)
        self.progress_bar.configure(progress_color=results['color'])
        
        # Update Terminal
        self.log_text.configure(state="normal")
        self.log_text.delete("0.0", "end")
        self.log_text.insert("end", f"> Analyzing payload...\n")
        self.log_text.insert("end", f"> Length: {len(password)}\n")
        for f in results['feedback']:
            self.log_text.insert("end", f"  {f}\n")
        self.log_text.insert("end", f"> STATUS: {results['strength']}\n")
        self.log_text.configure(state="disabled")
        
        # Log to file if length > 0
        if len(password) > 0:
            log_audit(results)
            
    def generate_and_copy(self):
        length = int(self.len_var.get())
        use_upper = self.chk_upper.get() == 1
        use_lower = self.chk_lower.get() == 1
        use_num = self.chk_num.get() == 1
        use_sym = self.chk_sym.get() == 1
        
        if not (use_upper or use_lower or use_num or use_sym):
            messagebox.showwarning("Warning", "Select at least one character type.")
            return
            
        new_pass = generate_password(length, use_upper, use_lower, use_num, use_sym)
        self.password_var.set(new_pass)
        
        # Copy to clipboard
        self.clipboard_clear()
        self.clipboard_append(new_pass)
        
        # Update terminal
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"\n> SYSTEM: Generated new payload ({length} chars)\n> Copied to clipboard.\n")
        self.log_text.configure(state="disabled")
        
    def export_report(self):
        if not self.current_results or not self.password_var.get():
            messagebox.showinfo("Info", "No data to export.")
            return
            
        filepath = filedialog.asksaveasfilename(defaultextension=".pdf", 
                                                filetypes=[("PDF files", "*.pdf")],
                                                title="Save Audit Report")
        if filepath:
            export_to_pdf(self.password_var.get(), self.current_results, filepath)
            messagebox.showinfo("Success", f"Report saved to:\n{filepath}")
