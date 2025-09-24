import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from magic_check import MagicCheck
import threading
import queue
import os
from datetime import datetime
from utils import DirectoryScanSummary

class MagicCheckGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MagicCheck - Security Scanner")
        self.root.geometry("800x600")
        
        # Create a queue for thread-safe communication
        self.message_queue = queue.Queue()
        
        # Initialize scanner
        self.scanner = MagicCheck()
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        
        # Create widgets
        self.create_widgets()
        
        # Start queue processing
        self.process_queue()
        
    def create_widgets(self):
        # Scan Type Selection
        ttk.Label(self.main_frame, text="Select Scan Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.scan_type = tk.StringVar(value="file")
        ttk.Radiobutton(self.main_frame, text="Single File", variable=self.scan_type, value="file").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(self.main_frame, text="Directory", variable=self.scan_type, value="directory").grid(row=0, column=2, sticky=tk.W)
        
        # Path Selection
        ttk.Label(self.main_frame, text="Select Path:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(self.main_frame, textvariable=self.path_var)
        self.path_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(self.main_frame, text="Browse", command=self.browse_path).grid(row=1, column=2, sticky=tk.W)
        
        # Report Format Selection
        ttk.Label(self.main_frame, text="Report Format:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.report_format = tk.StringVar(value="none")
        formats = [("Terminal Only", "none"), ("JSON", "json"), ("CSV", "csv"), ("HTML", "html")]
        for i, (text, value) in enumerate(formats):
            ttk.Radiobutton(self.main_frame, text=text, variable=self.report_format, value=value).grid(row=2, column=i+1, sticky=tk.W)
        
        # Start Button
        self.start_button = ttk.Button(self.main_frame, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=3, column=0, columnspan=3, pady=10)
        
        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(self.main_frame, variable=self.progress_var, maximum=100)
        self.progress.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Output Text Area
        self.output_area = scrolledtext.ScrolledText(self.main_frame, height=20, wrap=tk.WORD)
        self.output_area.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Configure tag colors for output
        self.output_area.tag_configure("safe", foreground="green")
        self.output_area.tag_configure("suspicious", foreground="red")
        self.output_area.tag_configure("warning", foreground="orange")
        self.output_area.tag_configure("info", foreground="blue")
        
    def browse_path(self):
        if self.scan_type.get() == "file":
            path = filedialog.askopenfilename(title="Select File")
        else:
            path = filedialog.askdirectory(title="Select Directory")
            
        if path:
            self.path_var.set(path)
            
    def update_output(self, text, tag=None):
        self.output_area.insert(tk.END, text + "\n", tag)
        self.output_area.see(tk.END)
        
    def process_queue(self):
        try:
            while True:
                msg = self.message_queue.get_nowait()
                if isinstance(msg, tuple):
                    text, tag = msg
                    self.update_output(text, tag)
                else:
                    self.update_output(msg)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)
            
    def start_scan(self):
        if not self.path_var.get():
            self.update_output("Please select a path first!", "warning")
            return
            
        # Clear output area
        self.output_area.delete(1.0, tk.END)
        
        # Disable start button
        self.start_button.state(['disabled'])
        
        # Reset progress
        self.progress_var.set(0)
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()
        
    def run_scan(self):
        try:
            path = self.path_var.get()
            self.status_var.set("Scanning...")
            
            # Print header
            self.message_queue.put(("MagicCheck Security Scanner", "info"))
            self.message_queue.put(("=" * 50, "info"))
            self.message_queue.put("")
            
            if self.scan_type.get() == "file":
                result = self.scanner.check_file(path)
                if result:
                    self.message_queue.put(("File Analysis Results:", "info"))
                    self.message_queue.put(("-" * 30,))
                    self.message_queue.put((f"Filename: {result['filename']}",))
                    self.message_queue.put((f"Type: {result['actual_type']}",))
                    self.message_queue.put((f"Size: {result['filesize']:,} bytes",))
                    self.message_queue.put((f"Risk Level: {result['risk_level']}", 
                                          "suspicious" if result['risk_level'] != 'Safe' else "safe"))
                    
                    if result.get('reasons'):
                        self.message_queue.put(("\nFindings:",))
                        for reason in result['reasons']:
                            tag = "suspicious" if "ALERT" in reason else "warning"
                            self.message_queue.put((f"- {reason}", tag))
            else:
                results = self.scanner.scan_directory(path)
                
                # Save report if requested
                if self.report_format.get() != "none":
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    base_path = os.path.join(os.getcwd(), f"magiccheck_report_{timestamp}")
                    
                    if self.report_format.get() == "json":
                        from utils import ReportExporter
                        ReportExporter.to_json(results, base_path + ".json")
                        self.message_queue.put((f"\nJSON report saved to: {base_path}.json", "info"))
                    elif self.report_format.get() == "csv":
                        from utils import ReportExporter
                        ReportExporter.to_csv(results, base_path + ".csv")
                        self.message_queue.put((f"\nCSV report saved to: {base_path}.csv", "info"))
                    elif self.report_format.get() == "html":
                        from utils import ReportExporter
                        ReportExporter.to_html(results, base_path + ".html")
                        self.message_queue.put((f"\nHTML report saved to: {base_path}.html", "info"))
                
        except Exception as e:
            self.message_queue.put((f"Error: {str(e)}", "suspicious"))
            
        finally:
            self.status_var.set("Ready")
            self.start_button.state(['!disabled'])
            self.progress_var.set(100)

def main():
    root = tk.Tk()
    app = MagicCheckGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
