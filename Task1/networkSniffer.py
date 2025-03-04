import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
from collections import defaultdict, deque
from datetime import datetime, timedelta
import socket
import dns.resolver
from matplotlib.figure import Figure
import numpy as np
import sys
import psutil

class NetworkAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        
        # Cross-platform window maximizing
        if sys.platform.startswith('win'):
            self.root.state('zoomed')
        else:
            self.root.attributes('-zoomed', True)

        # Variables
        self.packet_count = 0
        self.is_capturing = False
        self.bandwidth_data = {'time': [], 'in_bytes': [], 'out_bytes': []}
        self.dns_cache = {}
        self.start_time = time.time()
        self.total_bytes_in = 0
        self.total_bytes_out = 0
        self.bandwidth_history = {
            'download': deque(maxlen=60),
            'upload': deque(maxlen=60),
            'timestamps': deque(maxlen=60)
        }
        self.speed_history = {
            'download': deque(maxlen=10),
            'upload': deque(maxlen=10)
        }
        self.last_bytes = {
            'download': 0,
            'upload': 0
        }
        self.peak_speeds = {
            'download': 0,
            'upload': 0
        }
        self.protocol_counts = defaultdict(int)
        self.port_activity = defaultdict(int)
        self.active_connections = set()
        self.update_interval = 1000  # 1 second
        self.max_points = 60  # 1 minute of data

        self.create_gui()
        self.setup_graphs()
        self.update_bandwidth_periodic()

    def create_gui(self):
        # Main container with equal padding
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Control buttons
        control_frame = ttk.Frame(main_container)
        control_frame.pack(fill=tk.X, pady=(0, 5))

        # Add Start/Stop buttons
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.stop_button['state'] = 'disabled'

        # Add Save and Open buttons
        self.save_button = ttk.Button(control_frame, text="Save Capture", command=self.save_capture)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        self.open_button = ttk.Button(control_frame, text="Open Capture", command=self.open_capture)
        self.open_button.pack(side=tk.LEFT, padx=5)

        # Create PanedWindow for vertical split
        self.main_paned = ttk.PanedWindow(main_container, orient=tk.VERTICAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True)

        # Create PanedWindow for top horizontal split
        self.top_paned = ttk.PanedWindow(orient=tk.HORIZONTAL)
        self.main_paned.add(self.top_paned, weight=1)

        # Create PanedWindow for bottom horizontal split
        self.bottom_paned = ttk.PanedWindow(orient=tk.HORIZONTAL)
        self.main_paned.add(self.bottom_paned, weight=1)

        # Packet Details (Top Left)
        packet_frame = ttk.LabelFrame(self.top_paned, text="Packet Details")
        self.top_paned.add(packet_frame, weight=1)

        # Bandwidth Monitor (Top Right)
        self.bandwidth_frame = ttk.LabelFrame(self.top_paned, text="Network Activity")
        self.top_paned.add(self.bandwidth_frame, weight=1)

        # Network Stats (Bottom Left)
        stats_frame = ttk.LabelFrame(self.bottom_paned, text="Network Statistics")
        self.bottom_paned.add(stats_frame, weight=1)

        # Create notebook for statistics visualizations
        self.stats_notebook = ttk.Notebook(stats_frame)
        self.stats_notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Text stats tab
        self.stats_text = scrolledtext.ScrolledText(self.stats_notebook, 
                                                  height=15,
                                                  font=('Consolas', 10))
        self.stats_notebook.add(self.stats_text, text="Text Stats")

        # Charts tab
        self.charts_frame = ttk.Frame(self.stats_notebook)
        self.stats_notebook.add(self.charts_frame, text="Charts")

        # DNS Resolution (Bottom Right)
        dns_frame = ttk.LabelFrame(self.bottom_paned, text="DNS Resolution")
        self.bottom_paned.add(dns_frame, weight=1)

        self.packet_text = scrolledtext.ScrolledText(packet_frame, 
                                                   height=15,
                                                   font=('Consolas', 10))
        self.packet_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        self.dns_text = scrolledtext.ScrolledText(dns_frame,
                                                height=15,
                                                font=('Consolas', 10))
        self.dns_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

    def setup_graphs(self):
        # Bandwidth Graph
        self.bandwidth_fig = Figure(figsize=(6, 4), dpi=100)
        self.bandwidth_ax = self.bandwidth_fig.add_subplot(111)
        
        # Configure plot style for better responsiveness
        self.bandwidth_fig.set_tight_layout(True)
        self.bandwidth_ax.set_facecolor('#f8f9fa')
        self.bandwidth_fig.patch.set_facecolor('#ffffff')
        
        # Initialize empty lines with smaller window for more sensitivity
        self.max_points = 30  # 30 seconds for more sensitive display
        self.line_down, = self.bandwidth_ax.plot([], [], 
                                               color='#2ecc71', 
                                               linewidth=2, 
                                               label='Download')
        self.line_up, = self.bandwidth_ax.plot([], [], 
                                             color='#e74c3c', 
                                             linewidth=2, 
                                             label='Upload')
        
        # Configure bandwidth graph
        self.bandwidth_ax.set_xlabel('Time (s)')
        self.bandwidth_ax.set_ylabel('Speed (MB/s)')
        self.bandwidth_ax.set_title('Network Bandwidth')
        self.bandwidth_ax.grid(True, linestyle='--', alpha=0.7)
        self.bandwidth_ax.legend()

        # Create canvas for bandwidth graph
        self.bandwidth_canvas = FigureCanvasTkAgg(self.bandwidth_fig, self.bandwidth_frame)
        self.bandwidth_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Statistics Charts
        self.stats_fig = Figure(figsize=(6, 4), dpi=100)
        self.stats_fig.set_tight_layout(True)
        
        # Protocol distribution pie chart
        self.proto_ax = self.stats_fig.add_subplot(121)
        self.proto_ax.set_title('Protocol Distribution')
        
        # Port activity bar chart
        self.port_ax = self.stats_fig.add_subplot(122)
        self.port_ax.set_title('Top Ports Activity')
        
        self.stats_canvas = FigureCanvasTkAgg(self.stats_fig, self.charts_frame)
        self.stats_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def packet_callback(self, packet):
        if not self.is_capturing:
            return

        self.packet_count += 1
        current_time = time.time() - self.start_time

        if IP in packet:
            # Process bandwidth
            packet_size = len(packet)
            if packet[IP].dst == get_if_addr(conf.iface):
                self.total_bytes_in += packet_size
                self.bandwidth_data['in_bytes'].append(packet_size)
            else:
                self.total_bytes_out += packet_size
                self.bandwidth_data['out_bytes'].append(packet_size)

            self.bandwidth_data['time'].append(current_time)

            # Keep last 100 points
            window_size = 100
            if len(self.bandwidth_data['time']) > window_size:
                self.bandwidth_data['time'] = self.bandwidth_data['time'][-window_size:]
                self.bandwidth_data['in_bytes'] = self.bandwidth_data['in_bytes'][-window_size:]
                self.bandwidth_data['out_bytes'] = self.bandwidth_data['out_bytes'][-window_size:]

            # Process packet details
            packet_info = self.process_packet(packet)
            self.root.after(0, self.update_gui, packet_info)

    def process_packet(self, packet):
        packet_info = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "protocol": "Unknown",
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "length": len(packet)
        }

        # Update protocol statistics
        if TCP in packet:
            packet_info["protocol"] = f"TCP {packet[TCP].sport} → {packet[TCP].dport}"
            self.protocol_counts["TCP"] += 1
            self.port_activity[f"TCP/{packet[TCP].dport}"] += 1
            self.active_connections.add((packet[IP].src, packet[IP].dst, 'TCP'))
        elif UDP in packet:
            packet_info["protocol"] = f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
            self.protocol_counts["UDP"] += 1
            self.port_activity[f"UDP/{packet[UDP].dport}"] += 1
            self.active_connections.add((packet[IP].src, packet[IP].dst, 'UDP'))
        if DNS in packet:
            packet_info["protocol"] = "DNS"
            self.protocol_counts["DNS"] += 1

        # Resolve DNS
        self.resolve_dns(packet_info["src"])
        self.resolve_dns(packet_info["dst"])

        return packet_info

    def resolve_dns(self, ip):
        if ip not in self.dns_cache:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.dns_cache[ip] = hostname
                self.dns_text.insert(tk.END, f"{ip} → {hostname}\n")
                self.dns_text.see(tk.END)
            except:
                self.dns_cache[ip] = ip

    def update_gui(self, packet_info):
        # Update packet details
        self.packet_text.insert(tk.END, 
                              f"[{packet_info['timestamp']}] {packet_info['protocol']}: "
                              f"{packet_info['src']} → {packet_info['dst']} "
                              f"({packet_info['length']} bytes)\n")
        self.packet_text.see(tk.END)

        # Update network statistics
        self.update_stats()

        # Update bandwidth graph
        self.update_bandwidth_graph()

    def update_stats(self):
        stats = (
            f"Total Packets: {self.packet_count}\n"
            f"Total Download: {self.total_bytes_in/1024:.2f} KB\n"
            f"Total Upload: {self.total_bytes_out/1024:.2f} KB\n"
            f"Active Time: {time.time() - self.start_time:.1f} seconds\n"
        )
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats)

    def update_bandwidth_graph(self):
        if len(self.bandwidth_history['timestamps']) > 1:
            times = list(self.bandwidth_history['timestamps'])
            start_time = times[0]
            times = [t - start_time for t in times]
            
            down_speeds = [s/1024/1024 for s in self.bandwidth_history['download']]  # Convert to MB/s
            up_speeds = [s/1024/1024 for s in self.bandwidth_history['upload']]      # Convert to MB/s
            
            self.line_down.set_data(times, down_speeds)
            self.line_up.set_data(times, up_speeds)
            
            # Adjust axes
            self.bandwidth_ax.set_xlim(max(0, times[-1] - 30), times[-1] + 1)  # Show last 30 seconds
            max_speed = max(max(down_speeds + up_speeds, default=1), 1)
            self.bandwidth_ax.set_ylim(0, max_speed * 1.2)
            
            # Force redraw
            self.bandwidth_canvas.draw_idle()

    def start_capture(self):
        try:
            self.is_capturing = True
            self.start_button['state'] = 'disabled'
            self.stop_button['state'] = 'normal'
            self.start_time = time.time()
            
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {str(e)}")

    def stop_capture(self):
        self.is_capturing = False
        self.start_button['state'] = 'normal'
        self.stop_button['state'] = 'disabled'

    def capture_packets(self):
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda _: not self.is_capturing)

    def format_speed(self, bytes_per_sec):
        """Format speed in human readable format"""
        if bytes_per_sec >= 1024*1024*1024:
            return f"{bytes_per_sec/(1024*1024*1024):.2f} GB/s"
        elif bytes_per_sec >= 1024*1024:
            return f"{bytes_per_sec/(1024*1024):.2f} MB/s"
        elif bytes_per_sec >= 1024:
            return f"{bytes_per_sec/1024:.2f} KB/s"
        else:
            return f"{bytes_per_sec:.2f} B/s"

    def update_bandwidth_periodic(self):
        if self.is_capturing:
            net_io = psutil.net_io_counters()
            current_time = time.time()
            
            # Calculate speeds
            if self.last_bytes['download'] > 0:
                download_speed = (net_io.bytes_recv - self.last_bytes['download']) / self.update_interval * 1000
                upload_speed = (net_io.bytes_sent - self.last_bytes['upload']) / self.update_interval * 1000
                
                # Update peak speeds
                self.peak_speeds['download'] = max(self.peak_speeds['download'], download_speed)
                self.peak_speeds['upload'] = max(self.peak_speeds['upload'], upload_speed)
                
                # Add to history
                self.bandwidth_history['download'].append(download_speed)
                self.bandwidth_history['upload'].append(upload_speed)
                self.bandwidth_history['timestamps'].append(current_time)
                
                # Update speed history for averages
                self.speed_history['download'].append(download_speed)
                self.speed_history['upload'].append(upload_speed)
                
                # Update graph
                self.update_bandwidth_graph()
            
            self.last_bytes['download'] = net_io.bytes_recv
            self.last_bytes['upload'] = net_io.bytes_sent
            
            # Update statistics
            self.update_network_stats(net_io)
            
            # Update the charts every second
            self.update_stats_charts()
        
        self.root.after(self.update_interval, self.update_bandwidth_periodic)

    def update_network_stats(self, net_io):
        current_time = datetime.now()
        uptime = str(timedelta(seconds=int(time.time() - self.start_time)))
        
        # Calculate speeds and averages
        current_download = self.speed_history['download'][-1] if self.speed_history['download'] else 0
        current_upload = self.speed_history['upload'][-1] if self.speed_history['upload'] else 0
        avg_download = sum(self.speed_history['download']) / len(self.speed_history['download']) if self.speed_history['download'] else 0
        avg_upload = sum(self.speed_history['upload']) / len(self.speed_history['upload']) if self.speed_history['upload'] else 0
        
        # Get CPU and memory usage for network-related processes
        network_processes = self.get_network_processes()
        
        stats = (
            f"═══════════ Network Monitor Statistics ═══════════\n\n"
            f"📊 Session Information:\n"
            f"   • Capture Duration: {uptime}\n"
            f"   • Total Packets: {self.packet_count:,}\n"
            f"   • Active Connections: {len(self.active_connections)}\n\n"
            
            f"📈 Current Traffic:\n"
            f"   Download:\n"
            f"   • Current: {self.format_speed(current_download)}\n"
            f"   • Average: {self.format_speed(avg_download)}\n"
            f"   • Peak: {self.format_speed(self.peak_speeds['download'])}\n"
            f"   • Total: {self.format_bytes(net_io.bytes_recv)}\n\n"
            
            f"   Upload:\n"
            f"   • Current: {self.format_speed(current_upload)}\n"
            f"   • Average: {self.format_speed(avg_upload)}\n"
            f"   • Peak: {self.format_speed(self.peak_speeds['upload'])}\n"
            f"   • Total: {self.format_bytes(net_io.bytes_sent)}\n\n"
            
            f"📦 Packet Statistics:\n"
            f"   • Packets Received: {net_io.packets_recv:,}\n"
            f"   • Packets Sent: {net_io.packets_sent:,}\n"
            f"   • Errors (In/Out): {net_io.errin:,}/{net_io.errout:,}\n"
            f"   • Drops (In/Out): {net_io.dropin:,}/{net_io.dropout:,}\n\n"
            
            f"🔍 Protocol Distribution:\n"
            f"   " + "\n   ".join(f"• {proto}: {count}" 
                                 for proto, count in self.protocol_counts.items()) + "\n\n"
            
            f"👀 Top Network Processes:\n"
            f"   " + "\n   ".join(f"• {proc}" for proc in network_processes[:5]) + "\n\n"
            
            f"🔄 Last Updated: {current_time.strftime('%H:%M:%S')}"
        )
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats)

    def get_network_processes(self):
        """Get list of processes with network activity"""
        processes = []
        for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
            try:
                if proc.connections():
                    processes.append(f"{proc.name():<20} "
                                  f"(CPU: {proc.cpu_percent()}%, "
                                  f"Mem: {proc.memory_percent():.1f}%)")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(processes, reverse=True)

    def format_bytes(self, bytes):
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} PB"

    def update_stats_charts(self):
        # Clear previous charts
        self.proto_ax.clear()
        self.port_ax.clear()
        
        # Update protocol distribution pie chart
        if self.protocol_counts:
            protocols = list(self.protocol_counts.keys())
            counts = list(self.protocol_counts.values())
            self.proto_ax.pie(counts, labels=protocols, autopct='%1.1f%%')
            self.proto_ax.set_title('Protocol Distribution')

        # Update port activity bar chart
        if self.port_activity:
            # Get top 5 ports
            top_ports = sorted(self.port_activity.items(), 
                             key=lambda x: x[1], 
                             reverse=True)[:5]
            ports, activities = zip(*top_ports)
            
            y_pos = np.arange(len(ports))
            self.port_ax.barh(y_pos, activities)
            self.port_ax.set_yticks(y_pos)
            self.port_ax.set_yticklabels(ports)
            self.port_ax.set_title('Top Ports Activity')
            
        self.stats_fig.tight_layout()
        self.stats_canvas.draw()

    def save_capture(self):
        if not self.is_capturing:
            filename = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
            )
            if filename:
                try:
                    wrpcap(filename, self.packets)
                    messagebox.showinfo("Success", "Capture saved successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save capture: {str(e)}")

    def open_capture(self):
        filename = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if filename:
            try:
                # Stop current capture if running
                if self.is_capturing:
                    self.stop_capture()
                
                # Clear current data
                self.packet_count = 0
                self.total_bytes_in = 0
                self.total_bytes_out = 0
                self.protocol_counts.clear()
                self.port_activity.clear()
                self.active_connections.clear()
                
                # Read and process packets from file
                packets = rdpcap(filename)
                for packet in packets:
                    self.packet_callback(packet)
                
                messagebox.showinfo("Success", f"Loaded {len(packets)} packets from file!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open capture: {str(e)}")

def main():
    root = tk.Tk()
    app = NetworkAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main() 