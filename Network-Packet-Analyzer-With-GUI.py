from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import threading

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Packet Sniffer")
        self.master.geometry("600x400")

        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        self.save_button = tk.Button(master, text="Save Packets", command=self.save_packets, state=tk.DISABLED)
        self.save_button.pack(pady=10)

        self.packet_display = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=70, height=15)
        self.packet_display.pack(pady=10)

        self.packet_count_label = tk.Label(master, text="Packets Captured: 0")
        self.packet_count_label.pack(pady=10)

        self.packets = [] 
        self.packet_count = 0
        self.sniffing = False

    def packet_callback(self, packet):
        self.packet_count += 1
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "Others"

            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            self.packet_display.insert(tk.END, f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}\n")
            self.packet_display.see(tk.END) 
            self.packets.append(packet)
        self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.packet_display.delete(1.0, tk.END)
        self.packet_count = 0
        self.packets = []
        threading.Thread(target=self.sniff_packets).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL) 

    def sniff_packets(self):
        sniff(filter="ip", prn=self.packet_callback, store=0, stop_filter=lambda x: not self.sniffing)

    def save_packets(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                                   filetypes=[("PCAP files", "*.pcap"), ("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    for packet in self.packets:
                        f.write(str(packet) + '\n')
                messagebox.showinfo("Success", "Packets saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save packets: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
