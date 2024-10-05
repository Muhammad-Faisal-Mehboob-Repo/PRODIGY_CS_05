# Network Packet Analyzer with GUI

This repository contains a simple **Packet Sniffer** GUI application built using Python, Scapy, and Tkinter. The tool allows you to capture and view network packets in real-time. You can also save the captured packets to a file for further analysis.

## Features

- **Real-Time Packet Capture**: Captures IP packets using Scapy and displays information like source IP, destination IP, and protocol (TCP, UDP, ICMP, or others).
- **Start/Stop Sniffing**: Provides buttons to start and stop the packet capture process.
- **Save Packets**: After capturing packets, you can save them to a file in `.pcap` or `.txt` format for later use.
- **Simple GUI**: The interface is intuitive, featuring a scrollable text area where packet details are displayed in real-time.

## Requirements

- Python 3.x
- Scapy (`pip install scapy`)
- Tkinter (comes pre-installed with Python on most systems)

## How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/packet-sniffer-app.git
   cd packet-sniffer-app
   ```

2. Install the required dependencies:
   ```bash
   pip install scapy
   ```

3. Run the application:
   ```bash
   python packet_sniffer.py
   ```

## Usage

- **Start Sniffing**: Click the "Start Sniffing" button to begin capturing packets. The captured packets will appear in the scrollable text area.
- **Stop Sniffing**: Click "Stop Sniffing" to halt the packet capture.
- **Save Packets**: After capturing packets, click "Save Packets" to store the captured packets into a file.

## Contributing

Feel free to submit issues or pull requests if you find bugs or have ideas for enhancements.

## License

This project is licensed under the MIT License.
