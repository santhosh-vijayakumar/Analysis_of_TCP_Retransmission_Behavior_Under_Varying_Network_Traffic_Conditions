# TCP Performance Analysis Under Varying Network Traffic Conditions

Blog Post: https://tcpperformanceanalysis.blogspot.com/2026/04/introduction-transmission-control.html

------------------------------------------------------------------------

Project Overview

This project systematically analyzes how TCP performance metrics -
throughput, goodput, retransmission rate, SACK usage, duplicate ACKs,
and out-of-order packets - behave under Normal, Medium, and High
network traffic conditions.

------------------------------------------------------------------------

Full Analysis

The complete blog post with all graphs, inferences, and conclusions
is available at:
https://tcpperformanceanalysis.blogspot.com/2026/04/introduction-transmission-control.html

------------------------------------------------------------------------

Tools Used

- hping3 - Traffic generation
- Wireshark - Packet capture
- Python (pyshark, pandas, matplotlib) - Metrics extraction and visualization

------------------------------------------------------------------------

Repository Structure

data/
    normal_traffic.csv
    mid_traffic.csv
    high_traffic.csv

scripts/
    feature_extractor.py
    graph_generator.py

graphs/
    (30+ scatter plots)

README.md

------------------------------------------------------------------------

Contact

For questions or collaboration, please open an issue in this repository.

------------------------------------------------------------------------

License

MIT License
