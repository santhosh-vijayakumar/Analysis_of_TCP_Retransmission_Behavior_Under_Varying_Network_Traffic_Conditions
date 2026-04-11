import pyshark
import pandas as pd

# -----------------------------
# Set your PCAP file path here
# -----------------------------
pcap_file = r"D:\college\4th semester\Computer networks\lab 3\mid traffic da2.pcap"

# -----------------------------
# Helper function to safely get TCP attributes
# -----------------------------
def safe_int(pkt_layer, attr_name, default=0):
    """Return int value of attribute or default if not present"""
    try:
        return int(getattr(pkt_layer, attr_name, default))
    except (AttributeError, ValueError):
        return default

# -----------------------------
# TCP metrics extraction
# -----------------------------
def extract_all_tcp_metrics(pcap_file):
    """Extract ALL TCP parameters with 1-second time bins"""
    cap = pyshark.FileCapture(pcap_file, display_filter='tcp')
    time_bins = {}
    base_time = None

    for pkt in cap:
        if 'tcp' not in pkt:
            continue

        # Base timing
        pkt_time = float(pkt.sniff_time.timestamp())
        if base_time is None:
            base_time = pkt_time
        rel_time = pkt_time - base_time
        time_bin = int(rel_time)  # 1-second bins

        tcp = pkt.tcp

        # Core TCP Fields (safely)
        stream = safe_int(tcp, 'stream')
        seq = safe_int(tcp, 'seq')
        ack = safe_int(tcp, 'ack')
        win = safe_int(tcp, 'window')
        mss = safe_int(tcp, 'mss', 1460)
        sack_count = safe_int(tcp, 'options_sack_count', 0)

        # Analysis flags (safely)
        is_retrans = 1 if getattr(tcp, 'analysis_retransmission', None) else 0
        is_dupack = 1 if getattr(tcp, 'analysis_duplicate_ack', None) else 0
        is_ooo = 1 if getattr(tcp, 'analysis_out_of_order', None) else 0
        is_zero_win = 1 if win == 0 else 0

        # Derived metrics
        pkt_len = safe_int(pkt, 'length')
        data_len = max(0, pkt_len - 54)
        bif_proxy = max(0, seq - ack)

        # Initialize time bin if not exists
        if time_bin not in time_bins:
            time_bins[time_bin] = {
                'count': 0,
                'sum': 0,
                'data_bytes': 0,
                'sack_count': 0,
                'window': 0,
                'retrans': 0,
                'dupack': 0,
                'ooo': 0,
                'zero_win': 0
            }

        # Aggregate metrics to time bin
        bin_data = time_bins[time_bin]
        bin_data['count'] += 1
        bin_data['sum'] += bif_proxy
        bin_data['data_bytes'] += data_len
        bin_data['sack_count'] = max(bin_data['sack_count'], sack_count)
        bin_data['window'] = max(bin_data['window'], win)
        bin_data['retrans'] += is_retrans
        bin_data['dupack'] += is_dupack
        bin_data['ooo'] += is_ooo
        bin_data['zero_win'] += is_zero_win

    # Convert to DataFrame
    df_list = []
    for tbin, data in time_bins.items():
        row = {
            'time_s': tbin,
            'total_packets': data['count'],
            'bytes_in_flight_avg': data['sum'] / max(1, data['count']),
            'bytes_in_flight_max': data['sum'] / max(1, data['count']),
            'throughput_bps': (data['data_bytes'] * 8) / max(1, tbin + 1),
            'sack_count': data['sack_count'],
            'window_size': data['window'],
            'retransmissions': data['retrans'],
            'dupacks': data['dupack'],
            'ooo_packets': data['ooo'],
            'zero_window_probes': data['zero_win'],
            'mss_avg': mss,
            'data_bytes': data['data_bytes'],
            'goodput_bps': (data['data_bytes'] * 8) / max(1, tbin + 1),
            'retrans_rate_pct': (data['retrans'] / max(1, data['count'])) * 100,
            'ooo_rate_pct': (data['ooo'] / max(1, data['count'])) * 100,
            'avg_window': data['window'] / max(1, data['count'])
        }
        df_list.append(row)

    df = pd.DataFrame(df_list)
    return df.fillna(0).sort_values('time_s')


# -----------------------------
# Main Execution
# -----------------------------
print(f"Analyzing {pcap_file}...")

df = extract_all_tcp_metrics(pcap_file)

# Save CSV
output_csv = f"{pcap_file.split('\\')[-1].replace('.pcap','')}_all_metricmidtraffic.csv"
df.to_csv(output_csv, index=False)

print(f"✓ Saved {len(df)} time bins to {output_csv}")
print("Top parameters available: ")
print(df.columns.tolist())
print(f"Sample data: {df.head()}")
