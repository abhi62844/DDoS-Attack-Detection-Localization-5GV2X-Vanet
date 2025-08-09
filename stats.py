import xml.etree.ElementTree as ET
from collections import defaultdict
import sys

# --- Configuration ---
FLOWMON_XML_FILE = "flow_stats_ddos_detect.xml"
# --- Identify Target IPs (Get these from C++ output or ueIpIface assignment) ---
# --- Example IPs - REPLACE with actual IPs from your simulation output ---
LEGIT_FAP_UE_IPS = ["7.0.0.2", "7.0.0.3"] # Assuming UE 0 and UE 1 get these IPs
REMOTE_HOST_IP = "1.0.0.2"
# --- Define Time Windows (match C++ simulation times) ---
T_START = 0.0
T_ATTACK_START = 10.0
T_ATTACK_STOP = 25.0
T_END = 100.0 # Match simStopTime

# Define time windows
windows = {
    "Before Attack (0-10s)": (T_START, T_ATTACK_START),
    "During Attack (10-25s)": (T_ATTACK_START, T_ATTACK_STOP),
    "After Attack (25-100s)": (T_ATTACK_STOP, T_END)
}

# Data structure to hold stats: window -> flow_id -> stats_dict
time_binned_stats = defaultdict(lambda: defaultdict(lambda: {
    'txPackets': 0, 'txBytes': 0,
    'rxPackets': 0, 'rxBytes': 0,
    'lostPackets': 0, 'delaySum': 0.0,
    'firstTx': float('inf'), 'lastTx': 0.0,
    'firstRx': float('inf'), 'lastRx': 0.0
}))

try:
    print(f"Parsing Flow Monitor XML: {FLOWMON_XML_FILE}")
    tree = ET.parse(FLOWMON_XML_FILE)
    root = tree.getroot()
except FileNotFoundError:
    print(f"Error: XML file not found: {FLOWMON_XML_FILE}")
    sys.exit(1)
except ET.ParseError as e:
    print(f"Error parsing XML file: {e}")
    sys.exit(1)


# Find the flow classifier to map IPs
ip_classifier = None
for classifier in root.findall('.//Ipv4FlowClassifier'):
     ip_classifier = classifier # Assume only one IPv4 classifier
     break

if ip_classifier is None:
    print("Error: Could not find Ipv4FlowClassifier in XML.")
    sys.exit(1)

flow_map = {}
for flow in ip_classifier.findall('Flow'):
    flow_id = int(flow.get('flowId'))
    flow_map[flow_id] = {
        'sourceAddress': flow.get('sourceAddress'),
        'destinationAddress': flow.get('destinationAddress'),
        'protocol': flow.get('protocol'),
        'sourcePort': flow.get('sourcePort'),
        'destinationPort': flow.get('destinationPort')
    }

print(f"Found {len(flow_map)} flows.")

# Process Packet Probes
flow_probes = root.find('.//FlowProbes')
if flow_probes is None:
     print("Warning: No <FlowProbes> section found. Ensure probes were enabled in C++ serialization.")
else:
    print("Processing packet probes...")
    processed_packets = 0
    for flow_probe in flow_probes.findall('FlowProbe'):
        flow_id = int(flow_probe.get('flowId'))

        # Check if this flow involves one of our target UEs
        flow_info = flow_map.get(flow_id)
        if not flow_info:
            continue

        is_target_ul = (flow_info['sourceAddress'] in LEGIT_FAP_UE_IPS and
                        flow_info['destinationAddress'] == REMOTE_HOST_IP)
        is_target_dl = (flow_info['destinationAddress'] in LEGIT_FAP_UE_IPS and
                        flow_info['sourceAddress'] == REMOTE_HOST_IP)

        if not (is_target_ul or is_target_dl):
            continue # Skip flows not involving our target UEs

        # Process individual packets within this flow's probes
        for packet in flow_probe.findall('Packet'):
            processed_packets += 1
            tx_time = float(packet.get('txTime')[:-1]) # Remove 's' suffix
            rx_time = float(packet.get('rxTime')[:-1]) if packet.get('rxTime') else -1.0
            delay_str = packet.get('delay')
            delay = float(delay_str[:-1]) if delay_str else 0.0
            packet_size = int(packet.get('packetSize'))
            packet_uid = int(packet.get('packetUID')) # Unique packet ID

            # Determine which time window this packet belongs to (use Rx time if available, else Tx time)
            timestamp = rx_time if rx_time >= 0 else tx_time

            window_name = None
            for name, (start, end) in windows.items():
                if start <= timestamp < end:
                    window_name = name
                    break

            if window_name:
                stats = time_binned_stats[window_name][flow_id]
                stats['txPackets'] += 1
                stats['txBytes'] += packet_size
                stats['firstTx'] = min(stats['firstTx'], tx_time)
                stats['lastTx'] = max(stats['lastTx'], tx_time)

                if rx_time >= 0: # Packet was received
                    stats['rxPackets'] += 1
                    stats['rxBytes'] += packet_size
                    stats['delaySum'] += delay
                    stats['firstRx'] = min(stats['firstRx'], rx_time)
                    stats['lastRx'] = max(stats['lastRx'], rx_time)
                else: # Packet was lost (assuming no rxTime means lost)
                    # Need a reliable way to detect loss from probes, this is approximate
                    # Flow stats summary might be better for accurate loss count
                    stats['lostPackets'] += 1

    print(f"Processed {processed_packets} packet probes.")


# --- Calculate and Print Results ---
print("\n--- Time-Binned Statistics for FAP Legitimate UEs ---")

for window_name, (start_time, end_time) in windows.items():
    print(f"\n--- Window: {window_name} ({start_time:.1f}s - {end_time:.1f}s) ---")
    window_flows = time_binned_stats[window_name]
    if not window_flows:
        print("  No relevant packet activity found in this window.")
        continue

    for flow_id, stats in sorted(window_flows.items()):
        flow_info = flow_map[flow_id]
        flow_label = f"UL (UE {flow_info['sourceAddress']} -> RH)" if flow_info['sourceAddress'] in LEGIT_FAP_UE_IPS else f"DL (RH -> UE {flow_info['destinationAddress']})"

        print(f" Flow ID: {flow_id} ({flow_label})")
        print(f"  Tx Packets : {stats['txPackets']} ({stats['txBytes']} bytes)")
        print(f"  Rx Packets : {stats['rxPackets']} ({stats['rxBytes']} bytes)")
        # Loss calculation from probes is tricky, use overall flow stats for better accuracy if needed
        print(f"  Lost Packets (probe estimate): {stats['lostPackets']}")
        loss_ratio = (stats['lostPackets'] / stats['txPackets']) if stats['txPackets'] > 0 else 0
        print(f"  Loss Ratio (probe estimate): {loss_ratio:.4f}")

        if stats['rxPackets'] > 0:
            avg_delay = stats['delaySum'] / stats['rxPackets']
            # Throughput based on time packet received within window
            # Need first/last RX *within the window* for accurate interval throughput
            # Using overall firstTx/lastRx is simpler but less precise for window throughput
            duration = stats['lastRx'] - stats['firstTx'] if stats['lastRx'] > stats['firstTx'] else (end_time - start_time) # Approximate duration

            # Clamp duration to window boundaries for calculation if first/last fall outside
            calc_start = max(start_time, stats['firstTx'] if stats['firstTx'] != float('inf') else start_time)
            calc_end = min(end_time, stats['lastRx'] if stats['lastRx'] != 0.0 else end_time)
            calc_duration = calc_end - calc_start

            throughput_kbps = (stats['rxBytes'] * 8 / calc_duration / 1024) if calc_duration > 0 else 0

            print(f"  Avg Delay  : {avg_delay:.6f} s")
            print(f"  Throughput : {throughput_kbps:.2f} Kbps (approx for window)")
        else:
            print("  Avg Delay  : N/A")
            print(f"  Throughput : 0.00 Kbps")
        print("-" * 20)