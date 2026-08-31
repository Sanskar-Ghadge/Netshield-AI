"""Quick test: run model on simulated attack flows."""
from __future__ import annotations
import sys
sys.path.insert(0, "C:\\Users\\HP\\Desktop\\New folder\\CNT project\\python-engine")

from prediction.predict import IntrusionPredictor, ArtifactPaths
from prediction.flow_adapter import FlowPredictionAdapter
from packet_capture.flow import FlowAccumulator
from packet_capture.schemas import FlowKey, PacketRecord, FlowState, Direction
import time

paths = ArtifactPaths()
paths.validate()
predictor = IntrusionPredictor(paths)
adapter = FlowPredictionAdapter(predictor)

base_ts = time.time() * 1_000_000

# Test 1: Port scan - single SYN to various ports
print("=== Port Scan (single SYN to different ports) ===")
for dport in [22, 80, 443, 8080, 3389, 1, 2, 3, 4, 5]:
    key = FlowKey.from_endpoints('172.20.10.4', '8.8.8.8', 51567, dport, 6)
    acc = FlowAccumulator(key=key)
    pkt = PacketRecord(
        timestamp_us=base_ts + dport * 1000,
        src_ip='172.20.10.4', dst_ip='8.8.8.8',
        src_port=51567, dst_port=dport,
        protocol=6, ip_total_length=40, ip_header_length=20,
        transport_header_length=20, payload_length=0,
        tcp_flags=0x02, tcp_window=8192, tcp_data_offset=5,
        direction=Direction.FORWARD,
    )
    acc.ingest(pkt)
    flow_result = acc.to_flow_result()
    flow_result.state = FlowState.TIMEOUT
    flow_result.context = flow_result.to_context_dict()
    result = adapter.predict(flow_result)
    probs = result.class_probabilities
    dos = probs.get('DoS', 0)
    ddos = probs.get('DDoS', 0)
    ps = probs.get('PortScan', 0)
    benign = probs.get('BENIGN', 0)
    print(f'  Port {dport:5d}: {result.label:12s} conf={result.confidence:.4f}  (BENIGN={benign:.3f} DoS={dos:.3f} DDoS={ddos:.3f} PortScan={ps:.3f})')

print()

# Test 2: Brute force - many SYNs to port 22, different source ports
print("=== Brute Force (many SYNs to port 22) ===")
key = FlowKey.from_endpoints('172.20.10.4', '8.8.8.8', 51567, 22, 6)
acc = FlowAccumulator(key=key)
for i in range(200):
    pkt = PacketRecord(
        timestamp_us=base_ts + i * 2000,
        src_ip='172.20.10.4', dst_ip='8.8.8.8',
        src_port=51567, dst_port=22,
        protocol=6, ip_total_length=40, ip_header_length=20,
        transport_header_length=20, payload_length=0,
        tcp_flags=0x02, tcp_window=8192, tcp_data_offset=5,
        direction=Direction.FORWARD,
    )
    acc.ingest(pkt)

flow_result = acc.to_flow_result()
flow_result.state = FlowState.TIMEOUT
flow_result.context = flow_result.to_context_dict()
result = adapter.predict(flow_result)
probs = result.class_probabilities
print(f'  {result.label:12s} conf={result.confidence:.4f}')
for c, p in sorted(probs.items(), key=lambda x: -x[1]):
    print(f'    {c:15s}: {p:.4f}')
