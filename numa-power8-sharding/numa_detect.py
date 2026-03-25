"""
NUMA Topology Detection Utility
Parses /sys/devices/system/node/ for node topology and bandwidth.
"""
import os, json, subprocess

def detect_numa():
    nodes = {}
    base = '/sys/devices/system/node'
    try:
        node_dirs = [d for d in os.listdir(base) if d.startswith('node')]
        for nd in sorted(node_dirs):
            node_id = int(nd.replace('node',''))
            dist_path = os.path.join(base, nd, 'distance')
            mem_path = os.path.join(base, nd, 'meminfo')
            cpus_path = os.path.join(base, nd, 'cpumap')
            
            dist = open(dist_path).read().strip() if os.path.exists(dist_path) else ''
            mem_total = 0
            if os.path.exists(mem_path):
                for line in open(mem_path):
                    if 'MemTotal:' in line:
                        mem_total = int(line.split()[3]) * 1024
                        break
            
            nodes[node_id] = {
                'node_id': node_id,
                'distance': [int(x) for x in dist.split()] if dist else [],
                'mem_total_bytes': mem_total,
            }
    except FileNotFoundError:
        pass
    return nodes

def benchmark_bandwidth(node_id):
    """Estimate memory bandwidth using simple streaming copy."""
    import time
    size = 256 * 1024 * 1024  # 256MB
    data = bytearray(size)
    start = time.perf_counter()
    for _ in range(2):
        _ = data[:]
    elapsed = time.perf_counter() - start
    bw = (size * 2 / 1e9) / elapsed if elapsed > 0 else 0
    return round(bw, 2)

def main():
    nodes = detect_numa()
    for nid, info in sorted(nodes.items()):
        bw = benchmark_bandwidth(nid)
        print(f'Node {nid}: {info["mem_total_bytes"]//(1024**3)}GB, ~{bw} GB/s')
    print()
    print('JSON:')
    print(json.dumps({'nodes': nodes, 'bandwidth_gbs': {nid: benchmark_bandwidth(nid) for nid in nodes}}, indent=2))

if __name__ == '__main__':
    main()
