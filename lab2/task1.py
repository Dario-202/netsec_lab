"""Raggruppa le connessioni dietro un NAT tramite TCP Timestamp.

Uso:
    python -m pip install scapy matplotlib
    python tcp_timestamp_fingerprint.py

Analizza esclusivamente il traffico CLIENT -> server (IP pubblico del NAT).
"""

import csv
import re
from collections import defaultdict
from pathlib import Path
from statistics import median

from scapy.all import IP, TCP, PcapReader

NAT_IP = "198.51.100.7"
PCAP_FILE = Path(__file__).resolve().parent / "capture-7.pcap"
TOLERANCE_MS = 10.0
MOD = 2**32
HTTP_START = re.compile(
    rb"(?m)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d\.\d\r?\n"
)
TRACE = re.compile(rb"(?im)^X-Trace:[ \t]*([1-8])-([0-9a-f]{6})[ \t]*\r?$")


def ts_difference(a, b):
    """Differenza con segno fra timestamp TCP a 32 bit (gestisce il wrap)."""
    return ((int(a) - int(b) + MOD // 2) % MOD) - MOD // 2


def tcp_ts(tcp):
    for kind, value in tcp.options:
        if kind == "Timestamp" and isinstance(value, tuple):
            return int(value[0])  # TSval, non TSecr
    return None


def reassemble(chunks):
    """Ricompone i byte client->server, eliminando i duplicati TCP.

    Nei rari casi di gap (segmenti assenti nella cattura), conserva una
    separazione per non costruire richieste HTTP false.
    """
    if not chunks:
        return b""
    chunks = sorted(chunks, key=lambda x: x[0])
    start = chunks[0][0]
    end = start
    output = bytearray()
    for seq, data in chunks:
        if seq > end:
            output.extend(b"\n")  # gap nei dati catturati
            end = seq
        offset = max(0, end - seq)
        if offset < len(data):
            output.extend(data[offset:])
            end = seq + len(data)
    return bytes(output)


def read_http(data):
    requests = []
    for match in HTTP_START.finditer(data):
        # Consideriamo solo gli header della richiesta, fino alla riga vuota.
        tail = data[match.end():]
        end = re.search(rb"\r?\n\r?\n", tail)
        if end is None:
            continue
        headers = tail[:end.start()]
        trace = TRACE.search(headers)
        requests.append({
            "method": match.group(1).decode("ascii"),
            "path": match.group(2).decode("ascii", errors="replace"),
            "trace": (int(trace.group(1)), trace.group(2).decode("ascii")) if trace else None,
        })
    return requests


def load_flows(filename, nat_ip):
    flows = defaultdict(lambda: {"points": [], "chunks": [], "requests": []})
    count = 0
    with PcapReader(filename) as reader:
        for pkt in reader:
            count += 1
            if IP not in pkt or TCP not in pkt:
                continue
            ip, tcp = pkt[IP], pkt[TCP]
            if ip.src != nat_ip:
                continue  # evita i TSval del server
            key = (int(tcp.sport), str(ip.dst), int(tcp.dport))
            flow = flows[key]
            timestamp = tcp_ts(tcp)
            if timestamp is not None:
                flow["points"].append((float(pkt.time), timestamp))
            data = bytes(tcp.payload)
            if data:
                flow["chunks"].append((int(tcp.seq), data))

    for flow in flows.values():
        flow["points"].sort()
        flow["requests"] = read_http(reassemble(flow["chunks"]))
        del flow["chunks"]
    return flows, count


def fit_line(points):
    """Regressione TSval relativo = hz * tempo relativo + intercetta."""
    n = len(points)
    sx = sum(x for x, _ in points)
    sy = sum(y for _, y in points)
    sxx = sum(x * x for x, _ in points)
    sxy = sum(x * y for x, y in points)
    denominator = n * sxx - sx * sx
    if n < 2 or abs(denominator) < 1e-9:
        raise ValueError("Servono timestamp abbastanza distanti nel tempo")
    hz = (n * sxy - sx * sy) / denominator
    intercept = (sy - hz * sx) / n
    return hz, intercept


def main():
    # Cerca sempre capture-7.pcap nella cartella dello script.
    if not PCAP_FILE.is_file():
        raise SystemExit(
            f"File non trovato: {PCAP_FILE}\n"
            "Metti capture-7.pcap nella stessa cartella di questo script Python."
        )

    print(f"File PCAP: {PCAP_FILE}")
    flows, packets = load_flows(str(PCAP_FILE), NAT_IP)
    # La POST /admin/login individua la connessione di riferimento.
    admin_keys = [key for key, flow in flows.items()
                  if any(r["method"] == "POST" and
                         r["path"].split("?", 1)[0] == "/admin/login"
                         for r in flow["requests"])]
    if len(admin_keys) != 1:
        raise SystemExit(f"Trovate {len(admin_keys)} connessioni con POST /admin/login (attesa: 1). "
                         "Controlla che la cattura contenga HTTP non cifrato.")
    anchor_key = admin_keys[0]
    if not flows[anchor_key]["points"]:
        raise SystemExit("La connessione admin non contiene TCP TSval.")
    t0, ts0 = flows[anchor_key]["points"][0]
    print(f"Pacchetti letti: {packets}; connessioni client: {len(flows)}")
    print(f"Connessione admin: NAT:{anchor_key[0]} -> {anchor_key[1]}:{anchor_key[2]}")
    print(f"Punto di riferimento: TSval={ts0}, tempo relativo all'anchor=0 s")

    usable = {k: f for k, f in flows.items() if f["points"]}

    def representative(flow):
        return flow["points"][0]

    def valid_for(hz, intercept=0.0):
        result = {}
        tolerance = max(4.0, abs(hz) * TOLERANCE_MS / 1000.0)
        for key, flow in usable.items():
            # La mediana riduce gli effetti di jitter e dei singoli pacchetti anomali.
            residuals = [abs(ts_difference(ts, ts0) - hz * (t - t0) - intercept)
                         for t, ts in flow["points"]]
            error = median(residuals)
            if error <= tolerance:
                result[key] = error
        return result

    # Stima non basata sul solo intervallo SYN->ACK di 38 ms: confrontiamo
    # le connessioni distribuite lungo la cattura, cercando la retta comune.
    candidate_hz = []
    for key, flow in usable.items():
        if key == anchor_key:
            continue
        t, ts = representative(flow)
        dt = t - t0
        if abs(dt) < 2:
            continue
        hz = ts_difference(ts, ts0) / dt
        if 1 <= hz <= 10000:
            candidate_hz.append(hz)
    # Aggiungiamo anche stime ottenute dalla connessione admin (meno precise
    # quando l'intervallo temporale e' corto, ma utili come piano B).
    for t, ts in flows[anchor_key]["points"][1:]:
        dt = t - t0
        if abs(dt) >= 0.02:
            hz = ts_difference(ts, ts0) / dt
            if 1 <= hz <= 10000:
                candidate_hz.append(hz)

    if not candidate_hz:
        raise SystemExit("Nessuna frequenza candidata: dati TSval insufficienti.")

    # La frequenza corretta deve allineare il maggior numero di *connessioni*.
    best_hz = max(candidate_hz, key=lambda hz: (
        len(valid_for(hz)), -sum(valid_for(hz).values())
    ))
    selected = valid_for(best_hz)

    # Raffiniamo la stima usando più punti degli stream selezionati.
    hz, intercept = best_hz, 0.0
    for _ in range(4):
        selected = valid_for(hz, intercept)
        samples = []
        for key in selected:
            pts = usable[key]["points"]
            # Campionamento fino a 30 punti per stream, evita che un singolo
            # stream con tanti ACK domini la regressione.
            step = max(1, len(pts) // 30)
            for t, ts in pts[::step]:
                samples.append((t - t0, ts_difference(ts, ts0)))
        if len(samples) < 2:
            break
        try:
            hz, intercept = fit_line(samples)
        except ValueError:
            break
    selected = valid_for(hz, intercept)

    print(f"Frequenza TCP stimata: {hz:.4f} Hz")
    print(f"Connessioni compatibili: {len(selected)}")
    print("\nConnessioni attribuite al PC admin:")
    pieces = defaultdict(set)
    for key in sorted(selected, key=lambda k: usable[k]["points"][0][0]):
        print(f"  NAT:{key[0]} -> {key[1]}:{key[2]} (errore mediano: {selected[key]:.2f} tick)")
        for req in flows[key]["requests"]:
            print(f"    {req['method']} {req['path']} | X-Trace: {req['trace']}")
            if req["trace"]:
                n, value = req["trace"]
                pieces[n].add(value)

    print("\nFrammenti X-Trace:")
    for n in range(1, 9):
        values = sorted(pieces.get(n, []))
        print(f"  {n}: {', '.join(values) if values else 'MANCANTE'}")
    if all(len(pieces.get(n, [])) == 1 for n in range(1, 9)):
        token = "".join(next(iter(pieces[n])) for n in range(1, 9))
        print(f"\nFLAG: netsec{{{token}}}")
    else:
        print("\nToken incompleto/ambiguo: verifica la classificazione e i pacchetti HTTP.")

    with open(PCAP_FILE.parent / "tcp_timestamp_matches.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["nat_source_port", "server_ip", "server_port", "time_relative_s", "tsval", "admin_pc"])
        for key, flow in usable.items():
            for t, ts in flow["points"]:
                writer.writerow([key[0], key[1], key[2], f"{t-t0:.6f}", ts, int(key in selected)])
    print("\nEsportato: tcp_timestamp_matches.csv")

    # Grafico: i punti attribuiti al PC admin seguono la stessa retta.
    try:
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(11, 6))
        for key, flow in usable.items():
            color = "tab:red" if key in selected else "lightgray"
            xs = [(t - t0) / 60 for t, _ in flow["points"]]
            ys = [ts_difference(ts, ts0) for _, ts in flow["points"]]
            ax.scatter(xs, ys, s=5 if key in selected else 2, c=color, alpha=0.7)
        ax.scatter([0], [0], s=65, c="black", marker="x", zorder=5, label="Anchor admin")
        ax.set_xlabel("Tempo rispetto al primo pacchetto admin (minuti)")
        ax.set_ylabel("TSval - TSval anchor (con wrap a 32 bit)")
        ax.set_title(f"TCP Timestamp fingerprinting: {hz:.2f} Hz")
        ax.grid(alpha=0.25)
        ax.legend()
        fig.tight_layout()
        fig.savefig(PCAP_FILE.parent / "tcp_timestamp_plot.png", dpi=160)
        print("Esportato: tcp_timestamp_plot.png")
    except ImportError:
        print("Grafico non creato (installa matplotlib: python -m pip install matplotlib).")


if __name__ == "__main__":
    main()
