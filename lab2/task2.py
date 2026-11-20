from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

CARTELLA = Path(__file__).resolve().parent
PCAP_FILE = CARTELLA / "capture-7.2.pcap"
DOMINIO_C2 = "syncbridge.example"
FRAMMENTI_ATTESI = 8
LIMITE_TCP = 128 * 1024  # bastano i primi byte della connessione (ClientHello)


class DatiIncompleti(ValueError):
    """La struttura TLS e' incompleta o non valida."""


class Lettore:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def leggi(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise DatiIncompleti("Struttura TLS incompleta")
        valore = self.data[self.pos:self.pos + n]
        self.pos += n
        return valore

    def u8(self) -> int:
        return self.leggi(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.leggi(2), "big")


def grease(n: int) -> bool:
    """Riconosce 0x0a0a, 0x1a1a, ..., 0xfafa (RFC 8701)."""
    return (n & 0x0F0F) == 0x0A0A and (n >> 8) == (n & 0xFF)


def lista_u16(data: bytes) -> list[int]:
    if len(data) % 2:
        raise DatiIncompleti("Elenco uint16 di lunghezza dispari")
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)]


def valore_alpn(data: bytes) -> str:
    """Parte ALPN del JA4 secondo le regole FoxIO."""
    if not data:
        return "00"

    def alfanumerico(byte: int) -> bool:
        return (48 <= byte <= 57) or (65 <= byte <= 90) or (97 <= byte <= 122)

    if alfanumerico(data[0]) and alfanumerico(data[-1]):
        return chr(data[0]) + chr(data[-1])
    esadecimale = data.hex()
    return esadecimale[0] + esadecimale[-1]


def hash12(s: str) -> str:
    return hashlib.sha256(s.encode("ascii")).hexdigest()[:12]


def estrai_sni(ext: bytes) -> str:
    r = Lettore(ext)
    lunghezza = r.u16()
    nomi = Lettore(r.leggi(lunghezza))
    while nomi.pos < len(nomi.data):
        tipo = nomi.u8()
        nome = nomi.leggi(nomi.u16())
        if tipo == 0:  # host_name
            return nome.decode("ascii", errors="replace").lower().rstrip(".")
    return ""


def estrai_alpn(ext: bytes) -> bytes:
    r = Lettore(ext)
    protocolli = Lettore(r.leggi(r.u16()))
    if not protocolli.data:
        return b""
    return protocolli.leggi(protocolli.u8())


def estrai_versioni(ext: bytes) -> list[int]:
    r = Lettore(ext)
    return [v for v in lista_u16(r.leggi(r.u8())) if not grease(v)]


def estrai_firme(ext: bytes) -> list[int]:
    r = Lettore(ext)
    return [v for v in lista_u16(r.leggi(r.u16())) if not grease(v)]


def analizza_client_hello(body: bytes) -> dict:
    """Legge i campi di un ClientHello TLS e costruisce JA4 (a_b_c)."""
    r = Lettore(body)
    versione_legacy = r.u16()
    r.leggi(32)  # random
    r.leggi(r.u8())  # session ID

    ciphers = lista_u16(r.leggi(r.u16()))
    ciphers = [c for c in ciphers if not grease(c)]
    r.leggi(r.u8())  # compression methods

    estensioni: list[tuple[int, bytes]] = []
    if r.pos < len(body):
        lunghezza_estensioni = r.u16()
        exts = Lettore(r.leggi(lunghezza_estensioni))
        while exts.pos < len(exts.data):
            tipo = exts.u16()
            contenuto = exts.leggi(exts.u16())
            if not grease(tipo):
                estensioni.append((tipo, contenuto))

    tipi = [tipo for tipo, _ in estensioni]
    sni = ""
    alpn = b""
    firme: list[int] = []
    versione = versione_legacy

    for tipo, contenuto in estensioni:
        if tipo == 0:  # server_name
            sni = estrai_sni(contenuto)
        elif tipo == 16:  # ALPN
            alpn = estrai_alpn(contenuto)
        elif tipo == 13:  # signature_algorithms
            firme = estrai_firme(contenuto)
        elif tipo == 43:  # supported_versions
            versioni = estrai_versioni(contenuto)
            if versioni:
                versione = max(versioni)

    versioni_ja4 = {
        0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
        0x0300: "s3", 0x0002: "s2", 0xFEFF: "d1",
        0xFEFD: "d2", 0xFEFC: "d3",
    }
    a = (f"t{versioni_ja4.get(versione, '00')}"
         f"{'d' if 0 in tipi else 'i'}"
         f"{min(len(ciphers), 99):02d}"
         f"{min(len(estensioni), 99):02d}"
         f"{valore_alpn(alpn)}")

    elenco_cipher = ",".join(f"{x:04x}" for x in sorted(ciphers))
    b = hash12(elenco_cipher) if elenco_cipher else "0" * 12

    # Per JA4_c: estensioni ordinate SENZA SNI (0) e ALPN (16).
    elenco_estensioni = ",".join(f"{x:04x}" for x in sorted(
        tipo for tipo in tipi if tipo not in (0, 16)
    ))
    elenco_firme = ",".join(f"{x:04x}" for x in firme)  # NON ordinare
    raw_c = elenco_estensioni + ("_" + elenco_firme if elenco_firme else "")
    c = hash12(raw_c) if elenco_estensioni else "0" * 12

    return {
        "sni": sni,
        "ja4": f"{a}_{b}_{c}",
        "ja4_r": f"{a}_{elenco_cipher}_{elenco_estensioni}"
                 + ("_" + elenco_firme if elenco_firme else ""),
    }


def trova_client_hello(tcp_data: bytes) -> dict | None:
    """Estrae il primo ClientHello, anche se ripartito fra record TLS."""
    pos = 0
    handshake = bytearray()

    while pos + 5 <= len(tcp_data):
        tipo = tcp_data[pos]
        major = tcp_data[pos + 1]
        lunghezza = int.from_bytes(tcp_data[pos + 3:pos + 5], "big")
        if major != 3 or tipo not in (20, 21, 22, 23, 24):
            break  # non sembra TLS su questo stream
        inizio = pos + 5
        fine = inizio + lunghezza
        if fine > len(tcp_data):
            break  # non e' stato catturato l'intero record

        if tipo == 22:  # handshake record
            handshake.extend(tcp_data[inizio:fine])
            while len(handshake) >= 4:
                htipo = handshake[0]
                hlen = int.from_bytes(handshake[1:4], "big")
                if len(handshake) < 4 + hlen:
                    break
                body = bytes(handshake[4:4 + hlen])
                del handshake[:4 + hlen]
                if htipo == 1:  # TLS ClientHello
                    try:
                        return analizza_client_hello(body)
                    except DatiIncompleti:
                        return None
        elif tipo == 23:  # application data: nessun ClientHello leggibile
            break
        pos = fine
    return None


@dataclass
class Flusso:
    sorgente: str
    sport: int
    destinazione: str
    dport: int
    primo_frame: int
    tempo: float
    syn_seq: int | None = None
    base_seq: int | None = None
    segmenti: dict[int, tuple[bytes, int]] = field(default_factory=dict)

    def aggiungi(self, seq: int, payload: bytes, frame: int) -> None:
        if not payload:
            return
        if self.base_seq is None:
            self.base_seq = seq
        offset = ((seq - self.base_seq + 2**31) % 2**32) - 2**31
        if offset < 0 and self.syn_seq is None:
            # Se non abbiamo visto il SYN, ricalibra usando il segmento piu' vecchio.
            slittamento = -offset
            self.segmenti = {k + slittamento: v for k, v in self.segmenti.items()}
            self.base_seq = seq
            offset = 0
        if offset < 0 or offset >= LIMITE_TCP:
            return
        payload = payload[:LIMITE_TCP - offset]
        precedente = self.segmenti.get(offset)
        if precedente is None or len(payload) > len(precedente[0]):
            self.segmenti[offset] = (payload, frame)

    def ricostruisci(self) -> tuple[bytes, int]:
        risultato = bytearray()
        frame_inizio = self.primo_frame
        for offset, (payload, frame) in sorted(self.segmenti.items()):
            if offset > len(risultato):
                break  # manca un segmento TCP: niente reassembly incompleto
            if offset == 0 and not risultato:
                frame_inizio = frame
            sovrapposti = len(risultato) - offset
            if sovrapposti < len(payload):
                risultato.extend(payload[sovrapposti:])
            if len(risultato) >= LIMITE_TCP:
                break
        return bytes(risultato), frame_inizio


def scegli_pcap() -> Path:
    if not PCAP_FILE.is_file():
        raise FileNotFoundError(f"File PCAP non trovato: {PCAP_FILE}")
    return PCAP_FILE


def carica_flussi(pcap: Path) -> tuple[list[Flusso], int]:
    # Import locale: i test del parser TLS possono essere eseguiti senza Scapy.
    try:
        from scapy.all import PcapReader, IP, IPv6, TCP
    except ImportError as exc:
        raise RuntimeError("Scapy non installato. Esegui: python -m pip install scapy") from exc

    correnti: dict[tuple, Flusso] = {}
    tutti: list[Flusso] = []
    n = 0
    with PcapReader(str(pcap)) as reader:
        for pkt in reader:
            n += 1
            if TCP not in pkt:
                continue
            if IP in pkt:
                ip = pkt[IP]
            elif IPv6 in pkt:
                ip = pkt[IPv6]
            else:
                continue
            tcp = pkt[TCP]
            key = (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport))
            flags = int(tcp.flags)
            syn_iniziale = bool(flags & 0x02) and not bool(flags & 0x10)
            seq = int(tcp.seq)
            payload = bytes(tcp.payload)

            flow = correnti.get(key)
            if syn_iniziale:
                if flow is not None and flow.syn_seq == seq:
                    continue  # ritrasmissione dello stesso SYN
                flow = Flusso(key[0], key[1], key[2], key[3], n,
                              float(pkt.time), syn_seq=seq,
                              base_seq=(seq + 1) % 2**32)
                correnti[key] = flow
                tutti.append(flow)
            elif flow is None:
                flow = Flusso(key[0], key[1], key[2], key[3], n, float(pkt.time))
                correnti[key] = flow
                tutti.append(flow)

            if payload:
                flow.aggiungi(seq + int(syn_iniziale), payload, n)

    return tutti, n


def analizza_pcap(pcap: Path) -> list[dict]:
    flows, n_pacchetti = carica_flussi(pcap)
    print(f"Pacchetti letti: {n_pacchetti} | direzioni TCP: {len(flows)}")
    risultati: list[dict] = []
    for flow in flows:
        data, frame = flow.ricostruisci()
        if not data:
            continue
        hello = trova_client_hello(data)
        if hello is None:
            continue
        risultati.append({
            "frame": frame,
            "time": flow.tempo,
            "src": flow.sorgente,
            "sport": flow.sport,
            "dst": flow.destinazione,
            "dport": flow.dport,
            **hello,
        })
    return sorted(risultati, key=lambda x: x["frame"])


def main() -> None:
    pcap = scegli_pcap()
    print("File analizzato:", pcap.name)
    connessioni = analizza_pcap(pcap)
    print("ClientHello TLS trovati:", len(connessioni))
    if not connessioni:
        print("Nessun ClientHello ricostruito. Controlla che il PCAP contenga il TLS handshake.")
        return

    anchors = [c for c in connessioni
               if c["sni"] == DOMINIO_C2 or c["sni"].endswith("." + DOMINIO_C2)]
    if len(anchors) != 1:
        print(f"Connessioni verso {DOMINIO_C2}: {len(anchors)} (attesa: 1)")
        print("Esempi di SNI:", [c["sni"] for c in connessioni[:15]])
        return

    anchor = anchors[0]
    print("\nANCHOR C2:")
    print(f"  Frame {anchor['frame']} | {anchor['src']}:{anchor['sport']} -> "
          f"{anchor['dst']}:{anchor['dport']}")
    print("  SNI:  ", anchor["sni"])
    print("  JA4:  ", anchor["ja4"])
    print("  JA4_r:", anchor["ja4_r"])

    compatibili = [c for c in connessioni if c["ja4"] == anchor["ja4"]]
    frammenti: list[str] = []
    print("\nCONNESSIONI CON LO STESSO JA4 (ordine di cattura):")
    for c in compatibili:
        label = c["sni"].split(".", 1)[0]
        valido = bool(re.fullmatch(r"[0-9a-f]{6}", label))
        print(f"  Frame {c['frame']:6d} | {c['src']}:{c['sport']} -> "
              f"{c['dst']}:{c['dport']} | {c['sni']}"
              + ("  [6 HEX]" if valido else ""))
        if valido:
            frammenti.append(label)

    print(f"Frammenti esadecimali: {len(frammenti)}/{FRAMMENTI_ATTESI}")

    if len(frammenti) == FRAMMENTI_ATTESI:
        token = "".join(frammenti)
        print("FLAG:", f"netsec{{{token}}}")
    else:
        print("FLAG non generata: servono esattamente 8 frammenti compatibili.")
        print("Nota: JA4 uguale non garantisce che due applicazioni siano la stessa.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, DatiIncompleti) as e:
        print("ERRORE:", e)
