#!/usr/bin/env python3
"""
ESP32-H2 Multi-Dongle Zigbee Sniffer
Capture N canaux en parallèle → FIFO persistant pour Wireshark

Architecture :
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ ESP32-H2 │  │ ESP32-H2 │  │ ESP32-H2 │  ...
  │ Canal 11 │  │ Canal 12 │  │ Canal 13 │
  └────┬─────┘  └────┬─────┘  └────┬─────┘
       │              │              │
       └──────────────┼──────────────┘
                      │
              ┌───────▼────────┐
              │  Queue partagée │
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │  FIFO Writer    │──→ /chemin/vers/zigbee.fifo
              └────────────────┘
                                      │
                              wireshark -k -i /chemin/vers/zigbee.fifo

La FIFO est persistante :
  - Le script tourne en continu et capture
  - Wireshark peut se connecter / déconnecter librement
  - À chaque connexion Wireshark, le header PCAP est renvoyé
  - Les paquets capturés sans Wireshark sont perdus (pas de buffer infini)

Usage:
  # 3 dongles pour tester
  python3 zigbee_multi_capture.py \\
    --fifo /root/zigbee.fifo \\
    -p /dev/ttyACM0:11 \\
    -p /dev/ttyACM1:12 \\
    -p /dev/ttyACM2:13

  # 16 dongles (tous les canaux Zigbee)
  python3 zigbee_multi_capture.py \\
    --fifo /root/zigbee.fifo \\
    -p /dev/ttyACM0:11 -p /dev/ttyACM1:12 -p /dev/ttyACM2:13 \\
    -p /dev/ttyACM3:14 -p /dev/ttyACM4:15 -p /dev/ttyACM5:16 \\
    -p /dev/ttyACM6:17 -p /dev/ttyACM7:18 -p /dev/ttyACM8:19 \\
    -p /dev/ttyACM9:20 -p /dev/ttyACM10:21 -p /dev/ttyACM11:22 \\
    -p /dev/ttyACM12:23 -p /dev/ttyACM13:24 -p /dev/ttyACM14:25 \\
    -p /dev/ttyACM15:26

  # Autodétection des dongles ESP32-H2
  python3 zigbee_multi_capture.py --fifo /root/zigbee.fifo --auto

  # Sauvegarder aussi en fichier en plus du FIFO
  python3 zigbee_multi_capture.py \\
    --fifo /root/zigbee.fifo \\
    --save /root/capture.pcap \\
    -p /dev/ttyACM0:11 -p /dev/ttyACM1:12

  # Depuis Wireshark (dans un autre terminal) :
  wireshark -k -i /root/zigbee.fifo
"""

import argparse
import os
import re
import struct
import sys
import time
import signal
import threading
import queue

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("[!] pyserial requis : pip install pyserial")
    sys.exit(1)


# ═══════════════════════════════════════════════════
#  PCAP — IEEE 802.15.4 TAP (canal inclus)
# ═══════════════════════════════════════════════════

PCAP_MAGIC             = 0xA1B2C3D4
DLT_IEEE802_15_4_TAP   = 283

TAP_FCS_TYPE  = 0
TAP_CHANNEL   = 3
FCS_16_BIT    = 1
CHANNEL_PAGE  = 0


def zigbee_freq(ch):
    return 2405 + 5 * (ch - 11)


def make_tap_tlv(ttype, val):
    length = len(val)
    padded = (length + 3) & ~3
    return struct.pack('<HH', ttype, length) + val + (b'\x00' * (padded - length))


def make_tap_header(channel):
    tlv_fcs = make_tap_tlv(TAP_FCS_TYPE, struct.pack('<B', FCS_16_BIT))
    tlv_ch = make_tap_tlv(TAP_CHANNEL, struct.pack('<HHB',
        channel, zigbee_freq(channel), CHANNEL_PAGE))
    tlvs = tlv_fcs + tlv_ch
    return struct.pack('<BBH', 0, 0, 4 + len(tlvs)) + tlvs


def pcap_global_header():
    return struct.pack('<IHHiIII', PCAP_MAGIC, 2, 4, 0, 0, 65535, DLT_IEEE802_15_4_TAP)


def pcap_packet(frame, channel):
    tap = make_tap_header(channel)
    payload = tap + frame
    ts = time.time()
    n = len(payload)
    return struct.pack('<IIII', int(ts), int((ts % 1) * 1e6), n, n) + payload


# ═══════════════════════════════════════════════════
#  Capture Thread — 1 par dongle ESP32-H2
# ═══════════════════════════════════════════════════

class DongleCapture(threading.Thread):
    def __init__(self, port, channel, packet_queue, stats):
        super().__init__(daemon=True)
        self.port = port
        self.channel = channel
        self.packet_queue = packet_queue
        self.stats = stats
        self.running = True
        self.count = 0
        self.expecting = 0
        self.frame_parts = []
        self.collected = 0

    def send(self, ser, cmd):
        ser.write((cmd + '\r\n').encode())
        time.sleep(0.8)
        while ser.in_waiting:
            ser.readline()

    def init_radio(self, ser):
        ser.reset_input_buffer()
        ser.write(b'\r\n')
        time.sleep(0.3)
        ser.reset_input_buffer()
        self.send(ser, "esp154 -e")
        time.sleep(1)
        self.send(ser, f"channel -s {self.channel}")
        self.send(ser, "promisc -e")
        self.send(ser, "rx -r 1")
        time.sleep(0.5)
        ser.reset_input_buffer()

    def parse_line(self, line):
        m = re.search(r'Rx\s+Done\s+(\d+)\s+bytes', line)
        if m:
            self.expecting = int(m.group(1))
            self.frame_parts = []
            self.collected = 0
            return None

        if self.expecting > 0:
            m = re.search(r'i154cmd:\s+((?:[0-9a-fA-F]{2}\s+)*[0-9a-fA-F]{2})', line)
            if m:
                try:
                    hx = bytes.fromhex(m.group(1).replace(' ', ''))
                    self.frame_parts.append(hx)
                    self.collected += len(hx)
                    if self.collected >= self.expecting:
                        frame = b''.join(self.frame_parts)[:self.expecting]
                        self.expecting = 0
                        self.frame_parts = []
                        self.collected = 0
                        return frame
                except ValueError:
                    pass
        return None

    def run(self):
        try:
            ser = serial.Serial(
                self.port, 115200, timeout=0.5,
                dsrdtr=False, rtscts=False
            )
            ser.dtr = False
            ser.rts = False
            time.sleep(0.3)
        except Exception as e:
            print(f"[!] {self.port} (ch{self.channel}): Erreur ouverture — {e}")
            return

        freq = zigbee_freq(self.channel)
        print(f"[+] {self.port} → Canal {self.channel} ({freq} MHz) — initialisé")

        try:
            self.init_radio(ser)
        except Exception as e:
            print(f"[!] {self.port} (ch{self.channel}): Erreur init radio — {e}")
            ser.close()
            return

        while self.running:
            try:
                raw = ser.readline()
                if not raw:
                    continue
                line = raw.decode('utf-8', errors='replace').strip()
                if not line:
                    continue

                frame = self.parse_line(line)
                if frame and len(frame) >= 2:
                    pkt = pcap_packet(frame, self.channel)
                    self.packet_queue.put(pkt)
                    self.count += 1
                    self.stats[self.channel] = self.count

            except Exception:
                continue

        try:
            self.send(ser, "rx -r 0")
            ser.close()
        except Exception:
            pass

    def stop(self):
        self.running = False


# ═══════════════════════════════════════════════════
#  FIFO Writer — Sortie persistante pour Wireshark
# ═══════════════════════════════════════════════════

class FifoWriter(threading.Thread):
    """
    Écrit les paquets PCAP dans un FIFO nommé.
    
    Comportement :
    - Crée le FIFO au chemin spécifié
    - Attend qu'un lecteur (Wireshark) se connecte
    - Envoie le header PCAP global
    - Stream les paquets
    - Si Wireshark se déconnecte → attend une nouvelle connexion
    - Les paquets capturés sans lecteur sont perdus
    """

    def __init__(self, fifo_path, packet_queue):
        super().__init__(daemon=True)
        self.fifo_path = fifo_path
        self.packet_queue = packet_queue
        self.running = True
        self.connected = False

    def run(self):
        # Créer le FIFO
        if os.path.exists(self.fifo_path):
            os.remove(self.fifo_path)
        os.mkfifo(self.fifo_path)

        while self.running:
            try:
                print(f"\n[FIFO] En attente de Wireshark sur {self.fifo_path}")
                print(f"[FIFO] Lancez : wireshark -k -i {self.fifo_path}")

                # open() bloque jusqu'à qu'un lecteur se connecte
                with open(self.fifo_path, 'wb') as fifo:
                    self.connected = True
                    print(f"[FIFO] Wireshark connecté !")

                    # Envoyer le header PCAP
                    fifo.write(pcap_global_header())
                    fifo.flush()

                    # Vider la queue des vieux paquets
                    while not self.packet_queue.empty():
                        try:
                            self.packet_queue.get_nowait()
                        except queue.Empty:
                            break

                    # Streamer les paquets
                    while self.running:
                        try:
                            pkt = self.packet_queue.get(timeout=0.5)
                            fifo.write(pkt)
                            fifo.flush()
                        except queue.Empty:
                            continue

            except BrokenPipeError:
                self.connected = False
                print(f"\n[FIFO] Wireshark déconnecté — en attente de reconnexion...")
                continue
            except OSError:
                if self.running:
                    time.sleep(1)
                continue

    def stop(self):
        self.running = False
        self.connected = False
        # Débloquer le open() en écrivant dans le FIFO
        try:
            fd = os.open(self.fifo_path, os.O_WRONLY | os.O_NONBLOCK)
            os.close(fd)
        except Exception:
            pass
        # Nettoyer
        try:
            if os.path.exists(self.fifo_path):
                os.remove(self.fifo_path)
        except Exception:
            pass


# ═══════════════════════════════════════════════════
#  File Writer — Sauvegarde PCAP optionnelle
# ═══════════════════════════════════════════════════

class FileWriter(threading.Thread):
    """Sauvegarde les paquets en fichier PCAP en parallèle du FIFO."""

    def __init__(self, filepath, packet_queue):
        super().__init__(daemon=True)
        self.filepath = filepath
        self.packet_queue = packet_queue
        self.running = True

    def run(self):
        with open(self.filepath, 'wb') as f:
            f.write(pcap_global_header())
            f.flush()

            while self.running:
                try:
                    pkt = self.packet_queue.get(timeout=0.5)
                    f.write(pkt)
                    f.flush()
                except queue.Empty:
                    continue

    def stop(self):
        self.running = False


# ═══════════════════════════════════════════════════
#  Autodétection des ESP32-H2
# ═══════════════════════════════════════════════════

def detect_esp32h2():
    """Trouver tous les ESP32-H2 connectés en USB."""
    espressif_vid = 0x303A
    espressif_pid = 0x1001  # USB JTAG/serial debug unit

    found = []
    for port in serial.tools.list_ports.comports():
        if port.vid == espressif_vid and port.pid == espressif_pid:
            found.append(port.device)
        elif port.description and 'JTAG' in port.description:
            found.append(port.device)

    found.sort()
    return found


# ═══════════════════════════════════════════════════
#  Affichage stats
# ═══════════════════════════════════════════════════

class StatsDisplay(threading.Thread):
    """Affiche les stats de capture en temps réel."""

    def __init__(self, stats, fifo_writer):
        super().__init__(daemon=True)
        self.stats = stats
        self.fifo_writer = fifo_writer
        self.running = True
        self.start_time = time.time()

    def run(self):
        while self.running:
            time.sleep(2)
            elapsed = time.time() - self.start_time
            total = sum(self.stats.values())
            ws_status = "🟢 connecté" if self.fifo_writer.connected else "🔴 en attente"

            parts = []
            for ch in sorted(self.stats.keys()):
                parts.append(f"ch{ch}:{self.stats[ch]}")

            channels_str = " | ".join(parts) if parts else "aucun paquet"
            print(f"\r[{elapsed:.0f}s] Total: {total} | {channels_str} | Wireshark: {ws_status}   ",
                  end='', flush=True)

    def stop(self):
        self.running = False


# ═══════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='ESP32-H2 Multi-Dongle Zigbee Sniffer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:

  # 3 dongles
  %(prog)s --fifo /root/zigbee.fifo \\
    -p /dev/ttyACM0:11 -p /dev/ttyACM1:12 -p /dev/ttyACM2:13

  # Autodétection
  %(prog)s --fifo /root/zigbee.fifo --auto

  # Avec sauvegarde fichier
  %(prog)s --fifo /root/zigbee.fifo --save /root/capture.pcap \\
    -p /dev/ttyACM0:11 -p /dev/ttyACM1:12

  # Depuis un autre terminal :
  wireshark -k -i /root/zigbee.fifo
        """)

    parser.add_argument('--fifo', required=True,
                        help='Chemin du FIFO pour Wireshark (ex: /root/zigbee.fifo)')
    parser.add_argument('-p', '--port', action='append', default=[],
                        help='port:canal (ex: /dev/ttyACM0:11). Répétable.')
    parser.add_argument('--auto', action='store_true',
                        help='Autodétecter les ESP32-H2 et assigner canaux 11-26')
    parser.add_argument('--save', default=None,
                        help='Sauvegarder aussi en fichier PCAP')
    parser.add_argument('--start-channel', type=int, default=11,
                        help='Canal de départ en mode auto (défaut: 11)')

    args = parser.parse_args()

    print()
    print("╔═══════════════════════════════════════════════════╗")
    print("║  ESP32-H2 Multi-Dongle Zigbee Sniffer             ║")
    print("║  IEEE 802.15.4 TAP → FIFO → Wireshark             ║")
    print("╚═══════════════════════════════════════════════════╝")
    print()

    # ── Construire la liste port:canal ──
    dongles = []

    if args.auto:
        ports = detect_esp32h2()
        if not ports:
            print("[!] Aucun ESP32-H2 détecté. Vérifiez les connexions USB.")
            print("[*] Ports disponibles :")
            for p in serial.tools.list_ports.comports():
                print(f"    {p.device} — {p.description} [{p.hwid}]")
            sys.exit(1)

        ch = args.start_channel
        for port in ports:
            if ch > 26:
                print(f"[!] Plus de 16 dongles détectés, canaux 11-26 épuisés")
                break
            dongles.append((port, ch))
            ch += 1
    else:
        if not args.port:
            parser.error("Spécifiez au moins un -p port:canal ou utilisez --auto")

        for p in args.port:
            if ':' not in p:
                parser.error(f"Format invalide: '{p}'. Utilisez port:canal (ex: /dev/ttyACM0:11)")
            port, ch_str = p.rsplit(':', 1)
            ch = int(ch_str)
            if not 11 <= ch <= 26:
                parser.error(f"Canal {ch} invalide (11-26)")
            dongles.append((port, ch))

    # ── Afficher la configuration ──
    print(f"[*] Configuration :")
    print(f"    FIFO    : {args.fifo}")
    if args.save:
        print(f"    Fichier : {args.save}")
    print(f"    Dongles : {len(dongles)}")
    for port, ch in dongles:
        freq = zigbee_freq(ch)
        print(f"      {port} → Canal {ch} ({freq} MHz)")
    print()

    # ── Queues ──
    fifo_queue = queue.Queue(maxsize=10000)
    file_queue = queue.Queue(maxsize=10000) if args.save else None

    # Stats partagées
    stats = {}
    for _, ch in dongles:
        stats[ch] = 0

    # ── Démarrer le FIFO Writer ──
    fifo_writer = FifoWriter(args.fifo, fifo_queue)
    fifo_writer.start()

    # ── Démarrer le File Writer (optionnel) ──
    file_writer = None
    if args.save:
        file_writer = FileWriter(args.save, file_queue)
        file_writer.start()
        print(f"[+] Sauvegarde fichier : {args.save}")

    # ── Queue dispatcher (duplique vers fifo ET file) ──
    main_queue = queue.Queue(maxsize=10000)

    def dispatch():
        while True:
            try:
                pkt = main_queue.get(timeout=0.5)
                # Vers FIFO (drop si queue pleine = pas de Wireshark)
                try:
                    fifo_queue.put_nowait(pkt)
                except queue.Full:
                    pass
                # Vers fichier (si activé)
                if file_queue is not None:
                    try:
                        file_queue.put_nowait(pkt)
                    except queue.Full:
                        pass
            except queue.Empty:
                continue

    dispatcher = threading.Thread(target=dispatch, daemon=True)
    dispatcher.start()

    # ── Démarrer les captures ──
    captures = []
    for port, ch in dongles:
        cap = DongleCapture(port, ch, main_queue, stats)
        cap.start()
        captures.append(cap)
        time.sleep(0.5)  # Délai entre chaque init pour ne pas surcharger l'USB

    # ── Affichage stats ──
    stats_display = StatsDisplay(stats, fifo_writer)
    stats_display.start()

    print()
    print(f"[+] {len(captures)} dongles actifs — Capture en cours")
    print(f"[*] Connectez Wireshark : wireshark -k -i {args.fifo}")
    print(f"[*] Ctrl+C pour arrêter")
    print()

    # ── Attendre Ctrl+C ──
    def cleanup(sig, frame):
        print("\n\n[*] Arrêt en cours...")
        stats_display.stop()
        for cap in captures:
            cap.stop()
        fifo_writer.stop()
        if file_writer:
            file_writer.stop()

        # Résumé final
        total = sum(stats.values())
        print(f"\n{'='*55}")
        print(f"  RÉSUMÉ DE CAPTURE")
        print(f"{'='*55}")
        for ch in sorted(stats.keys()):
            freq = zigbee_freq(ch)
            count = stats[ch]
            bar = "█" * min(count // 5 + (1 if count > 0 else 0), 30)
            print(f"  Canal {ch:2d} ({freq} MHz) : {count:6d} paquets {bar}")
        print(f"{'='*55}")
        print(f"  Total : {total} paquets")
        if args.save:
            print(f"  Fichier : {args.save}")
        print()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Boucle principale (le vrai travail est dans les threads)
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()