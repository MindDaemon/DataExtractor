# Testanleitung

## Ziel

Diese Anleitung deckt zwei Dinge ab:

- schnelle Funktionsprüfung vor der Abgabe
- reproduzierbare Demo für die Kurzpräsentation

## Wichtige Einordnung

- Die Prüfungsvorgabe verlangt formal nur **eine gewählte Methode** aus `ARP`, `ICMP`, `SNMP` oder `DNS`.
- Dieses Projekt implementiert alle vier Methoden.
- Für die Präsentation solltest du **eine Methode als Primärpfad** festlegen und genau diese vorher mehrfach trocken testen.

## Voraussetzungen

- Python 3.11 oder neuer
- Abhängigkeiten aus `requirements.txt`
- Auf Windows: Npcap/Scapy-fähige Interfaces
- Start der Terminals mit ausreichenden Rechten, damit Senden/Sniffen funktioniert

Installation:

```bash
python -m pip install -r requirements.txt
```

Verfügbare Interfaces anzeigen:

```bash
python -c "from scapy.all import get_if_list; print(*get_if_list(), sep='\n')"
```

## Automatisierte Tests

Alle vorhandenen Tests ausführen:

```bash
python -m pytest -q -p no:cacheprovider
```

Erwartung:

- alle Tests grün
- damit sind Framing, Codec, DNS-Mapping und die Transportlogik auf Paketebene abgedeckt

Wichtig:

- diese Tests ersetzen **nicht** den echten End-to-End-Lauf auf deinem Zielsystem

## Empfohlener Demo-Pfad

Für einen einzelnen Windows-Rechner ist aktuell `ICMP` über das Npcap-Loopback-Interface der belastbarste lokale Testpfad.

Beispiel auf demselben Gerät:

Terminal 1, Receiver:

```bash
python -m receiver.main --method icmp --iface "\Device\NPF_Loopback" --peer 127.0.0.1 --out receiver/output/output.txt --psk "lab-shared-key" --pcap captures/receiver_capture.pcap --log-level INFO
```

Terminal 2, Sender:

```bash
python -m sender.main --method icmp --iface "\Device\NPF_Loopback" --peer 127.0.0.1 --in data/input.txt --psk "lab-shared-key" --pcap captures/sender_capture.pcap --log-level INFO
```

Erwartetes Ergebnis:

- Sender meldet `Transfer complete`
- Receiver zeigt den rekonstruierten Text auf dem Bildschirm
- Receiver schreibt die Datei `receiver/output/output.txt`
- beide Programme erzeugen eine `.pcap`

## Lokales Testen je Methode

### ICMP

- lokal auf demselben Windows-Rechner über `127.0.0.1` und `\Device\NPF_Loopback` praktisch testbar
- dieser Pfad wurde erfolgreich verifiziert

### DNS

- die Paketlogik ist durch Tests abgesichert
- auf Windows-Loopback mit der aktuellen Scapy-Sendeart war der lokale Realtest nicht stabil
- für die Demo besser zwei VMs oder zwei Hosts im selben IPv4-Subnetz verwenden

Beispiel:

```bash
python -m receiver.main --method dns --iface <IFACE> --peer <SENDER-IP> --out receiver/output/output.txt --psk "lab-shared-key" --dns-domain exfil.lab --dns-port 5300 --pcap captures/receiver_dns.pcap
python -m sender.main --method dns --iface <IFACE> --peer <RECEIVER-IP> --in data/input.txt --psk "lab-shared-key" --dns-domain exfil.lab --dns-port 5300 --pcap captures/sender_dns.pcap
```

### SNMP

- die Paketlogik ist durch Tests abgesichert
- auf Windows-Loopback mit der aktuellen Scapy-Sendeart war der lokale Realtest nicht stabil
- für die Demo besser zwei VMs oder zwei Hosts im selben IPv4-Subnetz verwenden

Beispiel:

```bash
python -m receiver.main --method snmp --iface <IFACE> --peer <SENDER-IP> --out receiver/output/output.txt --psk "lab-shared-key" --snmp-community public --snmp-port 1161 --snmp-oid 1.3.6.1.4.1.55555.1.0 --pcap captures/receiver_snmp.pcap
python -m sender.main --method snmp --iface <IFACE> --peer <RECEIVER-IP> --in data/input.txt --psk "lab-shared-key" --snmp-community public --snmp-port 1161 --snmp-oid 1.3.6.1.4.1.55555.1.0 --pcap captures/sender_snmp.pcap
```

### ARP

- ARP braucht eine Broadcast-Domain und ist **kein localhost-Protokoll**
- für ARP daher besser zwei VMs oder zwei Hosts im selben Layer-2-Netz verwenden

Beispiel:

```bash
python -m receiver.main --method arp --iface <IFACE> --peer <SENDER-IP> --out receiver/output/output.txt --psk "lab-shared-key" --pcap captures/receiver_arp.pcap
python -m sender.main --method arp --iface <IFACE> --peer <RECEIVER-IP> --in data/input.txt --psk "lab-shared-key" --pcap captures/sender_arp.pcap
```

## Abgabe-Checkliste

Vor der Präsentation einmal vollständig prüfen:

1. `data/input.txt` enthält den geforderten Text aus der Aufgabenstellung.
2. Sender und Receiver verwenden dieselbe Methode und denselben `--psk`.
3. Die Ausgabedatei von Programm B enthält den vollständigen Text.
4. Beide `.pcap`-Dateien wurden neu erzeugt.
5. Der gewählte Demo-Pfad funktioniert beim ersten Versuch reproduzierbar.
6. Für die Doku ist beschrieben:
   - gewählte Methode
   - Kodierung
   - Integritätsprüfung
   - Fehlerkorrektur
   - Erkennung und Gegenmaßnahmen

## Empfohlene Präsentationsstrategie

- Für die Bewertung reicht eine sauber funktionierende Methode.
- Wenn du auf einem einzelnen Windows-Rechner demonstrierst, nimm `ICMP` über Loopback.
- Wenn du mehrere Methoden zeigen willst, mache das nur zusätzlich und nicht als kritischen Hauptpfad.
