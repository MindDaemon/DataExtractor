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

## Kurzbefehle

Wenn du die langen CLI-Kommandos abkürzen willst, kannst du stattdessen den Repo-Launcher `run.py` verwenden.

Format:

```bash
python run.py <rolle> <protokoll> "<iface>" <peer-ip> "<psk>"
```

Rollen:

- `s` oder `sender`
- `r` oder `receiver`

Protokolle:

- `i` oder `icmp`
- `d` oder `dns`
- `a` oder `arp`
- `s` oder `snmp`

Beispiele:

```bash
python run.py r i "\Device\NPF_Loopback" 127.0.0.1 "lab-shared-key"
python run.py s i "\Device\NPF_Loopback" 127.0.0.1 "lab-shared-key"
```

Der Launcher setzt automatisch diese Defaults:

- Sender-Input: `data/input.txt`
- Receiver-Output: `receiver/output/output_<methode>.txt`
- Sender-PCAP: `captures/sender_<methode>.pcap`
- Receiver-PCAP: `captures/receiver_<methode>.pcap`
- DNS-Port: `5300`
- DNS-Domain: `exfil.lab`
- SNMP-Port: `1161`
- SNMP-Community: `public`
- SNMP-OID: `1.3.6.1.4.1.55555.1.0`

Die langen Original-Kommandos funktionieren weiterhin unverändert.

## Empfohlener Demo-Pfad

Für einen einzelnen Windows-Rechner ist aktuell `ICMP` über das Npcap-Loopback-Interface der belastbarste lokale Testpfad.

Beispiel auf demselben Gerät:

Terminal 1, Receiver:

Kurzbefehl:

```bash
python run.py r i "\Device\NPF_Loopback" 127.0.0.1 "lab-shared-key"
```

Originalkommando:

```bash
python -m receiver.main --method icmp --iface "\Device\NPF_Loopback" --peer 127.0.0.1 --out receiver/output/output_icmp.txt --psk "lab-shared-key" --pcap captures/receiver_icmp.pcap --log-level INFO
```

Terminal 2, Sender:

Kurzbefehl:

```bash
python run.py s i "\Device\NPF_Loopback" 127.0.0.1 "lab-shared-key"
```

Originalkommando:

```bash
python -m sender.main --method icmp --iface "\Device\NPF_Loopback" --peer 127.0.0.1 --in data/input.txt --psk "lab-shared-key" --pcap captures/sender_icmp.pcap --log-level INFO
```

Erwartetes Ergebnis:

- Sender meldet `Transfer complete`
- Receiver zeigt den rekonstruierten Text auf dem Bildschirm
- Receiver schreibt die Datei `receiver/output/output_icmp.txt`
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

Kurzbefehle:

```bash
python run.py r d "<IFACE>" <SENDER-IP> "lab-shared-key"
python run.py s d "<IFACE>" <RECEIVER-IP> "lab-shared-key"
```

Originalkommandos:

```bash
python -m receiver.main --method dns --iface "<IFACE>" --peer <SENDER-IP> --out receiver/output/output_dns.txt --psk "lab-shared-key" --dns-domain exfil.lab --dns-port 5300 --pcap captures/receiver_dns.pcap --log-level INFO
python -m sender.main --method dns --iface "<IFACE>" --peer <RECEIVER-IP> --in data/input.txt --psk "lab-shared-key" --dns-domain exfil.lab --dns-port 5300 --pcap captures/sender_dns.pcap --log-level INFO
```

### SNMP

- die Paketlogik ist durch Tests abgesichert
- auf Windows-Loopback mit der aktuellen Scapy-Sendeart war der lokale Realtest nicht stabil
- für die Demo besser zwei VMs oder zwei Hosts im selben IPv4-Subnetz verwenden

Beispiel:

Kurzbefehle:

```bash
python run.py r s "<IFACE>" <SENDER-IP> "lab-shared-key"
python run.py s s "<IFACE>" <RECEIVER-IP> "lab-shared-key"
```

Originalkommandos:

```bash
python -m receiver.main --method snmp --iface "<IFACE>" --peer <SENDER-IP> --out receiver/output/output_snmp.txt --psk "lab-shared-key" --snmp-community public --snmp-port 1161 --snmp-oid 1.3.6.1.4.1.55555.1.0 --pcap captures/receiver_snmp.pcap --log-level INFO
python -m sender.main --method snmp --iface "<IFACE>" --peer <RECEIVER-IP> --in data/input.txt --psk "lab-shared-key" --snmp-community public --snmp-port 1161 --snmp-oid 1.3.6.1.4.1.55555.1.0 --pcap captures/sender_snmp.pcap --log-level INFO
```

### ARP

- ARP braucht eine Broadcast-Domain und ist **kein localhost-Protokoll**
- für ARP daher besser zwei VMs oder zwei Hosts im selben Layer-2-Netz verwenden

Beispiel:

Kurzbefehle:

```bash
python run.py r a "<IFACE>" <SENDER-IP> "lab-shared-key"
python run.py s a "<IFACE>" <RECEIVER-IP> "lab-shared-key"
```

Originalkommandos:

```bash
python -m receiver.main --method arp --iface "<IFACE>" --peer <SENDER-IP> --out receiver/output/output_arp.txt --psk "lab-shared-key" --pcap captures/receiver_arp.pcap --log-level INFO
python -m sender.main --method arp --iface "<IFACE>" --peer <RECEIVER-IP> --in data/input.txt --psk "lab-shared-key" --pcap captures/sender_arp.pcap --log-level INFO
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
