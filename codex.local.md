# Prüfungsleistung – Network Security (23CS1)

**Quelle:** „Prüfungsleistung Network Security“ – Version 3.4 (23CS1), M. Eppler, 02.02.2026

---

## Beschreibung der Prüfungsleistung

Die Prüfungsleistung besteht aus dem Programmentwurf zweier Programme, der dazugehörigen Dokumentation sowie der Demonstration von beiden Programmen im Rahmen einer Kurzpräsentation.

Die Prüfungsleistung darf als Gruppe mit maximal drei Teilnehmer:innen erbracht werden. Die Gruppe erstellt dann zusätzlich eine schriftliche Tabelle / Dokumentation, aus der die individuelle Leistung der Gruppenteilnehmer:innen zur Prüfungsleistung hervorgeht.

---

## Szenario Beschreibung

Mit Hilfe von zwei selbst entwickelten Programmen soll die Extraktion von Daten über das Netzwerk nachgestellt und demonstriert werden. Das erste Programm („Programm A“) extrahiert die zu übertragenden Daten aus einer Textdatei und sendet diese an das zweite Programm („Programm B“) über das Netzwerk. Das zweite Programm stellt die empfangenen Daten als Ausgabe auf dem Bildschirm dar und speichert diese in einer Textdatei ab.

Als Methode für die Extraktion über das Netzwerk kann eine der folgenden vier Methoden gewählt werden:

- ARP  
- ICMP  
- SNMP  
- DNS  

Die Programmiersprache ist frei wählbar.

Um eventuell vorhandene Sicherheitssysteme zu umgehen und die Erkennung zu erschweren, dürfen die extrahierten Daten nicht im Klartext, sondern nur codiert über das Netzwerk übertragen werden. Die spezifischen Protokollabläufe von DNS, ARP, SNMP bzw. ICMP sind dabei zu beachten und einzuhalten.

Ebenso sind in den beiden Programmen Mechanismen zur Sicherstellung der Datenintegrität bei der Übertragung und geeignete Methoden zur Fehlerkorrektur vorzusehen.

Im Rahmen des Szenarios wird davon ausgegangen, dass Programm A bereits im Netzwerk erfolgreich durch einen vorherigen Angriff installiert wurde (z.B. durch einen Drive-by Download oder über einen entsprechend gestalteten Anhang in einer E-Mail).

Ebenfalls kann davon ausgegangen werden, dass Programm B an einer entsprechenden Stelle im Netz bereits vorhanden ist und unter vollständiger Kontrolle der angreifenden Partei steht:

- Bei Methode ARP befinden sich Programm A und Programm B in derselben Broadcast Domain.
- Bei den Methoden ICMP, SNMP und DNS befinden sich Programm A und Programm B innerhalb desselben IPv4 Subnetzes.

**Hinweis:** Bei einem realen Angriff werden sich bei ICMP, SNMP und DNS die Programme in unterschiedlichen Subnetzen oder im Internet befinden. Ebenso wird das Programm B bei ARP noch eine Komponente zur Extraktion der Daten über andere Wege zur angreifenden Partei vorsehen (z.B. WLAN oder Mobilfunk). Im Rahmen der Prüfungsleistung wird das Szenario in diesem Punkt stark vereinfacht und weicht von der Realität ab.

---

## Zu übertragender Text

Der folgende Text stellt die zu extrahierenden Daten dar und soll als auslesbare Textdatei auf dem Computersystem von Programm A vorhanden sein. Es handelt sich hierbei um die beiden Paragrafen 202c und 202d des Strafgesetzbuches (https://www.gesetze-im-internet.de/stgb/__202c.html und https://www.gesetze-im-internet.de/stgb/__202d.html). Der Text ist vollständig inklusive aller Leer- und Sonderzeichen sowie Absätzen zu übertragen:

```text
/// Begin Text ///
§ 202c Vorbereiten des Ausspähens und Abfangens von Daten
(1) Wer eine Straftat nach § 202a oder § 202b vorbereitet, 
indem er
1.
Passwörter oder sonstige Sicherungscodes, die den Zugang zu 
Daten (§ 202a Abs. 2) ermöglichen, oder
2.
Computerprogramme, deren Zweck die Begehung einer solchen Tat 
ist,
herstellt, sich oder einem anderen verschafft, verkauft, einem 
anderen überlässt, verbreitet oder sonst zugänglich macht, 
wird mit Freiheitsstrafe bis zu zwei Jahren oder mit 
Geldstrafe bestraft.
(2) § 149 Abs. 2 und 3 gilt entsprechend.
§ 202d Datenhehlerei
(1) Wer Daten (§ 202a Absatz 2), die nicht allgemein 
zugänglich sind und die ein anderer durch eine rechtswidrige 
Tat erlangt hat, sich oder einem anderen verschafft, einem 
anderen überlässt, verbreitet oder sonst zugänglich macht, um 
sich oder einen Dritten zu bereichern oder einen anderen zu 
schädigen, wird mit Freiheitsstrafe bis zu drei Jahren oder 
mit Geldstrafe bestraft.
(2) Die Strafe darf nicht schwerer sein als die für die Vortat 
angedrohte Strafe.
(3) Absatz 1 gilt nicht für Handlungen, die ausschließlich der 
Erfüllung rechtmäßiger dienstlicher oder beruflicher Pflichten 
dienen. Dazu gehören insbesondere
1.
solche Handlungen von Amtsträgern oder deren Beauftragten, mit 
denen Daten ausschließlich der Verwertung in einem 
Besteuerungsverfahren, einem Strafverfahren oder einem 
Ordnungswidrigkeitenverfahren zugeführt werden sollen, sowie
2.
solche beruflichen Handlungen der in § 53 Absatz 1 Satz 1 
Nummer 5 der Strafprozessordnung genannten Personen, mit denen 
Daten entgegengenommen, ausgewertet oder veröffentlicht 
werden.
/// End Text ///
```

---

## Prüfungsleistung Programmentwurf

### Beschreibung Programm A

Programm A stellt im Szenario die Malware dar, welche vom User des Systems heruntergeladen und gestartet wurde. Folgende Funktionen müssen im Programm A gegeben sein:

1. Auslesen der Textdatei mit den zu extrahierenden Daten (siehe vorherigen Absatz).
2. Codierung des Textinhaltes mit einem geeigneten Codierungsverfahren. Eine symmetrische oder asymmetrische Verschlüsselung der Daten ist nicht erforderlich und wird im Rahmen der Prüfungsleistung gleichrangig wie ein anderes geeignetes Codierungsverfahren gewertet.
3. Senden der codierten Daten über den Netzwerkstack mit Hilfe einer der folgenden Methoden: ARP, ICMP, SNMP oder DNS.
4. Erzeugung eines Packet Captures durch das Programm selbst als pcap-Datei während der Laufzeit des Programmes.
5. Mechanismus zur Überwachung der fehlerfreien Übertragung der Daten (Integritätsprüfung) und Fehlerkorrektur.

### Beschreibung Programm B

Programm B stellt im Szenario die Software des Angreifers dar, welche die von der Malware gesendeten Daten empfängt, decodiert und als Bildschirmausgabe darstellt. Folgende Funktionen müssen im Programm B gegeben sein:

1. Empfang der von Programm A gesendeten Daten vom Netzwerkstack.
2. Erzeugung eines Packet Captures durch das Programm selbst als pcap-Datei während der Laufzeit des Programmes.
3. Decodierung der Daten (Umwandlung in Text).
4. Mechanismus zur Überwachung der fehlerfreien Übertragung der Daten (Integritätsprüfung) und Fehlerkorrektur.
5. Ausgabe der decodierten Daten auf dem Bildschirm und in einer Textdatei.

---

## Beschreibung des Netzwerksetups für das Szenario

Programm A und Programm B müssen in geeigneten Betriebsumgebungen gestartet werden und über ein Netzwerk miteinander verbunden sein. Dies kann beispielsweise wie folgt umgesetzt werden:

- Zwei physikalisch getrennte Computersysteme, welche über einen Switch miteinander verbunden sind (Computersystem A für Programm A, Computersystem B für Programm B). Sowohl auf Computersystem A als auch auf Computersystem B muss zur Überprüfung des Netzwerkverkehrs das Programm Wireshark (www.wireshark.org) vorhanden sein. Programm A und Programm B können hier jeweils pro Computersystem auch in einer virtualisierten Umgebung laufen.
- Ein Computersystem mit einer Virtualisierungslösung, welche zwei virtuelle Gastsysteme beinhaltet (Gastsystem A für Programm A, Gastsystem B für Programm B). Die beiden virtuellen Gastsysteme sind durch die Virtualisierungslösung netzwerktechnisch miteinander verbunden. Sowohl im Gastsystem A als auch im Gastsystem B muss zur Überprüfung des Netzwerkverkehrs das Programm Wireshark vorhanden sein.
- Ein Computersystem mit Visual Studio Code (https://code.visualstudio.com/), in dem beide Programme getrennt voneinander gestartet werden.

Es ist bei der Wahl der Betriebsumgebung darauf zu achten, dass die Daten in jedem Fall über den Netzwerkstack übertragen werden und nicht einfach nur per API-Call oder ähnlichen Methoden an das andere Programm direkt ohne Einbindung der Protokolle ARP, ICMP, SNMP oder DNS übergeben werden.

---

## Prüfungsleistung Dokumentation

Die im Rahmen der Prüfungsleistung zu erstellende Dokumentation muss folgende Punkte umfassen:

- Die Vor- und Nachnamen aller Teilnehmer:innen der Gruppe
- Gewählte Angriffsmethode (ARP, ICMP, SNMP oder DNS)
- Motivation: warum haben Sie sich für die gewählte Angriffsmethode entschieden?
- Die technische Beschreibung der gewählten Angriffsmethode: wie erfolgt der Transport der extrahierten Daten über den Netzwerkstack?
- Die technische Beschreibung des gewählten Codierungsverfahrens: wie werden die Daten für die Übertragung vorbereitet und codiert? Wie erfolgt die Decodierung?
- Die technische Beschreibung der Integritätsprüfung und des Fehlerkorrekturverfahrens: wie wird von beiden Programmen sichergestellt, dass die übertragenen Daten korrekt sind? Wie werden Fehler bei der Übertragung erkannt und korrigiert?
- Persönliches Fazit: wie schätzen Sie den Erfolg und die Robustheit / Zuverlässigkeit der von Ihnen gewählten Angriffsmethode in der Praxis ein? Wie könnte dieser Angriff erkannt und verhindert werden? Was wird dafür benötigt?

Der Umfang der Dokumentation sollte sich zwischen 7 und 10 Seiten bewegen. Vom Ansatz her sollte diese so verfasst sein, dass ein Entscheider / eine Entscheiderin im Unternehmen eine realistische Risikoabschätzung vornehmen und gegebenenfalls Budget für zielführende Gegenmaßnahmen bewilligen kann.

---

## Prüfungsleistung Kurzpräsentation

Die Funktionsfähigkeit der beiden Programme A und B soll im Rahmen einer Kurzpräsentation durch die Gruppe demonstriert werden. Der Zeitumfang für die Präsentation beträgt:

- 5 Minuten für die Vorbereitung (Umbauarbeiten wie zum Beispiel Aufbau der Rechnerumgebung, Anschluss an den Beamer, etc.)
- 5 Minuten für die eigentliche Präsentation der beiden Programme

Die Kurzpräsentation selbst wird nicht gewertet, sie dient aber als Grundlage für die Bewertung der Prüfungsleistung. Sie müssen hierfür also keine Präsentation mit Folien oder ähnliches vorbereiten.

Zweck der Kurzpräsentation ist der Beweis, dass die beiden erstellten Programme die Datenextraktion vornehmen können. Insbesondere wird dabei auf folgende Punkte geachtet:

- Die Datenextraktion ist beim ersten Versuch erfolgreich
- Das Programm B zeigt den Inhalt der übertragenen Daten vollständig und fehlerfrei auf dem Bildschirm an
- Erzeugung der beiden Packet Capture-Dateien im pcap-Format
- Darstellung der decodierten Daten auf dem Bildschirm und Speicherung in einer Textdatei bei Programm B

Sollte die Datenextraktion im ersten Versuch nicht erfolgreich sein, so ist ein zweiter Versuch nach einer Unterbrechung von maximal 15 Minuten auf Wunsch der Gruppe möglich. Weitere zusätzliche Versuche sind nicht vorgesehen.

Bitte beachten Sie, dass sich die Inanspruchnahme eines zweiten Versuches auf die Bewertung der Prüfungsleistung entsprechend auswirken wird. Für die Gesamtbewertung (Ausgabe auf dem Bildschirm, Packet Captures, etc.) wird dabei immer der zuletzt durchgeführte Versuch betrachtet.

---

## Bewertungskriterien

### Prüfpunkte

**Programm A:**

- Erfolgreiches Auslesen der Textdatei mit dem vorgegebenen Text
- Codierung mit dem in der Dokumentation beschriebenen Codierungsverfahren
- Erfolgreiches Senden der codierten Daten über den Netzwerkstack mit dem dafür vorgesehenen Netzwerkprotokoll
- Die Daten werden nicht im Klartext übertragen
- Mechanismus zur Fehlererkennung und -korrektur vorhanden
- Packet Capture wird als pcap-Datei erzeugt

**Programm B:**

- Empfang der von Programm A gesendeten und codierten Daten vom Netzwerkstack
- Decodierung mit dem in der Dokumentation beschriebenen Codierungsverfahren und Überführung in Klartext
- Ausgabe des vorgegebenen Textes auf dem Bildschirm inklusive aller Satz-, Sonder- und Leerzeichen
- Speicherung der Ausgabe in einer Textdatei
- Mechanismus zur Fehlererkennung und -korrektur vorhanden
- Packet Capture wird als pcap-Datei erzeugt

**Dokumentation:**

- Vollständigkeit gemäß der Beschreibung im Abschnitt „Prüfungsleistung Dokumentation“
- Technische Korrektheit der Angaben im Dokument

**Kurzpräsentation:***  

\* Die Kurzpräsentation selbst wird nicht bewertet. Im Rahmen der Kurzpräsentation wird aber die erfolgreiche Durchführung der Datenextraktion von der Gruppe demonstriert und dient somit als Basis für die Bewertung der anderen für die Prüfungsleistung relevanten Punkte.

---

## Abgabetermine der Prüfungsleistung

Für die Prüfungsleistung sind folgende Abgabetermine vorgesehen:

- **Festlegung der Gruppeneinteilung** (Sicherstellung, dass jede(r) Studierende einer Gruppe zugeordnet ist)  
  - Per E-Mail an martin@kurslabor.de  
  - Spätestens bis zum **23. Februar 2026**

- **Dokumentation**  
  - per E-Mail an martin@kurslabor.de  
  - der Eingang wird vom Dozenten entsprechend nach spätestens 24 Stunden bestätigt  
  - **7 Tage vor dem Termin der Kurzpräsentation**: **16. März 2026**

- **Source Codes der Programme A und B**  
  - Packet Captures der Programme A und B nach dem letzten unternommenen Versuch der Datenextraktion  
  - Textdatei von Programm B mit den decodierten Daten  
  - per USB-Stick  
  - **Am Tag der Kurzpräsentation**: **24. März 2026**
