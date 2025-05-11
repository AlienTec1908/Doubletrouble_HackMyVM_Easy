# Doubletrouble - HackMyVM (Easy)

![Doubletrouble.png](Doubletrouble.png)

## Übersicht

*   **VM:** Doubletrouble
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Doubletrouble)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 24. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Doubletrouble_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser "Easy"-Challenge war es, Root-Zugriff auf der Maschine "Doubletrouble" zu erlangen. Die Enumeration deckte einen Webserver (Apache) auf, der eine "qdPM 9.1"-Anwendung hostete. In einem versteckten Verzeichnis (`/secret/`) wurde eine Bilddatei (`doubletrouble.jpg`) gefunden. Mittels Steganographie (`stegseek`) wurden aus diesem Bild Zugangsdaten (`otisrush@localhost.com:otis666`) extrahiert. Ein öffentlicher Exploit für qdPM 9.1 (Exploit-DB 47954) wurde mit diesen Credentials verwendet, um eine PHP-Webshell hochzuladen und RCE zu erlangen, was zu einer initialen Shell als `www-data` führte. Als `www-data` wurde eine `sudo`-Regel entdeckt, die das Ausführen von `/usr/bin/awk` als jeder Benutzer ohne Passwort erlaubte. Durch Ausführen von `sudo awk 'BEGIN {system("/bin/sh")}'` wurde eine Root-Shell erlangt und die Flags gelesen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `wget`
*   `exiftool`
*   `stegseek`
*   `gobuster`
*   `steghide`
*   `searchsploit`
*   `python` (für Exploit-Skript)
*   `nc` (netcat)
*   `python3` (für pty-Shell-Stabilisierung)
*   `sudo` (auf Zielsystem)
*   `awk` (als Exploit-Vektor)
*   Standard Linux-Befehle (`ls`, `whoami`, `export`, `cat`, `su` (versucht), `ss`, `find`, `id`, `cd`, `vi`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Doubletrouble" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mittels `arp-scan` (Ziel: `192.168.2.120`).
    *   `nmap`-Scan identifizierte SSH (22/tcp) und Apache (80/tcp) mit der Anwendung "qdPM | Login".
    *   `gobuster` fand diverse Verzeichnisse, u.a. `/secret/`.
    *   Aus `/secret/doubletrouble.jpg` wurden mittels `stegseek` und dem Passwort `92camaro` die Zugangsdaten `otisrush@localhost.com:otis666` extrahiert.
    *   SSH-Login mit diesen Credentials scheiterte.

2.  **Initial Access (als `www-data` via qdPM RCE):**
    *   `searchsploit` fand einen RCE-Exploit für qdPM 9.1 (Exploit-DB 47954, `47954.py`).
    *   Das Python-Exploit-Skript (`qdpmExploit.py`) wurde mit den zuvor gefundenen Credentials (`otisrush@localhost.com:otis666`) ausgeführt.
    *   Der Exploit lud eine PHP-Webshell (`904447-backdoor.php`) in `/uploads/users/` hoch und ermöglichte RCE.
    *   Über die Webshell wurde eine Bash-Reverse-Shell zu einem Netcat-Listener des Angreifers gestartet.
    *   Erfolgreicher Shell-Zugriff als `www-data`.

3.  **Privilege Escalation (von `www-data` zu `root` via Sudo/awk):**
    *   Als `www-data` zeigte `sudo -l`, dass `/usr/bin/awk` als jeder Benutzer (`ALL : ALL`) ohne Passwort (`NOPASSWD:`) ausgeführt werden durfte.
    *   Der Befehl `sudo awk 'BEGIN {system("/bin/sh")}'` wurde ausgeführt.
    *   Dies startete eine Shell als `root`.

4.  **Flags:**
    *   Als `root` wurden die User- und Root-Flags gelesen. (Die User-Flag war im Bericht nicht explizit im Home-Verzeichnis eines Benutzers verortet, wird aber als `user.txt` im Flag-Abschnitt angegeben).

## Wichtige Schwachstellen und Konzepte

*   **Steganographie:** Zugangsdaten waren in einer Bilddatei versteckt und wurden mit `stegseek` extrahiert.
*   **Bekannte Webanwendungs-Schwachstelle (RCE):** Ausnutzung eines öffentlichen RCE-Exploits für qdPM 9.1.
*   **Unsichere `sudo`-Regel (`awk`):** Das Erlauben von `awk` mit `NOPASSWD` und `ALL:ALL` ermöglichte eine einfache Root-Eskalation durch Ausführung von Shell-Befehlen.
*   **PHP Webshell / Reverse Shell:** Verwendet für initialen Zugriff und Codeausführung.

## Flags

*   **User Flag (`user.txt` - Pfad nicht explizit im Log für den Fund, aber Flag genannt):** `6CEA7A737C7C651F6DA7669109B5FB52`
*   **Root Flag (`/root/root.txt` - Pfad nicht explizit im Log, aber Standard):** `1B8EEA89EA92CECB931E3CC25AA8DE21`

## Tags

`HackMyVM`, `Doubletrouble`, `Easy`, `Web`, `Apache`, `qdPM`, `Steganography`, `stegseek`, `RCE`, `Exploit-DB`, `PHP Webshell`, `sudo`, `awk`, `Privilege Escalation`, `Linux`
