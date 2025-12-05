# PINSS - Portable Intelligent Network Security System


🎤 START DEMO — WHAT YOU SAY

(Memorize or keep this beside you)

🔹 1. Start PINSS Engine

You say:

“Sir, this is the PINSS real-time autonomous network threat detection engine.
When I start it, it begins capturing packets, extracting features, running rule-based detection, ML detection, and mitigation.”

Run in Terminal 1:

python3 pinss_main.py


You say:

“As you see, the engine has loaded the ML model and is monitoring the network in real time.”

🔹 2. Show system normal (proves baseline stability)

PINSS prints:

✅ System Normal (No threats detected)


You say:

“The system stays quiet under normal traffic and avoids false detections.”

🎤 PHASE 2 — ATTACK SIMULATION
🔹 3. Simulating ARP Spoof Attack

Open Terminal 2 → run:

python3


Paste:

from scapy.all import *

send(ARP(op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66"))
send(ARP(op=2, psrc="192.168.1.1", hwsrc="AA:BB:CC:DD:EE:FF"))


PINSS will instantly show detection:

🚨 RULE DETECTION: ARP spoofing suspected...
[MITIGATION - ARP SPOOF] Firewall rule added...
[FIREWALL STATUS]
DROP   all  --  192.168.1.1   0.0.0.0/0
[LOGGED]


You say:

“Sir, PINSS has detected an ARP spoofing attempt.
Two different MAC addresses claimed to be the router IP, which is a classic ARP spoof attack.
The system automatically blocked the attacker using a firewall rule.”

🎤 PHASE 3 — PROOF TO EXAMINER

Now you show undeniable evidence.

🔹 4. PROOF 1 — Show Firewall Rules

Terminal 3:

sudo iptables -L -n


Examiner will see:

DROP    all  --  192.168.1.1    0.0.0.0/0


You say:

“Sir, here is the firewall rule created by PINSS.
This rule was added automatically after detection, which blocks all traffic originating from the attacker IP.”

🔹 5. PROOF 2 — Show Ping to Attacker Fails

Try:

ping -c 4 192.168.1.1


It will fail or timeout.

You say:

“As you can see, the attacker cannot reach the system anymore.
The packets are being dropped by the firewall.”

🔹 6. PROOF 3 — Show Log Entry

Open your log file:

cat logs/detection_history.csv


Examiner sees:

timestamp, ARP Spoofing, 192.168.1.1, Blocked via firewall, ...


You say:

“Every detection and mitigation is permanently logged for audit and intelligence sharing.”
