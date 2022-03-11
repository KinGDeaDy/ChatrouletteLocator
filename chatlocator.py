import pyshark
from geolite2 import geolite2

reader = geolite2.reader()


def get_ip_location(ip):
    location = reader.get(ip)

    try:
        country = location["country"]["names"]["en"]
    except:
        country = "Unknown"

    try:
        subdivision = location["subdivisions"][0]["names"]["en"]
    except:
        subdivision = "Unknown"
    try:
        city = location["city"]["names"]["en"]
    except:
        city = "Unknown"

    return country, subdivision, city


capture = pyshark.LiveCapture(interface='Беспроводная сеть')
capture.set_debug()
with open("filter_ips.txt") as f:
    ips = f.read().split("\n")
for packet in capture.sniff_continuously():
    try:
        if packet.ip.src not in ips:
            print(packet.ip.src, get_ip_location(packet.ip.src))
    except:
        pass
