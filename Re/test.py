from netzob.all import *

pseudos = ["zoby", "ditrich", "toto", "carlito"]
cities = ["Paris", "Munich", "Barcelone", "Vienne"]
ips = ["192.168.0.10", "10.120.121.212", "78.167.23.10"]
# Creation of the different types of message
# msgsType1 = [ RawMessage("hello {0}, what's up in {1} ?".format(pseudo, city).encode('utf-8')) for pseudo in pseudos for city in cities]
# msgsType2 = [ RawMessage("My ip address is {0}".format(ip).encode('utf-8')) for ip in ips]
# msgsType3 = [ RawMessage("Your IP is {0}, name = {1} and city = {2}".format(ip, pseudo, city).encode('utf-8')) for ip in ips for pseudo in pseudos for city in cities]
# messages = msgsType1 + msgsType2 + msgsType3
messages=["160303007a020000760303","none","1403030001011703030045","none"]
rows=[]
for seq in messages:
    rows.append(RawMessage(seq.encode('utf-8')))
print(rows)

symbols = Format.clusterByAlignment(rows)
print(symbols)
Format.splitAligned(symbols[0])
print(symbols[1])
