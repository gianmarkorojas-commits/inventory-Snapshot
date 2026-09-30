# inventory-Snapshot
takes a timestamped snapshot of the current IPv4 ARP/neighbor cache, appends it to a JSONL log, and diffs it against the previous snapshot — reporting stable devices, new devices, devices not seen, and (the thing the whole exercise is for) a known MAC showing up at a different IP.


python3 inventory_snapshot.py snapshot   # take one, append, show diff vs previous
python3 inventory_snapshot.py diff       # re-show the last diff without taking a new snapshot
python3 inventory_snapshot.py history    # list all snapshots taken
