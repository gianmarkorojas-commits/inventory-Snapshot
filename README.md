# inventory-Snapshot
takes a timestamped snapshot of the current IPv4 ARP/neighbor cache, appends it to a JSONL log, and diffs it against the previous snapshot — reporting stable devices, new devices, devices not seen, and (the thing the whole exercise is for) a known MAC showing up at a different IP.
