import pyshark, time, json

bpf_filter = "tcp port 8000"
capture = pyshark.LiveCapture(interface="eth0", bpf_filter=bpf_filter)

#open file 
with open("log.json", "r+") as f:
    #read last data
    data = json.loads(f.read())
    for packet in capture.sniff_continuously():
        # adjusted output
        try:
            #reset the file
            f.seek(0)

            # get timestamp
            localtime = time.asctime(time.localtime(time.time()))
        
            # get packet content
            protocol = packet.transport_layer   # protocol type
            src_addr = packet.ip.src            # source address
            src_port = packet[protocol].srcport   # source port
            dst_addr = packet.ip.dst            # destination address
            dst_port = packet[protocol].dstport   # destination port

            #add data to array for log
            log = {
                "time":localtime,
                "source-ip":src_addr,
                "source-port":src_port,
                "destination-ip":dst_addr,
                "destination-port":dst_port,
                "protocol":protocol
            }

            print("\n")
            # output packet info
            print("%s IP %s:%s <-> %s:%s (%s)" % (localtime, src_addr, src_port, dst_addr, dst_port, protocol))
            print("_"*100)

            #log the data
            data["log"].append(log)
            f.write(json.dumps(data))
        except AttributeError as e:
            # ignore packets other than TCP, UDP and IPv4
            pass
    
 