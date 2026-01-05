APPLICATIONS = {
    "web": {"protocol": "HTTP", "transport": "TCP", "port": 80},
    "dns": {"protocol": "DNS", "transport": "UDP", "port": 53}
}


packet = {}
ip_validations = {}

def ip_validate(ip_add:str):
    octets = [octet for octet in ip_add.split('.')]
    if len(octets) == 4:
        try:
            octets = [int(octet) for octet in octets]
            for octet in octets:
                if octet >= 0 and octet <= 255:
                    pass
                else:
                    print("One or more octets are out of range..")
                    return False
        except ValueError as e:
            print("Invalid literal in IPV4 add instead of an int..")
            return False
        
        return True
    else:
        print("One or more IPV4 addresses are incorrect..")
        return False
       
def application_data(app_type,payload,src_ip,dest_ip):
    app_protocol = None
    try:
        app_protocol = APPLICATIONS[app_type]['protocol']
    except KeyError as e:
        print(f"The application protocol could not be located with key : {app_type}..")
        app_protocol = None
    app_payload = payload
    if app_protocol != None:
        app_PDU = {
            "application" : {
                    "protocol" : app_protocol,
                    "payload" : app_payload
                }
        }
    else:
        print("Stopped due to app_protocol : None..")
        return 0
    packet.update(app_PDU)
    transport_selection(app_type,src_ip,dest_ip)            

def transport_selection(app_type,src_ip,dest_ip):
    transport_protocol = APPLICATIONS[app_type]["transport"]
    destination_port = APPLICATIONS[app_type]['port']
    # transport_PDU = app_PDU
    transport_data = {
        "transport" : {
            "protocol" : transport_protocol,
            "dest_port" : destination_port
        }
    }
    # transport_PDU.update(transport_data)
    packet.update(transport_data)
    packet_encapsulation(src_ip,dest_ip)

def packet_encapsulation(src_ip,dest_ip):
    if ip_validate(src_ip):
        ip_check = {"src_ip_valid" : True}
        ip_validations.update(ip_check)
    else:
        ip_check = {"src_ip_valid" : False}
        ip_validations.update(ip_check)
        return
    if ip_validate(dest_ip):
        ip_check = {"dest_ip_valid" : True}
        ip_validations.update(ip_check)
    else:
        ip_check = {"dest_ip_valid" : False}
        ip_validations.update(ip_check)
        return
    # network_PDU = transport_PDU
    packet_data = {
        "network": {
        "src_ip" : src_ip,
        "dest_ip" : dest_ip
        }
    }
    # network_PDU.update(packet_data)
    packet.update(packet_data)
    return True

def result():
    layers = []
    if "application" in packet:
        layers.append("Application")
    if "transport" in packet:
        layers.append("Transport")
    if "network" in packet:
        layers.append("Network")
        print("\nPacket successfully constructed..")
        print("\nLayers present:")
        for layer in layers:
            print(f"- {layer}")
        print(f"\nTransport protocol : {packet['transport']['protocol']}")
        print(f"Destination port : {APPLICATIONS[app_type]['port']}")
        print(f"Source IP valid : {ip_validations['src_ip_valid']}")
        print(f"Destination IP valid : {ip_validations['dest_ip_valid']}")
    else:
        print("Packet was not constructed..")    

print("IPV4 Communication Simulator\n")
src_ip = input("Enter source IP :")
dest_ip = input("Enter destination IP :")
app_type = input('Application type :')
payload = input('Enter your payload :')

application_data(app_type,payload,src_ip,dest_ip)
result()

