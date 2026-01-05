
class PacketBuilder:
    APPLICATIONS = {
    "web": {"protocol": "HTTP", "transport": "TCP", "port": 80},
    "dns": {"protocol": "DNS", "transport": "UDP", "port": 53}}

    def __init__(self):
        self.packet = {}
        self.errors = []
        self.data_for_transport_layer = None

    def ip_validate(self,ip_add):
        octets = [octet for octet in ip_add.split('.')]
        if len(octets) == 4:
            try:
                octets = [int(octet) for octet in octets]
                for octet in octets:
                    if octet >= 0 and octet <= 255:
                        pass
                    else:
                        return False
            except ValueError as e:
                return False
            
            return True
        else:
            return False
        
    def application_layer(self,app_type,payload):
        if app_type not in self.APPLICATIONS:
            self.errors.append(f"Apptype {app_type} is unknown..")
            return
        
        app_data = self.APPLICATIONS[app_type]
        self.packet['application'] = {
                    "protocol" : app_data['protocol'],
                    "payload" : payload
                }
       
        self.data_for_transport_layer = app_data         

    def transport_layer(self):
        if 'application' not in self.packet:
            return
        app_data = self.data_for_transport_layer

        self.packet['transport'] = {
                "protocol" : app_data["transport"],
                "dest_port" : app_data["port"]
            }

    def network_layer(self,src_ip,dest_ip):
        src_check = self.ip_validate(src_ip)
        dest_check = self.ip_validate(dest_ip)
        self.packet['network'] = {
            "src_ip" : "⚠️",
            "dest_ip" : "⚠️"
        }
        if src_check:
            self.packet['network']['src_ip'] = src_ip
        else:
            self.errors.append(f"Invalid source ip : {src_ip}..")

        if dest_check:
            self.packet['network']['dest_ip'] = dest_ip
        else:
            self.errors.append(f"Invalid destination ip : {dest_ip}..")


    def result(self):
        print("\n--Packet Analysis--")
        if self.errors:
            print(f"\n⚠️  Alert: Packet contains {len(self.errors)} errors (see details below)..")

        application = self.packet.get('application',{})
        transport = self.packet.get('transport',{})
        network = self.packet.get('network',{})

     
        print("\nLayers Constructed:")
        print(f"\n└──[Network] -> Source IP : {network.get('src_ip')}  | Destination IP : {network.get('dest_ip')}")
        if transport:
            print(f"\n └──[Transport] -> Protocol : {transport.get('protocol')} | Port : {transport.get('dest_port')}")
        if application:
            print(f"\n  └──[Application] -> Protocol : {application.get('protocol')} | Payload : {application.get('payload')}")
        
        if self.errors:
            print("\n❌ Following fixes are required:\n")
            for error in self.errors:
                print(f"{self.errors.index(error) + 1}. {error}..")
        else:
            print("\n✅ Packet constructed successfully.")
        print("\n")


def main():
    print("\nPacket Encapsulation Simulator\n")
    src_ip = input("Enter source IP :")
    dest_ip = input("Enter destination IP :")
    app_type = input('Application type :').lower()
    payload = input('Enter your payload :')
    builder = PacketBuilder()
    builder.application_layer(app_type,payload)
    builder.transport_layer()
    builder.network_layer(src_ip,dest_ip)
    builder.result()

main()