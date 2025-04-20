from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
from datetime import datetime
from random import randrange, choice
from time import sleep, time
from random import choice

class MyTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h1 = self.addHost('h1', cpu=1.0/20, mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost('h2', cpu=1.0/20, mac="00:00:00:00:00:02", ip="10.0.0.2/24")
        h3 = self.addHost('h3', cpu=1.0/20, mac="00:00:00:00:00:03", ip="10.0.0.3/24")    

        s2 = self.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h4 = self.addHost('h4', cpu=1.0/20, mac="00:00:00:00:00:04", ip="10.0.0.4/24")
        h5 = self.addHost('h5', cpu=1.0/20, mac="00:00:00:00:00:05", ip="10.0.0.5/24")
        h6 = self.addHost('h6', cpu=1.0/20, mac="00:00:00:00:00:06", ip="10.0.0.6/24")

        s3 = self.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h7 = self.addHost('h7', cpu=1.0/20, mac="00:00:00:00:00:07", ip="10.0.0.7/24")
        h8 = self.addHost('h8', cpu=1.0/20, mac="00:00:00:00:00:08", ip="10.0.0.8/24")
        h9 = self.addHost('h9', cpu=1.0/20, mac="00:00:00:00:00:09", ip="10.0.0.9/24")

        s4 = self.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h10 = self.addHost('h10', cpu=1.0/20, mac="00:00:00:00:00:10", ip="10.0.0.10/24")
        h11 = self.addHost('h11', cpu=1.0/20, mac="00:00:00:00:00:11", ip="10.0.0.11/24")
        h12 = self.addHost('h12', cpu=1.0/20, mac="00:00:00:00:00:12", ip="10.0.0.12/24")

        s5 = self.addSwitch('s5', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h13 = self.addHost('h13', cpu=1.0/20, mac="00:00:00:00:00:13", ip="10.0.0.13/24")
        h14 = self.addHost('h14', cpu=1.0/20, mac="00:00:00:00:00:14", ip="10.0.0.14/24")
        h15 = self.addHost('h15', cpu=1.0/20, mac="00:00:00:00:00:15", ip="10.0.0.15/24")

        s6 = self.addSwitch('s6', cls=OVSKernelSwitch, protocols='OpenFlow13')
        h16 = self.addHost('h16', cpu=1.0/20, mac="00:00:00:00:00:16", ip="10.0.0.16/24")
        h17 = self.addHost('h17', cpu=1.0/20, mac="00:00:00:00:00:17", ip="10.0.0.17/24")
        h18 = self.addHost('h18', cpu=1.0/20, mac="00:00:00:00:00:18", ip="10.0.0.18/24")

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)

        self.addLink(h7, s3)
        self.addLink(h8, s3)
        self.addLink(h9, s3)

        self.addLink(h10, s4)
        self.addLink(h11, s4)
        self.addLink(h12, s4)

        self.addLink(h13, s5)
        self.addLink(h14, s5)
        self.addLink(h15, s5)

        self.addLink(h16, s6)
        self.addLink(h17, s6)
        self.addLink(h18, s6)

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s6)

def ip_generator():
    ip = ".".join(["10","0","0",str(randrange(1,19))])
    return ip

def generate_ddos_traffic(hosts):
    src = choice(hosts)
    dst = ip_generator()   
    print("--------------------------------------------------------------------------------")
    print("Performing ICMP (Ping) Flood")  
    print("--------------------------------------------------------------------------------")   
    src.cmd("timeout 12s hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood {}".format(dst))  
    sleep(3)
        
    src = choice(hosts)
    dst = ip_generator()   
    print("--------------------------------------------------------------------------------")
    print("Performing UDP Flood")  
    print("--------------------------------------------------------------------------------")   
    src.cmd("timeout 12s hping3 -2 -V -d 120 -w 64 --rand-source --flood {}".format(dst))    
    sleep(3)
    
    src = choice(hosts)
    dst = ip_generator()    
    print("--------------------------------------------------------------------------------")
    print("Performing TCP-SYN Flood")  
    print("--------------------------------------------------------------------------------")
    src.cmd('timeout 12s hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.1')
    sleep(3)
    
    # src = choice(hosts)
    # dst = ip_generator()   
    # print("--------------------------------------------------------------------------------")
    # print("Performing LAND Attack")  
    # print("--------------------------------------------------------------------------------")   
    # src.cmd("timeout 20s hping3 -1 -V -d 120 -w 64 --flood -a {} {}".format(dst,dst))
    # sleep(100)  
    # print("--------------------------------------------------------------------------------")



def generate_normal_traffic(hosts, h1):
    print("--------------------------------------------------------------------------------")    
    print("Generating normal traffic ...")    
    h1.cmd('cd /home/mininet/webserver')
    h1.cmd('python -m SimpleHTTPServer 80 &')
    h1.cmd('iperf -s -p 5050 &')
    h1.cmd('iperf -s -u -p 5051 &')
    sleep(2)
    
    for h in hosts:
        h.cmd('cd /home/mininet/Downloads')
    
    start_time = time()
    j = 0
    while time() - start_time < 120 and j < 50:  # upper bound to prevent infinite loop
        src = choice(hosts)
        dst = ip_generator()
        
        if j < 9:
            print("generating ICMP traffic between %s and h%s and TCP/UDP traffic between %s and h1" % (src, ((dst.split('.'))[3]), src))
            src.cmd("ping {} -c 100 &".format(dst))
            src.cmd("iperf -p 5050 -c 10.0.0.1")
            src.cmd("iperf -p 5051 -u -c 10.0.0.1")
        else:
            print("generating ICMP traffic between %s and h%s and TCP/UDP traffic between %s and h1" % (src, ((dst.split('.'))[3]), src))
            src.cmd("ping {} -c 100".format(dst))
            src.cmd("iperf -p 5050 -c 10.0.0.1")
            src.cmd("iperf -p 5051 -u -c 10.0.0.1")
        
        print("%s Downloading index.html from h1" % src)
        src.cmd("wget http://10.0.0.1/index.html")
        print("%s Downloading test.zip from h1" % src)
        src.cmd("wget http://10.0.0.1/test.zip")

        j += 1

    h1.cmd("rm -f *.* /home/mininet/Downloads")
    print("--------------------------------------------------------------------------------")  

def startNetwork():
    # Get user input for iterations and traffic pattern
    while True:
        try:
            iterations = int(input("Enter number of iterations: "))
            if iterations <= 0:
                print("Please enter a positive integer")
                continue
                
            print("Enter traffic pattern (0 for normal, 1 for DDoS)")
            pattern = input(f"Enter {iterations}-digit string (e.g. '010' for 3 iterations): ")
            
            if len(pattern) != iterations or not all(c in '01' for c in pattern):
                print(f"Please enter exactly {iterations} digits with only 0 or 1")
                continue
                
            break
        except ValueError:
            print("Please enter a valid number")
    
    # Start network
    topo = MyTopo()
    c0 = RemoteController('c0', ip='10.200.244.53', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)
    net.start()
    
    # Get all hosts
    hosts = [net.get(f'h{i}') for i in range(1, 19)]
    h1 = hosts[0]
    
    start_time = datetime.now()
    
    # Run iterations based on user input
    for i, traffic_type in enumerate(pattern):
        print(f"\n=== Iteration {i+1} of {iterations} ===")
        print(f"Traffic type: {'DDoS' if traffic_type == '1' else 'Normal'}")
        
        if traffic_type == '1':
            generate_ddos_traffic(hosts)
        else:
            generate_normal_traffic(hosts, h1)
    
    end_time = datetime.now()
    print(f"\nTotal execution time: {end_time - start_time}")
    
    # CLI(net)  # Uncomment if you want to keep the CLI open after execution
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    startNetwork()