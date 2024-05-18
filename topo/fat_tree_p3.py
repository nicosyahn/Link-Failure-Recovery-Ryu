from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController

if '__main__' == __name__:
    net = Mininet(controller=RemoteController)

    #Add Controller
    c0 = net.addController('c0',port=6633)

    #Add Switches
    s1 = net.addSwitch('s1',cls=OVSSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2',cls=OVSSwitch, protocols='OpenFlow13')
    s3 = net.addSwitch('s3',cls=OVSSwitch, protocols='OpenFlow13')
    s4 = net.addSwitch('s4',cls=OVSSwitch, protocols='OpenFlow13')
    
    s5 = net.addSwitch('s5',cls=OVSSwitch, protocols='OpenFlow13')
    s6 = net.addSwitch('s6',cls=OVSSwitch, protocols='OpenFlow13')
    s7 = net.addSwitch('s7',cls=OVSSwitch, protocols='OpenFlow13')
    s8 = net.addSwitch('s8',cls=OVSSwitch, protocols='OpenFlow13')
                               
    s9 = net.addSwitch('s9',cls=OVSSwitch, protocols='OpenFlow13')
    s10 = net.addSwitch('s10',cls=OVSSwitch, protocols='OpenFlow13')
    s11 = net.addSwitch('s11',cls=OVSSwitch, protocols='OpenFlow13')
    s12 = net.addSwitch('s12',cls=OVSSwitch, protocols='OpenFlow13')
                               
    s13 = net.addSwitch('s13',cls=OVSSwitch, protocols='OpenFlow13')
    s14 = net.addSwitch('s14',cls=OVSSwitch, protocols='OpenFlow13')
    s15 = net.addSwitch('s15',cls=OVSSwitch, protocols='OpenFlow13')
    s16 = net.addSwitch('s16',cls=OVSSwitch, protocols='OpenFlow13')
                               
    s17 = net.addSwitch('s17',cls=OVSSwitch, protocols='OpenFlow13')
    s18 = net.addSwitch('s18',cls=OVSSwitch, protocols='OpenFlow13')
    s19 = net.addSwitch('s19',cls=OVSSwitch, protocols='OpenFlow13')
    s20 = net.addSwitch('s20',cls=OVSSwitch, protocols='OpenFlow13')

    #Add Hosts
    h1 = net.addHost('h1',ip='192.168.0.1/24')
    h2 = net.addHost('h2',ip='192.168.0.2/24')
    h3 = net.addHost('h3',ip='192.168.0.3/24')
    h4 = net.addHost('h4',ip='192.168.0.4/24')

    h5 = net.addHost('h5',ip='192.168.0.5/24')
    h6 = net.addHost('h6',ip='192.168.0.6/24')
    h7 = net.addHost('h7',ip='192.168.0.7/24')
    h8 = net.addHost('h8',ip='192.168.0.8/24')

    #Link Switch to Switch
    net.addLink(s1, s5), net.addLink(s1, s7)
    net.addLink(s1, s9), net.addLink(s1, s11)
    net.addLink(s2, s5), net.addLink(s2, s7)
    net.addLink(s2, s9), net.addLink(s2, s11)  
    net.addLink(s3, s6), net.addLink(s3, s8)
    net.addLink(s3, s10), net.addLink(s3, s12)
    net.addLink(s4, s6), net.addLink(s4, s8)
    net.addLink(s4, s10), net.addLink(s4, s12)
    net.addLink(s5, s13), net.addLink(s5, s14)
    net.addLink(s6, s13), net.addLink(s6, s14)    
    net.addLink(s7, s15), net.addLink(s7, s16)
    net.addLink(s8, s15), net.addLink(s8, s16)    
    net.addLink(s9, s17), net.addLink(s9, s18)
    net.addLink(s10, s17), net.addLink(s10, s18)    
    net.addLink(s11, s19), net.addLink(s11, s20)            
    net.addLink(s12, s19), net.addLink(s12, s20)

    #Link Host To Switch
    net.addLink(h1, s13)  
    net.addLink(h2, s14)  
    net.addLink(h3, s15)  
    net.addLink(h4, s16)  
    net.addLink(h5, s17)  
    net.addLink(h6, s18)  
    net.addLink(h7, s19)  
    net.addLink(h8, s20) 

    #Start Network
    net.build()
    c0.start()
    s1.start([c0]), s2.start([c0])
    s3.start([c0]), s4.start([c0])
    s5.start([c0]), s6.start([c0])
    s7.start([c0]), s8.start([c0])
    s9.start([c0]), s10.start([c0])
    
    s11.start([c0]), s12.start([c0])
    s13.start([c0]), s14.start([c0])
    s15.start([c0]), s16.start([c0])
    s17.start([c0]), s18.start([c0])
    s19.start([c0]), s20.start([c0])

    #net.startTerms()

    CLI(net)

    net.stop()

