from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm
from mininet.log import setLogLevel, info

def myNetwork():
    net = Mininet(controller=RemoteController)
    
    #Add Controller
    #info( '*** Adding controller\n' )
    c0 = net.addController('c0', port=6633)

    #Add Switches
    #info( '*** Add switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')
    s5 = net.addSwitch('s5')
    s6 = net.addSwitch('s6')
    s7 = net.addSwitch('s7')
    s8 = net.addSwitch('s8')
    s9 = net.addSwitch('s9')
    s10 = net.addSwitch('s10')
    s11 = net.addSwitch('s11')
    s12 = net.addSwitch('s12')
    s13 = net.addSwitch('s13')
    s14 = net.addSwitch('s14')
    s15 = net.addSwitch('s15')
    s16 = net.addSwitch('s16')
    s17 = net.addSwitch('s17')
    s18 = net.addSwitch('s18')
    s19 = net.addSwitch('s19')
    s20 = net.addSwitch('s20')

    #Add hosts
    #info( '*** Add hosts\n')
    h1 = net.addHost('h1',mac='00:00:00:00:00:01')
    h2 = net.addHost('h2',mac='00:00:00:00:00:02')
    h3 = net.addHost('h3',mac='00:00:00:00:00:03')
    h4 = net.addHost('h4',mac='00:00:00:00:00:04')
    h5 = net.addHost('h5',mac='00:00:00:00:00:05')
    h6 = net.addHost('h6',mac='00:00:00:00:00:06')
    h7 = net.addHost('h7',mac='00:00:00:00:00:07')
    h8 = net.addHost('h8',mac='00:00:00:00:00:08')

    #Add links switch to switch
    #info( '*** Add links switch to switch\n')
    net.addLink(s1, s5, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s1, s7, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s1, s9, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s1, s11, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s2, s5, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s2, s7, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s2, s9, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s2, s11, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s3, s6, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s3, s8, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s3, s10, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s3, s12, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s4, s6, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s4, s8, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s4, s10, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s4, s12, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s5, s13, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s5, s14, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s6, s14, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s6, s13, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s7, s15, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s7, s16, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s8, s16, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s8, s15, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s9, s17, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s9, s18, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s10, s17, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s10, s18, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s11, s19, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s11, s20, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s12, s19, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s12, s20, bw=20.0, delay='0ms', use_htb=True)
    
    #Add links switches to hosts
    #info( '*** Add links switch to host\n')
    net.addLink(s13, h1, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s14, h2, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s15, h3, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s16, h4, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s17, h5, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s18, h6, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s19, h7, bw=20.0, delay='0ms', use_htb=True)
    net.addLink(s20, h8, bw=20.0, delay='0ms', use_htb=True)
    
    #Start Network
    #info( '*** Starting network\n')
    net.build()
    #Start Controller
    #info( '*** Starting controllers\n')
    c0.start()
    #Start Switches
    #info( '*** Starting switches\n')
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])
    s5.start([c0])
    s6.start([c0])
    s7.start([c0])
    s8.start([c0])
    s9.start([c0])
    s10.start([c0])
    s11.start([c0])
    s12.start([c0])
    s13.start([c0])
    s14.start([c0])
    s15.start([c0])
    s16.start([c0])
    s17.start([c0])
    s18.start([c0])
    s19.start([c0])
    s20.start([c0])

    CLI(net)

    net.stop()

if '__main__' == __name__:
    setLogLevel( 'info' )
    myNetwork()