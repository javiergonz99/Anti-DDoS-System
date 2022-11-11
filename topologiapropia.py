#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
import time


def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    #info( '*** Adding controller\n' )
    c0=net.addController(name='c0',controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6653)
            

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, failMode='standalone')
    

    info( '*** Add hosts\n')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)

    info( '*** Add links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
  

    info( '*** Starting network\n')
    net.build()
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([])

    net.start()
    
    #PARA ABRIR WIRESHARK
    time.sleep(10)
    '''
    #PRIMER ESCENARIO: HOST 2 MANDA 2 PAQUETES POR SEGUNDO AL HOST 1
    info("HOST 2 manda 2 paq/seg al HOST1\n")
    for i in range(20):
        for j in range(2):
            h2.cmd("nc 10.0.0.1 22 -w 1 &")
        time.sleep(1)
    
    
    #SEGUNDO ESCENARIO: HOST 2 MANDA 25 PAQUETES POR SEGUNDO CADA 6 SEGUNDOS AL HOST 1
    info("HOST 2 manda 5 paq/seg al HOST1\n")
    for i in range(10):
        for j in range(5):
            h2.cmd("nc 10.0.0.1 22 -w 1 &")
        time.sleep(1)
    
    
    #TERCER ESCENARIO: HOST 2 MANDA 25 PAQUETES POR SEGUNDO CADA 6 SEGUNDOS AL HOST 1
    info("HOST 2 manda 25 paq/seg cada 6s al HOST1\n")
    for i in range(5):
        for j in range(25):
            h2.cmd("nc 10.0.0.1 22 -w 1 &")
        time.sleep(6)
    
    
    #CUARTO ESCENARIO. Host 2 envia 3 paq/s al host 1 al puerto 22. Host 3 envia 6 paq/s al host 1.    
    #DOS ORIGENES, DOS PUERTOS DESTINO
    for i in range(12):
        h2.cmd("nc 10.0.0.1 22 -w 1 &")
        h3.cmd("nc 10.0.0.1 23 -w 1 &")
        h2.cmd("nc 10.0.0.1 22 -w 1 &")
        h3.cmd("nc 10.0.0.1 23 -w 1 &")
        h2.cmd("nc 10.0.0.1 22 -w 1 &")
        h3.cmd("nc 10.0.0.1 23 -w 1 &")
        h3.cmd("nc 10.0.0.1 23 -w 1 &")
        h3.cmd("nc 10.0.0.1 23 -w 1 &")
        h3.cmd("nc 10.0.0.1 23 -w 1 &")
        time.sleep(1)
    '''
    
    #QUINTO ESCENARIO. Host 2 envia 6 paq/s al host 1 al puerto 22. Host 3 envia 6 paq/s al host 1.    
    #DOS ORIGENES, DOS PUERTOS DESTINO
    for i in range(6):
        for j in range(6):
            h2.cmd("nc 10.0.0.1 22 -w 1 &")
            h3.cmd("nc 10.0.0.1 23 -w 1 &")
        time.sleep(1)

    

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
    
