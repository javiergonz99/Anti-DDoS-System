# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,ipv4,tcp,udp
from ryu.lib.packet import ether_types
import json
from datetime import datetime
from scapy.all import TCP, rdpcap
import math
from colorama import Fore, Back, Style
#from pruebas import ListaPaquetes

#Esta clase es la que se encarga del control total del reenvio de paquetes en el switch. Se controlan todos los paquetes mediante el analisis y comparacion
#con las políticas implementadas.
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    
    Politicas = {}
    Politicas['Datos'] = {}
    Politicas['Datos']['10.0.0.1'] = {}
    Politicas['Datos'].update({'10.0.0.1': {
    'politica1': {'puerto': '22', 'tasa': '4','tamano_VentanaTiempo': '5','origenes':{},'IPs_bloqueadas':{},'tiempo_bloqueo':3},
    'politica2':{'puerto': '23', 'tasa': '4','tamano_VentanaTiempo': '6','origenes':{},'IPs_bloqueadas':{},'tiempo_bloqueo':3}
    }})

    with open('Politicas.json', 'w') as file:
        json.dump(Politicas,file,indent=4)
    

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg  #Obtiene un objeto del tipo ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn
        #print(msg)
        datapath = msg.datapath #obtiene objeto tipo ryu.controller.controller.Datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        print("-----------------------------------------------------------")
        
        
        
        pkt = packet.Packet(msg.data) #objeto tipo ryu.lib.packet.packet.Packet
        
        instante_llegada = int(time.time())
        print(Fore.RED + "[+] Recibido paquete: ", datetime.fromtimestamp(instante_llegada))
        print(Style.RESET_ALL)

        with open('Politicas.json') as file:
            Politicas = json.load(file)
        
        IP_origen = ""
        IP_destino = ""
        global CONTADOR_PAQUETES
        CONDICION = 1
        CONDICIONBLOQUEO = 1
        OTRO_PUERTO = 0
        
        
        for p in pkt.protocols:
            #print("-----------------------------------------------------------")
            #print(p)
            #SE COMPRUEBA QUE EL DESTINO ESTA EN LA LISTA DE SERVIDORES DESTINO
            if(p.protocol_name == "ipv4"):
                for destino in Politicas['Datos'].keys():
                    if(destino == p.dst):
                        IP_origen = p.src
                        IP_destino = p.dst
            
        #Se comprueba primero si se trata de un paquete ARP de Broadacast
        if(IP_destino == ""):
            print("\tPaquete ARP")
            eth = pkt.get_protocols(ethernet.ethernet)[0] #ryu.lib.packet.ethernet.ethernet
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                # ignore lldp packet
                return
            
            dst = eth.dst
            src = eth.src

            dpid = format(datapath.id, "d").zfill(16)
            self.mac_to_port.setdefault(dpid, {})

            self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            '''
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            '''
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            

        #SE COMPRUEBA SI EXISTE ALGUNA REGLA QUE COINCIDA CON EL PUERTO DESTINO. Se recorren
        #las politicas del destino previamente comprobado para buscar coincidencias. Ademas se buscan coincidencias de bloqueos de IPs
        else:
            if(p.protocol_name == "tcp" ):
                print("\tIP origen: " + IP_origen)
                print("\tPuerto destino: " + str(p.dst_port))
                #Se comprueba si el puerto destino del paquete coincide con alguna politica
                for politica in Politicas['Datos'][IP_destino].keys():
                    #print(politica)
  
                    if(Politicas['Datos'][IP_destino][politica]['puerto'] == str(p.dst_port)):
                        print("\tPolitica aplicada: " + politica)
                        #Se comprueba si la IP origen esta bloqueada, y en caso afirmativo, se comprueba si ha superado ya el limite de bloqueo.
                        #Si no lo ha superado, no se envia paquete. En caso de haber superado el limite, se puede volver a guardar paquetes y reenviar
                        if(IP_origen in Politicas['Datos'][IP_destino][politica]['IPs_bloqueadas'].keys()):
                            instante_bloqueo = Politicas['Datos'][IP_destino][politica]['IPs_bloqueadas'][IP_origen]
                            #Si la diferencia entre el instante actual y el de bloque es mayor que el tiempo de bloqueo, se habra superado ya dicho tiempo.
                            #Por tanto, se elimina la IP origen de la lista de IPs bloqueadas
                            if((instante_llegada-instante_bloqueo)>= Politicas['Datos'][IP_destino][politica]['tiempo_bloqueo']):
                                CONDICION = 1
                                del Politicas['Datos'][IP_destino][politica]['IPs_bloqueadas'][IP_origen]
                            else:
                                print("\tEstado politica: ACTIVADO BLOQUEO")
                                CONDICION = 0


                        if(CONDICION == 1):                          
                            tasa_politica = int(Politicas['Datos'][IP_destino][politica]['tasa'])
                        #Se comprueba si el origen esta ya incluido en la lista de origenes de la politica. 
                       
                            lista_origenes = list(Politicas['Datos'][IP_destino][politica]['origenes'].keys())
                            #Si el origen no esta incluido, se crea el diccionario para contar el par seg-paq.
                            if(IP_origen not in lista_origenes):
                                #print("CASO 1. La IP origen es "+ IP_origen + " y el puerto destino es " + str(p.dst_port))
                                #CREACION LISTA SEG-PAQUETES POR ORIGEN
                                CONTADOR_PAQUETES = ListaPaquetes(int(Politicas['Datos'][IP_destino][politica]['tamano_VentanaTiempo']))
                                Actualizado_PAQ_SEG = CONTADOR_PAQUETES.anade_paquete(instante_llegada,CONTADOR_PAQUETES.paquetes_segundos)
                                Politicas['Datos'][IP_destino][politica]['origenes'].update({IP_origen:Actualizado_PAQ_SEG})
                                eth = pkt.get_protocols(ethernet.ethernet)[0] #ryu.lib.packet.ethernet.ethernet
                                
                        #Cuando si se encuentre el origen en el diccionario, se sumara un paquete al segundo correspondiente. Posteriormente 
                        #se comprueba si la tasa de llegada de un origen es mayor que la tasa estipulada en la tasa. Si es mayor, se bloquea dicha IP
                        #y se anade el instante de bloqueo.
                            else:
                                #print("CASO 2. La IP origen es "+ IP_origen + " y el puerto destino es " + str(p.dst_port))
                                #OBTENCION LISTA DE SEG-PAQUETES DE ORIGEN CONCRETO
                                RECUENTO_PAQ_SEG = Politicas['Datos'][IP_destino][politica]['origenes'][IP_origen]
                                Actualizado_PAQ_SEG = CONTADOR_PAQUETES.anade_paquete(instante_llegada,RECUENTO_PAQ_SEG)
                                Politicas['Datos'][IP_destino][politica]['origenes'].update({IP_origen:Actualizado_PAQ_SEG})
                                tasa_calculada = CONTADOR_PAQUETES.calcula_tasa()
                                print("\tTasa trafico: " + str(tasa_calculada) + " paq/seg. Ventana: " + str(CONTADOR_PAQUETES.CW))
                                
                                if((tasa_calculada > tasa_politica) & (IP_origen not in Politicas['Datos'][IP_destino][politica]['IPs_bloqueadas'])):
                                    Politicas['Datos'][IP_destino][politica]['IPs_bloqueadas'].update({IP_origen:instante_llegada})
                                    CONDICIONBLOQUEO = 0

                            if(CONDICIONBLOQUEO == 1):

                                eth = pkt.get_protocols(ethernet.ethernet)[0] #ryu.lib.packet.ethernet.ethernet
                                if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                                    # ignore lldp packet
                                    return
                                
                                dst = eth.dst
                                src = eth.src

                                dpid = format(datapath.id, "d").zfill(16)
                                self.mac_to_port.setdefault(dpid, {})

                                self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)
                                # learn a mac address to avoid FLOOD next time.
                                self.mac_to_port[dpid][src] = in_port

                                if dst in self.mac_to_port[dpid]:
                                    out_port = self.mac_to_port[dpid][dst]
                                else:
                                    out_port = ofproto.OFPP_FLOOD

                                actions = [parser.OFPActionOutput(out_port)]                            
                                data = None
                                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                                    data = msg.data
                                
                                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                        in_port=in_port, actions=actions, data=data)
                                datapath.send_msg(out)
                                
                        with open('Politicas.json', 'w') as file:
                            json.dump(Politicas,file,indent=4)
                '''
                    else:
                        OTRO_PUERTO = 1
                        
                
                if(OTRO_PUERTO == 1):
                    eth = pkt.get_protocols(ethernet.ethernet)[0] #ryu.lib.packet.ethernet.ethernet
                    if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                    # ignore lldp packet
                        return
                                                
                    dst = eth.dst
                    src = eth.src
                    dpid = format(datapath.id, "d").zfill(16)
                    self.mac_to_port.setdefault(dpid, {})

                    self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)
                    # learn a mac address to avoid FLOOD next time.
                    self.mac_to_port[dpid][src] = in_port

                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD

                    actions = [parser.OFPActionOutput(out_port)]                            
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                                                
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                '''
class ListaPaquetes:
    
    def __init__(self, CW):  
        self.paquetes_segundos = {}
        self.CW = CW
        
        #Se crea un diccionario del tamano de la ventana de tiempo que se use en la tasa. 
        for pos in range(CW):
            self.paquetes_segundos[pos] = 0 

    #Metodo que permite anadir un paquete al segundo determinado.
    def anade_paquete(self,TS,ListaSEGUNDOS):
        #se redondea el timestamp hacia abajo
        self.paquetes_segundos = ListaSEGUNDOS
        #Lo tengo que pasar a STR porque al obtener el diccionario SEG-PAQ de cada origen, los SEG aparecen como string  
        TS_redondeado = str(int(math.floor(TS)))
        #Se comprueba si el segundo en el que ha llegado el paquete esta en el diccionario. En caso afirmativo, se suma 1 a ese segundo
        #y en caso negativo se elimina la primera posicion del diccionario y se anade el nuevo seg al final con valor 1.
        if(TS_redondeado in self.paquetes_segundos):
            self.paquetes_segundos[TS_redondeado] = self.paquetes_segundos[TS_redondeado] + 1
        else:
            valor_eliminar = next(iter(self.paquetes_segundos))  #Coge el primer valor de la primera posicion del diccionario
            del self.paquetes_segundos[valor_eliminar]
            self.paquetes_segundos.setdefault(TS_redondeado, 1)
        
        return self.paquetes_segundos

    #Método que permite calcula la tasa de llegada.
    def calcula_tasa(self):
        #Se obtiene el tamano de la lista de PAQ-SEQ y se guarda el ultimo seg registrado de la lista
        self.CW = len(list(self.paquetes_segundos.keys()))
        ultimo_seg_registrado = int(list(self.paquetes_segundos.keys())[self.CW-1])
        suma_paquetes = 0
    
        TASA = 0
        #Se comprueba si cada uno de los claves del diccionario es mayor que la resta del último segundo registrado menos el tamano ventana. En caso afirmativo, se
        #se anade el total de paquetes de ese segundo. 
        for registro in range(self.CW):
            if(int(list(self.paquetes_segundos.keys())[registro]) > ultimo_seg_registrado - self.CW):
                suma_paquetes = suma_paquetes + list(self.paquetes_segundos.values())[registro]
       
        TASA = suma_paquetes/(float(self.CW))
        
        return TASA
        
