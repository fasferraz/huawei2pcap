import sys
import datetime
import struct

#constants:

globalheader_ip = b'\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\xe4'

ipheader1 = b'\x45\x00'
ipheader3 = b'\x00\x00\x00\x00\xff'
ipheader5 = b'\x00\x00'
    
udpheader2 = b'\x00\x00'

sctpheader2 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03'
sctpheader4 = b'\x00\x00\x00\x00\x00\x00\x00\x00'

gsmtapheader1_ul = b'\x02\x04\x0d\x00\x40\x00\x00\x00\x00\x00\x00\x00'  #0d -> LTE RRC
gsmtapheader1_dl = b'\x02\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00'  #0d -> LTE RRC
gsmtapheader3 = b'\x00\x00\x00'

portsctp = b'\x8e\x3c'
portgsmtap = b'\x12\x79'

s1approtocol = b'\x00\x00\x00\x12' #S1AP
sctpprotocol = b'\x84'
udpprotocol = b'\x11'

def return_date(aux):
    year, month, day, hour, milissecond = aux[6:10], aux[0:2], aux[3:5], aux[11:19], aux[21:-1]     
    utc = int((datetime.datetime.strptime(year + '-' + month + '-' + day + ' ' + hour, '%Y-%m-%d %H:%M:%S') - datetime.datetime(1970,1,1)).total_seconds())              
    hour_packet = struct.pack("!I", utc)
    milissecond_packet = struct.pack("!I", int(milissecond)*1000)     
    
    return hour_packet,milissecond_packet

def bytes2hex(byteArray):     
    return ''.join(hex(i).replace("0x", "0x0")[-2:] for i in byteArray)

def hex2bytes(hexString):
    return bytearray.fromhex(hexString)

def hex2int(hexString):
    return int.from_bytes(hex2bytes(hexString), "big") 
    
def huawei_channel_mapping(id): #dl=0/ul=1  #maps lte huawei channel code to gsmtap code
#returns gsmtap code, direction
    if id == 1: return 1,0
    elif id == 2: return 3,1
    elif id == 3: return 0,0
    elif id == 4: return 2,1
    elif id == 5: return 6,0
    elif id == 6: return 5,0
    elif id == 7: return 4,1
    elif id == 30: return 15,0
    elif id == 31: return 17,1
    elif id == 32: return 14,0
    elif id == 33: return 16,1
    elif id == 34: return 21,0
    elif id == 35: return 20,0   
    elif id == 36: return 18,1


def main():
    if len(sys.argv) == 3:
        try:        
            f = open(sys.argv[1], 'rt')
        except:
            print('Error opening csv file')
            exit()
        try:            
            s = open(sys.argv[2], 'wb')
        except:
            print('Error creating file to save')
            exit()
    else:
        print('Usage: python3 huawei2pcap.py <file_csv_to_read> <file_pcap_to_save>')
        exit()
         
    s.write(globalheader_ip)
    
    for line in f:
        array = line.split(',')
        if len(array) == 10 and array[0] != '"No."':
            hour_packet, milissecond_packet = return_date(array[1])    
            
            packet = array[9].replace(' ','')[:-1]   #to remove spaces and CR/LF

            if array[3][0:2] == 'To':
                ipsource = b'\x01\x01\x01\x01'
                ipdestination = b'\x02\x02\x02\x02'    
            else:
                ipsource = b'\x02\x02\x02\x02'
                ipdestination = b'\x01\x01\x01\x01'                            
                
            #### S1AP ####
            if array[2][0:4] == 'S1AP':
                             
                sctplen = int(len(packet) / 2 + 16)
                sctppadding = ''
                if sctplen % 4 != 0:
                    sctppadding = '00'*(4-(sctplen % 4))
                    
                packet += sctppadding
                iplen = int(sctplen + 32 + len(sctppadding) / 2)
                            
                final_packet = ipheader1 + struct.pack("!H",iplen) + ipheader3 + sctpprotocol + ipheader5 \
                    + ipsource + ipdestination + portsctp + portsctp + sctpheader2 \
                    + struct.pack("!H",sctplen) + sctpheader4 + s1approtocol  + hex2bytes(packet)          
            
            #### RRC ####
            elif array[2][0:3] == 'RRC':    

                channel_type = hex2int(packet[0:2])

                packet = packet[2:]
                
                iplen = int(len(packet) / 2 + 28 + 16)
                udplen = iplen - 20                
                
                gsmtap_channel, direction = huawei_channel_mapping(channel_type)
                if direction == 0: #dl
                    gsmtap = gsmtapheader1_dl + bytes([gsmtap_channel]) + gsmtapheader3
                else:
                    gsmtap = gsmtapheader1_ul + bytes([gsmtap_channel]) + gsmtapheader3
                               
                final_packet = ipheader1 + struct.pack("!H",iplen) + ipheader3 + udpprotocol + ipheader5  \
                    + ipsource + ipdestination + portgsmtap + portgsmtap + struct.pack("!H",udplen) \
                    + udpheader2 + gsmtap + hex2bytes(packet)          
                        
            
            packetheaderfinal_packet = hour_packet + milissecond_packet + b'\x00\x00' \
                + struct.pack("!H",len(final_packet)) + b'\x00\x00' + struct.pack("!H",len(final_packet)) \
                + final_packet
            s.write(packetheaderfinal_packet)


if __name__ == "__main__":
    main()        
