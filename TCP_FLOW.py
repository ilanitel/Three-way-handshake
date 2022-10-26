from scapy.all import *


'''
created by ilanit elsa

'''

'''
PART 1

Three way handshake
Create a Scapy function that receives an IP address, port number, and a text message as arguments. It then
creates a full three-way TCP handshake.
The function must fulfill the following requirements:
a. The function returns 2 variables, one Boolean and one String.
b. If the function successfully connects to the port the Boolean variable returned will be True.
c. The function sends the text message variable to the target after a successful connection and saves
the reply to a string variable – returning it at the end of the program as the String variable
d. If the connection fails, the function returns the Boolean variable as False the string will return as
None
'''
#This fuction we try to implement a tcp connection with an ip,port and send a payload
def tcp_flow(targe_ip,target_port,msg):
    #variables
    is_succssed = False
    ip = IP(dst=targe_ip)
    #Step 1 : send syn request
    #First we will check if the target host is alive and if destination port is open by sending syn packet with a syn request
    syn_request = ip/TCP(dport=int(target_port))
    # Send the packet and get answers and answers
    ans,unans = sr(syn_request,timeout=1)
    #Checking if we receive an answer
    if not ans:
        #If we don't get an answer we will send feedback
        return is_succssed,f'Host {target_port} is offline'
    else:
        # Step 2 find syn_ack response
        #We receved a list as a response and we need to look for the syn flag
        for snd,rcv in ans:
            if rcv[TCP].flags == 'SA':
                #Step 3 send an ack request
                # To finsh the three hadeshake we will send an ack request
               ack_request = ip/TCP(dport=int(target_port),flags='A',seq=rcv.seq+1,ack=snd.seq+1)/Raw(load=msg)
               ack_request.show()
               send(ack_request)
               is_succssed = True
               msg = (ack_request[Raw].load).decode('utf-8')
            else:
                msg = None
                print(f'Host is alive but {target_port} is close')

    return is_succssed,msg

f,a = tcp_flow('140.82.112.4',80,'TCL FLOW')
print(f,a)
f,a = tcp_flow('140.82.110.4',443,'TCL FLOW')
print(f,a)