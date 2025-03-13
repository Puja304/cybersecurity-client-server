import socket
import logging
from header import ReliableTransportLayerProtocolHeader
import random
import time

HOST = '127.0.0.1'   #IP for both sender and receiver
SENDER_PORT = 8001
RECEIVER_PORT = 8000  
WINDOW_SIZE = 4
MSS = 15
TIMEOUT = 180

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("Receiver")


#function that enables handshaking
def handshake(server_sock):

    global SENDER_PORT
    connection_details = {
        "Alive": False,
        "senderSeqNum": 0,
        "senderACKNum": 0,
        "receiverSeqNum": 0,
        "receiverACKNum": 0,
        "sender_mss" : 0
    }

    logger.info("Receiver: Waiting for SYN...")
    data, addr = server_sock.recvfrom(1024)
    data = ReliableTransportLayerProtocolHeader.from_bytes(data)

    #setting a value for SENDER_PORT
    SENDER_PORT = addr[1]

    if addr == (HOST, SENDER_PORT) and data.syn == 1:
        logger.info("Receiver: Received SYN, sending SYN-ACK...")
        connection_details["Alive"] = True
        connection_details["Port"] =  SENDER_PORT
        connection_details["senderSeqNum"] = data.seq_num
        connection_details["senderACKNum"] = data.seq_num + 1
        connection_details["receiverSeqNum"] = random.randint(0, 2000)
        connection_details["receiverACKNum"] = connection_details["senderSeqNum"] + 1
        connection_details["sender_mss"] = data.mss
        
        syn_ack_packet = ReliableTransportLayerProtocolHeader(RECEIVER_PORT, SENDER_PORT, connection_details["receiverSeqNum"], connection_details["receiverACKNum"], WINDOW_SIZE, MSS, syn=1, ack=1)
        server_sock.sendto(syn_ack_packet.to_bytes(), addr)
        logger.info("Receiver: Sent SYN-ACK.")

        # Wait for final ACK
        data, addr = server_sock.recvfrom(1024)
        data = ReliableTransportLayerProtocolHeader.from_bytes(data)
        if addr == (HOST, SENDER_PORT) and data.ack == 1 and data.ack_num == connection_details["receiverSeqNum"] + 1:
            logger.info("Receiver: Received final ACK. Handshake complete.")
            connection_details["senderSeqNum"] = data.seq_num + 2
    return connection_details


#writes down stuff in a file to verify the order is correct
def log_received_packet(packet_data, file_path="received_packets.txt"):
    try:
        with open(file_path, "a") as file:
            file.write(packet_data + "\n")
    except Exception as e:
        print(f"Error writing to file: {e}")


def accept_fin(server_sock,connection_details):

    print("Sending FINACK")
    finack = ReliableTransportLayerProtocolHeader(
        RECEIVER_PORT,
        SENDER_PORT,
        connection_details["receiverSeqNum"], 
        connection_details["receiverACKNum"],
        WINDOW_SIZE, 
        MSS, 
        fin=True, 
        ack=True)

    server_sock.sendto(finack.to_bytes(), (HOST, SENDER_PORT))

    try:
        time.sleep(5)
        data,addr = server_sock.recvfrom(1024)
        if (addr == (HOST,SENDER_PORT)):
            data = ReliableTransportLayerProtocolHeader.from_bytes(data)
            if (data.ack) :
                print("ACK received for FINACK. Connection Terminated")
            else:
                print("Connection continued")
    except:
        print('Connection timed out. Terminated. ')



#function that sends an ack when a file is received
def send_ack(server_socket, connnection_details):
    print(f"Sending ACK for {connnection_details["receiverACKNum"]}")
    ack = ReliableTransportLayerProtocolHeader(
        RECEIVER_PORT,
        SENDER_PORT, 
        connnection_details["receiverSeqNum"],
        connnection_details["receiverACKNum"] ,
        WINDOW_SIZE,
        MSS,
        ack=True )
    
    #send ack to sender
    server_socket.sendto(ack.to_bytes(), (HOST,SENDER_PORT))

    #update own sequence number:
    connnection_details["receiverSeqNum"] += 1


#function that receives data 
def receive_date(server_socket, connection_details):
    intialSequenceNumber = connection_details["senderSeqNum"] - 1
    expectedSequenceNumber = intialSequenceNumber 
    print(f"expected sequence 1 = {expectedSequenceNumber}")
    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            print(f"expected sequence 2 = {expectedSequenceNumber}")
            #making sure they are the ones we are connected to
            if (addr == (HOST,SENDER_PORT)):
                #being able to read data
                print(f"expected sequence 3 = {expectedSequenceNumber}")
                data = ReliableTransportLayerProtocolHeader.from_bytes(data)

                if(data.fin):
                    print("Received FIN message. Moving on to ending connection")
                    return [True,connection_details]
                
                if (data.seq_num == expectedSequenceNumber):
                    print(f"expected sequence 4 = {expectedSequenceNumber}")
                    if (data.verify_checksum()):
                    #SET THE DETAILS RIGHT
                        connection_details["receiverACKNum"] = expectedSequenceNumber
                        print(f" Passing : {connection_details["receiverACKNum"]}")
                        log_received_packet(data.app_data)
                        print(f"Logged : {data.app_data}")
                        send_ack(server_socket, connection_details)
                        time.sleep(2)
                        expectedSequenceNumber += connection_details["sender_mss"]
                        connection_details["receiverACKNum"] = expectedSequenceNumber
                    else:
                        print("Packer corrupt. Dropped.")
                else:
                    print(f"Package {data.seq_num} out of order. Was Expecting: {expectedSequenceNumber}. Dropped.")
        

        except:
            print("Socket Timed Out : Nothing Received")
            return [False,connection_details]
            
        


def start_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((HOST, RECEIVER_PORT))
    server_sock.settimeout(TIMEOUT)

    connection_details = handshake(server_sock)

    #if the connection was made successfully
    if (connection_details["Alive"]):
        received = receive_date(server_sock, connection_details)
        if received[0]:
            accept_fin(server_sock=server_sock, connection_details=received[1])
        server_sock.close()

if __name__ == "__main__":
    start_server()
