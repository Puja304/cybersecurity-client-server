import socket
import random
from header import ReliableTransportLayerProtocolHeader
import logging
import time
import copy
import warnings
import matplotlib.pyplot as plt
warnings.filterwarnings("ignore")


#constants
HOST = '127.0.0.1'   #IP for both sender and receiver
SENDER_PORT = 8001
RECEIVER_PORT = 8000  
WINDOW_SIZE = 9
MSS = 15
SOCKET_TIMEOUT = 20
CURRENT_TIMEOUT = 60
BETA = 0.8
ALPHA = 0.125
MAX_RETRIES = 5
TIMEOUT_MULTIPLIER = 2
LOSS_PROBABILITY = 0.0 # % of packet loss / corruption probability for simulation
CWND_INIT = MSS  # Initial congestion window size
CWND_MAX = WINDOW_SIZE * MSS  # Maximum congestion window size
SLOW_START = "SLOW_START"
CONGESTION_AVOIDANCE = "CONGESTION_AVOIDANCE"
cwnd_values = []  # List to store CWND_INIT values for plotting
cwnd_timestamps = []  # List to store timestamps corresponding to CWND values
# Initialize state
congestion_state = SLOW_START
# Slow start threshold (ssthresh)
ssthresh = CWND_MAX // 2  # Can be adjusted



logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("Sender")



# Read data from a file
def read_data_from_file(file_path="data.txt"):
    """
    Reads and returns the content of a file.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return ""
    except UnicodeDecodeError:
        print(f"Error decoding file {file_path}. Please check the file encoding.")
        return ""


# Replace DATA with content from data.txt
DATA = read_data_from_file("data.txt")

# 3 - way handhsake 
def handshake(sender_socket):

    #intialises an empty details dictionary 
    connection_details = {
        "Alive": False,
        "IP": 0,
        "Port": 0,
        "receiverSeqNum": 0,
        "receiverACKNum": 0,
        "receiver_window": 0,
        "receiver_mss": 0,
        "senderSeqNum": 0,
        "senderACKNum": 0
    }

    logger.info("Sender: Sending SYN to initiate handshake...")
    app_data = "Hey! Do you want to connect?"
    synbit = 1

    #choosing a sequence number
    seq = random.randint(0,2000)

    print(f"SEQUENCE NUMBER : {seq} at start")
    ack_num = 0

    #send SYN message
    message = ReliableTransportLayerProtocolHeader(SENDER_PORT, RECEIVER_PORT, seq, ack_num, WINDOW_SIZE, MSS, syn=synbit, app_data=app_data)
    sender_socket.sendto(message.to_bytes(), (HOST, RECEIVER_PORT))

    try:
        data, addr = sender_socket.recvfrom(1024)
        data = ReliableTransportLayerProtocolHeader.from_bytes(data)
        if addr == (HOST, RECEIVER_PORT):
            if data.syn == 1 and data.ack == 1 and data.ack_num == seq + 1:
                logger.info("Sender: Received SYN-ACK, sending ACK...")

                connection_details["Alive"] = True
                connection_details["receiver_window"] = data.sending_window
                connection_details["receiver_mss"] = data.mss
                connection_details["Port"] = addr[1]
                connection_details["receiverSeqNum"] = data.seq_num
                connection_details["receiverACKNum"] = data.ack_num
                connection_details["senderSeqNum"] = seq + 1
                print("")
                connection_details["senderACKNum"] = connection_details["receiverSeqNum"] + 1
                print(f"SEQUENCE NUMBER : {connection_details["senderSeqNum"]} after handshake step 3")
                ack_bit = 1
                app_data = "Great! Let's connect"
                message = ReliableTransportLayerProtocolHeader(SENDER_PORT, RECEIVER_PORT, connection_details["senderSeqNum"], connection_details["senderACKNum"], WINDOW_SIZE, MSS, ack=ack_bit, app_data=app_data)
                sender_socket.sendto(message.to_bytes(), (HOST, RECEIVER_PORT))
                logger.info("Sender: Sent ACK in response to SYNACK. 3-way handshake complete")
                connection_details["senderSeqNum"] += 1 #since the next data will also be from sender
    except:
        #if it fails to receive anything back
        return connection_details 
    return connection_details


#converts data into MSS-sized chunks so that each chuck can be treated as a single packet
# returns an array such that each index is a new packet's data
def prepare_packets():
    chunks = []
    total_data_length = len(DATA)

    for i in range(0, total_data_length, MSS):
        chunk = DATA[i:i + MSS]
        chunks.append(chunk)

    return chunks


def send_packet(sender_socket, connection_details, data, retransmission=False):
    added = ""
    if retransmission:
        added = "(Retransmission)"
    if random.random() < LOSS_PROBABILITY:
        #simulating loss or corruption (half the time not sent, the other time corrupted )
        if random.random() < 0.5:
            logger.debug(f"Client: {added} Simulating loss of packet {connection_details['senderSeqNum']}.")
        else:
            logger.debug(f"Client: {added} Simulating corruption of packet {connection_details['senderSeqNum']}.")
            packet_header = ReliableTransportLayerProtocolHeader(SENDER_PORT, RECEIVER_PORT, connection_details["senderSeqNum"], connection_details["senderACKNum"], WINDOW_SIZE, MSS, app_data=data)
            packet_header.checksum +=  1
            sender_socket.sendto(packet_header.to_bytes(), (HOST, RECEIVER_PORT))
        return
    packet_header = ReliableTransportLayerProtocolHeader(SENDER_PORT, RECEIVER_PORT, connection_details["senderSeqNum"], connection_details["senderACKNum"], WINDOW_SIZE, MSS, app_data=data)
    packet_bytes = packet_header.to_bytes()
    sender_socket.sendto(packet_bytes, (HOST, RECEIVER_PORT))
    logger.debug(f"Client: {added} Sent packet {connection_details['senderSeqNum']}.")



#received acks, checks for corruption, and then updates it in the set holding all acked numbers
def receive_ack(sender_socket, specific_cd, connection_details):
    try:
        time.sleep(5)
        ack, addr = sender_socket.recvfrom(1024)
        header = ReliableTransportLayerProtocolHeader.from_bytes(ack)
        desiredAck = specific_cd["senderSeqNum"]
        print(f"ACKed = {header.ack_num}")
        print(f"Want ACK for = {desiredAck}")
        #ack not corrupted
        if(header.verify_checksum()):
            # if the right person sent it
            if(addr == (HOST,RECEIVER_PORT)):
                #if the ack bit is set
                if ((header.ack_num == desiredAck)):
                    #We received an acknowledgment for this packet
                    print(f"Received ACK for {desiredAck} BEFORE")
                    connection_details["receiverACKNum"] = header.ack_num 
                    connection_details["senderACKNum"] = connection_details["receiverSeqNum"] + connection_details["receiver_mss"]
                    print(f"Received ACK for {desiredAck} AFTER")
                    return True
                else:
                    print("Not an ACK message. Ignored.")
                    return False
            else:
                print("Unrecognized sender. Discarded")
                return False
        else:
            print("Corrupted ACK. Discarded")
            return False
    except Exception as e:
        print(e) #this line is printing timed out message
        print("Waiting to receive...")
        return False


#function that retransmits the entire window when the base times out
def retransmit_window(sender_socket, base, last, sent_packets):
    for i in range(base,last+MSS,MSS):
        if(i in sent_packets):
            print(f"Intending to Retransmit : {i}")
            send_packet(sender_socket, sent_packets[i][1], sent_packets[i][2], retransmission=True)
            sent_packets[i][0] = time.time() #resetting timer if it needs to be retransmitted again


#sends data to the receiver while sliding the window appropriately. Uses Go-Back-N for pipelining
def send_data(sender_socket, connection_details, data):
    global CWND_INIT, CWND_MAX, congestion_state,ssthresh, SLOW_START, CONGESTION_AVOIDANCE
    cwnd_values.append(CWND_INIT) #Storing the first value at time 0
    initial_sequence =  connection_details["senderSeqNum"] 
    base = initial_sequence  # the sequence number of the first packet in the current sliding window
    last = base + CWND_INIT # the sequence number of the last packet in the current window4
    total_packets = len(data) # total number of packets to send
    ending_sequence = initial_sequence + (MSS * (total_packets - 1))
    print(f"Ending sequence: {ending_sequence}")
    sent_packets = {}


    while base < ending_sequence:
        last = min(base + CWND_INIT, ending_sequence) 
        print(f"Base = {base}, Last = {last}")
        for seq_num in range(base,last + MSS,MSS):
            #packet_size = len(data[seq_num]) #calculating the size of each packet for dynamic window sliding
            if seq_num not in sent_packets:
                print("Goes here")
                connection_details["senderSeqNum"] = seq_num

                #send the packet with that sequence number, ack number, etc 
                send_packet(sender_socket=sender_socket, connection_details=connection_details, data=data[int((seq_num - initial_sequence)/MSS) ], retransmission=False)
            
                #storing this information for future use; along with the time it was sent. the last value is a bool storing whether or not it is acked
                sent_packets[seq_num] = [time.time(), copy.deepcopy(connection_details), data[int((seq_num - initial_sequence)/MSS)], False]

        retransmit  = True
        initial_base = base
        initial_last = last
        print(f"Base = {base}, last = {last}")
        while (((time.time() - sent_packets[initial_base][0]) < CURRENT_TIMEOUT) & (base < initial_last)):
            print(f"Passed (Base) : {sent_packets[base][1]["senderSeqNum"]}")
            print(f"Current base = {base}, initial_last = {initial_last}")
            success = receive_ack(sender_socket,sent_packets[base][1], connection_details)
            if success:
                # Adjust congestion window based on the current state
                if congestion_state == SLOW_START:
                    if CWND_INIT < ssthresh:
                        # Exponential growth in slow start
                        #CWND_INIT += MSS
                        print(f"Before Slow Start CWND chance: {CWND_INIT}")
                        CWND_INIT = min(CWND_INIT * 2, CWND_MAX) #Exponential growth in slow start
                        print(f"Slow Start: CWND_INIT = {CWND_INIT}")
                    else:
                        # Transition to congestion avoidance
                        congestion_state = CONGESTION_AVOIDANCE
                        print("Transition to Congestion Avoidance")
                if congestion_state == CONGESTION_AVOIDANCE:
                    # Linear growth in congestion avoidance
                    #CWND_INIT += MSS * (MSS // CWND_INIT)
                    print(f"Before Congestion Avoidance CWND chance: {CWND_INIT}")
                    CWND_INIT += MSS
                    print(f"Congestion Avoidance: CWND_INIT = {CWND_INIT}")

                cwnd_values.append(CWND_INIT)
                cwnd_timestamps.append(time.time())
                retransmit = False
                base += MSS
                sent_packets[base][0] = time.time()  # Reset timer
                if (base + CWND_INIT) <= ending_sequence:
                    last = base + CWND_INIT
                else:
                    last = ending_sequence
            else:
                # Handle retransmission (timeout or loss)
                print("Packet loss detected, entering Slow Start")
                ssthresh = max(CWND_INIT // 2, MSS)  # Update ssthresh
                CWND_INIT = MSS  # Reset to one MSS
                congestion_state = SLOW_START
                cwnd_values.append(CWND_INIT)
                cwnd_timestamps.append(time.time())
                retransmit_window(sender_socket, base, last, sent_packets)


        #if there are packets that haven't been acknowleged, retrasnmit the whole window

        if retransmit:
            #multiplicative decrease due to loss
            CWND_INIT = max(MSS, CWND_INIT // 2)
            print(f"Applying mutiplicative decrease : CWND_INIT = {CWND_INIT}")
            cwnd_values.append(CWND_INIT)  # Track the current value of CWND_INIT
            cwnd_timestamps.append(time.time())
            retransmit_window(sender_socket, base, last, sent_packets)
    
   #values at the end (to show stagnation when it happens)
    cwnd_values.append(CWND_INIT)
    cwnd_timestamps.append(time.time())

    # Normalize timestamps to start at 0
    elapsed_time = [-10] + [t - cwnd_timestamps[0] for t in cwnd_timestamps]

    plt.plot(elapsed_time, cwnd_values, marker='o')
    plt.title("CWND Size vs Time")
    plt.xlabel("Time (seconds)")
    plt.ylabel("CWND Size (bytes)")
    plt.grid(True)
    plt.show()

    return


#end the connection
def terminate_connection(sender_socket, connection_details):
    logger.info("Sender: Sending FIN to terminate the connection...")

    seq_num = connection_details["senderSeqNum"]
    ack_num = connection_details["receiverSeqNum"] + 1

    fin_bit = 1
    app_data = "Goodbye! Closing connection."
    fin_packet = ReliableTransportLayerProtocolHeader(
        SENDER_PORT, RECEIVER_PORT, seq_num+1, ack_num, WINDOW_SIZE, MSS, fin=fin_bit, app_data=app_data
    )
    sender_socket.sendto(fin_packet.to_bytes(), (HOST, RECEIVER_PORT))

    attempts = 0
    while attempts < MAX_RETRIES:
        try:
            logger.info("Sender: Waiting for FIN-ACK from receiver...")
            data, addr = sender_socket.recvfrom(1024)
            data = ReliableTransportLayerProtocolHeader.from_bytes(data)

            if addr == (HOST, RECEIVER_PORT) and data.fin == 1 and data.ack == 1:
                logger.info("Sender: Received FIN-ACK, sending final ACK...")

                ack_bit = 1
                app_data = "Final ACK. Connection closed."
                final_ack_packet = ReliableTransportLayerProtocolHeader(
                    SENDER_PORT, RECEIVER_PORT, seq_num + 1, ack_num + 1, WINDOW_SIZE, MSS, ack=ack_bit, app_data=app_data
                )
                sender_socket.sendto(final_ack_packet.to_bytes(), (HOST, RECEIVER_PORT))
                logger.info("Sender: Sent final ACK. Connection closed.")
                break
        except socket.timeout:
            logger.info("Sender: Timeout, retrying FIN-ACK...")
            attempts += 1
            time.sleep(1)
    return

#function that intiates connection, sends data, ends the connection and closes the socket
def start_sender():
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    sender_socket.bind((HOST, SENDER_PORT))
    sender_socket.settimeout(SOCKET_TIMEOUT)

    #initiates 3-way handshake
    connection_details = handshake(sender_socket)

    #if the connection was made successfully 
    if (connection_details["Alive"]):
        data = prepare_packets()
        send_data(sender_socket,connection_details,data)
        terminate_connection(sender_socket, connection_details)
        sender_socket.close()
#Starts the program
if __name__ == "__main__":
    start_sender()

