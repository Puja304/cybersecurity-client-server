import zlib
import struct

class ReliableTransportLayerProtocolHeader:
    def __init__(self, source_port_num, dest_port_num, seq_num, ack_num, sending_window, mss, syn=False, ack=False, fin=False, app_data=""):
        self.syn = syn
        self.ack = ack
        self.fin = fin
        self.source_port_num = source_port_num
        self.dest_port_num = dest_port_num
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.sending_window = sending_window
        self.app_data = app_data
        self.mss = mss
        self.checksum = self.calculateChecksum()

    def calculateChecksum(self):
        # Convert all fields to 16-bit values (truncate or split as necessary)
        fields = [
            self.source_port_num & 0xFFFF,
            self.dest_port_num & 0xFFFF,
            (self.seq_num >> 16) & 0xFFFF,  # Upper 16 bits of seq_num
            self.seq_num & 0xFFFF,          # Lower 16 bits of seq_num
            (self.ack_num >> 16) & 0xFFFF,  # Upper 16 bits of ack_num
            self.ack_num & 0xFFFF,          # Lower 16 bits of ack_num
            self.sending_window & 0xFFFF,
            self.mss & 0xFFFF,
            (int(self.syn) << 2 | int(self.ack) << 1 | int(self.fin)) & 0xFFFF,  # Pack flags into a single field
        ]

        def wraparound_add(val1, val2):
            return (val1 + val2) & 0xFFFF

        # Include application data as 16-bit chunks
        app_data_bytes = self.app_data.encode()  # Convert string to bytes
        for i in range(0, len(app_data_bytes), 2):
            if i + 1 < len(app_data_bytes):
                # Combine two bytes into a 16-bit value
                fields.append((app_data_bytes[i] << 8) + app_data_bytes[i + 1])
            else:
                # Add padding if app_data length is odd
                fields.append(app_data_bytes[i] << 8)

        # Calculate the sum of all fields with wraparound
        checksum = 0
        for field in fields:
            checksum = wraparound_add(checksum, field)

        # Take one's complement of the result
        checksum = ~checksum & 0xFFFF

        return checksum

    def to_bytes(self):
        # Combine all fields into a single byte stream
        flags = self.syn << 2 | self.ack << 1 | self.fin  # a single byte to represent all flags
        header = f"{self.source_port_num},{self.dest_port_num},{self.seq_num},{self.ack_num},{self.sending_window},{self.mss},{flags},{self.checksum}|{self.app_data}"
        return header.encode('utf-8')

    @staticmethod
    def from_bytes(data):
        # Decode the byte stream back to the header and payload
        decoded_header = data.decode('utf-8')
        header, payload = decoded_header.split('|')

        # Extract all header fields, separated by commas
        source_port_num, dest_port_num, seq_num, ack_num, sending_window, mss, flags, checksum = map(int, header.split(','))

        # Extract the flag bits
        syn, ack, fin = (flags & 4) >> 2, (flags & 2) >> 1, (flags & 1)

        # Create a new header and return it
        return ReliableTransportLayerProtocolHeader(
            source_port_num=source_port_num,
            dest_port_num=dest_port_num,
            seq_num=seq_num,
            ack_num=ack_num,
            sending_window=sending_window,
            mss=mss,
            syn=syn,
            ack=ack,
            fin=fin,
            app_data=payload,
        )
    
    def verify_checksum(self):
        calculated_checksum = self.calculateChecksum()
        return calculated_checksum == self.checksum
