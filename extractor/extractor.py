#!/usr/bin/env python

'''
Feature Extractor for Bigtree project
    by maziazy@gmail.com

DO NOT use scapy. It's really handy but way too slow.

TODO:
  * Should judge whether a packet is SSL by signature,
    but not TCP port 443
  * We should use ndpi libary to identify the flow, but not the ndpiReader

'''

from dpkt import pcap, ssl
from subprocess import call
from os import devnull
import os
import warnings
import mpkt
import json
import sys
import csv

_PRECEDING_PACKETS_NUM = 5
_NDPI_TEMPNAME = 'ndpi_out.json'

# Flow features
class Feature(mpkt.FiveTuple):
    def __init__(self, src, dst, sport, dport, proto='TCP'):
        super(Feature, self).__init__(src, dst, sport, dport, proto)

        self.packets_size = []                      # Preceding packets byte count
        self.talk_size = {'A': 0, 'B':0, 'A+B': 0}  # APPR talk byte count
        self.talk_pkt = {'A': 0, 'B':0, 'A+B': 0}   # APPR talk packet count

        self.objs = {                               # Extraction objectives
            'APPR': False,
            'preceding': False
        }

    @classmethod
    def from5tuple(cls, tuple):
        return cls(tuple.src, tuple.dst, tuple.sport, tuple.dport, tuple.proto)

    ''' Check whether all extraction objectives are completed'''
    def complete(self):
        for key, objective in self.objs.iteritems():
            if not objective: return False
        return True

    ''' Convert features into 5 tuple '''
    def to5tuple(self):
        return mpkt.FiveTuple(self.src, self.dst, self.sport, self.dport, self.proto)

    ''' Convert features into list '''
    def toList(self):
        list = []
        for i in range(0, _PRECEDING_PACKETS_NUM):
            list.append(self.packets_size[i])
        list.append(self.talk_pkt['A'])
        list.append(self.talk_pkt['B'])
        list.append(self.talk_pkt['A+B'])
        list.append(self.talk_size['A'])
        list.append(self.talk_size['B'])
        list.append(self.talk_size['A+B'])
        list.append(self.dport)
        list.append(self.sport)

        return list

# Flow features with ground truth
class Essence(Feature):
    def __init__(self, src, dst, sport, dport, proto='TCP', app='Unknown'):
        super(Essence, self).__init__(src, dst, sport, dport, proto)

        self.app = app                              # Application of this flow

    @classmethod
    def from5tuple(cls, tuple):
        return cls(tuple.src, tuple.dst, tuple.sport, tuple.dport, tuple.proto)

    @classmethod
    def fromFeature(cls, feat):
        this = cls(feat.src, feat.dst, feat.sport, feat.dport, feat.proto)

        this.packets_size   = feat.packets_size
        this.talk_size      = feat.talk_size
        this.talk_pkt       = feat.talk_pkt


# Convert ndpi json output to a [flow: app] dictionary
def json2dict(appjson):
    dict = {}
    for flow in appjson['known.flows']:
        if flow['protocol'] != 'TCP': continue

        name = mpkt.FiveTuple(flow['host_a.name'], flow['host_b.name'],
            flow['host_a.port'], flow['host_n.port'], 'TCP').toString()

        if name in dict:
            warnings.warn(name.toString()+' has appeared twice.')
            # if name appeared twice, then we cannot distinguish those flows

        dict[name] = flow['detected.protocol.name']
    '''
    for flow in appjson['unknown.flows']:
        if flow['protocol'] != 'TCP': continue

        name = mpkt.FiveTuple(flow['host_a.name'], flow['host_b.name'],
            flow['host_a.port'], flow['host_n.port'], 'TCP').toString()

        if name in dict:
            warnings.warn(name.toString()+' has appeared twice.')
            # if name appeared twice, then we cannot distinguish those flows

        dict[name] = flow['detected.protocol.name']
    '''
    return dict

def main():
    # Check for arguments
    if len(sys.argv) == 2:
        file_in = sys.argv[1]
        file_out = 'essence.csv'
    elif len(sys.argv) == 3:
        file_in = sys.argv[1]
        file_out = sys.argv[2]
    else:
        print "Usage: ", sys.argv[0], "input.pcap", "[output.csv]"
        return

    # Open files for input and output
    try:
        FNULL = open(devnull, 'w')   # File of nowhere
        fi = open(file_in, 'r')
        fo = open(file_out, 'w')
        fo_writer = csv.writer(fo)
    except IOError as (errno, strerror):
        print "I/O error({0}): {1}".format(errno, strerror)
        return

    # ndpi reader
    '''
    if call([os.path.dirname(os.path.realpath(__file__))+'/ndpiReader',
            '-i', file_in, '-j', _NDPI_TEMPNAME, '-v 1', '-f tcp'],
            stdout=FNULL):
        raise RuntimeError('Can not execute ndpiReader correctly.')
    '''
    appdict = json2dict(json.load(open(_NDPI_TEMPNAME), encoding='latin-1'))

    # Prepare csv (header)
    csv_header = ['connection']
    for i in xrange(1, _PRECEDING_PACKETS_NUM+1):
        csv_header.append('packet '+str(i)+' size')
    csv_header.append('packet count A')
    csv_header.append('packet count B')
    csv_header.append('packet count A+B')
    csv_header.append('byte count A')
    csv_header.append('byte count B')
    csv_header.append('byte count A+B')
    csv_header.append('dport')
    csv_header.append('sport')
    csv_header.append('label')
    fo_writer.writerow(csv_header)

    # Prepare PCAP reader
    pcapin = pcap.Reader(fi)
    cons = {}                   # set of connections
    features = {}               # set of features

    for ts, buf in pcapin:
        try: pkt = mpkt.Packet(buf)
        except mpkt.PacketError: continue

        name = pkt.get5tuple().toString()
        name_rev = pkt.get5tuple().reversal().toString()
        # Append to connections list if this is a SYN-SENT, or reset it
        if name not in cons and pkt.isFlags('SYN'):
            cons[name] = mpkt.Connection.from5tuple(ts, pkt.get5tuple())
            features[name] = Feature.from5tuple(pkt.get5tuple())

        # reverse 5-tuple if this is a reversal packet
        if name not in cons and name_rev in cons:
            name, name_rev = name_rev, name

        # Process the packet
        if name in cons:
            con     = cons[name]
            feature = features[name]

            # Update connection information and strip SSL handshake
            alters = con.next(pkt)

            # Feature extraction
            # Talk A complete
            if alters['APPR'] == 3 or alters['APPR'] == 4:
                feature.talk_size['A'] = con.count['byte']
                feature.talk_pkt['A'] = con.count['data']
            # Talk B complete
            elif alters['APPR'] == 5:
                feature.talk_size['B'] = con.count['byte'] - feature.talk_size['A']
                feature.talk_pkt['B'] = con.count['data'] - feature.talk_pkt['A']
                feature.talk_size['A+B'] = con.count['byte']
                feature.talk_pkt['A+B'] = con.count['data']
                feature.objs['APPR'] = True

            # Cpature preceding packet byte count
            if pkt.len > 0 and len(feature.packets_size) < _PRECEDING_PACKETS_NUM and \
               (con.l5_proto != 'SSL' or con.state['SSL'] == mpkt.SSLState.EXCHANGE_MESS):
                feature.packets_size.append(pkt.len)

                # Captured all preceding packets
                if len(feature.packets_size) == _PRECEDING_PACKETS_NUM:
                    feature.objs['preceding'] = True

            # Write to csv file
            if feature.complete():
                #print con.toString(), 'Capture time:', ts - con.time['starting']

                essence = feature.toList()                     # Features
                #essence.insert(0, ts - con.time['starting'])   # Capture time
                essence.insert(0, con.toString())              # Connection name

                # Ground truth (appication name)
                if name in appdict:
                    essence.append(appdict[name])
                elif name_rev in appdict:
                    essence.append(appdict[name_rev])
                else:
                    essence.append('Unknown')
                    #warnings.warn(name.toString()+' has not apeared on ndpi result.')

                fo_writer.writerow(essence)
                del cons[name]
                del features[name]

    '''
    # Connections not in csv file
    for name in cons:
        name_rev = cons[name].get5tuple().reversal().toString()
        if name in appdict:
            print name, features[name].objs, appdict[name]
        elif name_rev in appdict:
            print name, features[name].objs, appdict[name_rev]
    '''

    fi.close()
    fo.close()

if __name__ == "__main__":
    main()
