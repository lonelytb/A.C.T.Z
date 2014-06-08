from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
import pox.lib.packet as pkt
import os
import csv
import MySQLdb

''' Add your imports here ... '''

teamSrc = 0
teamDst = 0
string1 = 0
name = 0
log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ['HOME']
db = MySQLdb.connect("localhost","root","44123429","mininet" )
cursor = db.cursor()
sql = "SELECT * FROM HOSTS"
try:
   cursor.execute(sql)
   results = cursor.fetchall()
   for row in results:
      ID = row[0]
      MAC = row[1]
      TEAM = row[2]
      print "ID=%s, MAC=%s, Team=%s" % \
             (ID, MAC, TEAM)
except:
   print "Error: unable to fecth data"
db.close()

''' Add your global variables here ... '''


class Firewall (EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp(self, event):
        ''' Add your logic here ... '''
    def _handle_PacketIn (self, event):
        #teamSrc = 0
        #teamDst = 0
        packet = event.parsed
	if packet.type == 2048:
            pkt = event.parsed.find('ipv4')
            #log.info(packet.type)
            global string1
            string1 = pkt.dstip.toStr()
        p = event.parsed.find('dns')
        if p is not None and p.parsed:
            for q in p.questions:
                if q.qclass != 1: continue
                log.info(q.name)
                db = MySQLdb.connect("localhost","root","44123429","mininet" )
                cursor = db.cursor()
                sql = "SELECT * FROM WEBSITE"
                cursor.execute(sql)
                results = cursor.fetchall()
                db.close()
		for row in results:
                    global name
                    name = row[1]
                    log.info("============")
                    
                    if name == q.name or name+".localdomain" ==  q.name+".localdomain":
                        log.info("test")
                        event.halt = True
                        log.info("Blocked DNSlookup to %s", q.name)
        
        db = MySQLdb.connect("localhost","root","44123429","mininet" )
        cursor = db.cursor()
        sql = "SELECT * FROM HOSTS WHERE MAC = '%s' " % (packet.src)
        cursor.execute(sql)
        results = cursor.fetchall()
        for row in results:
            global teamSrc 
            teamSrc= row[2]
        db.close()

        db = MySQLdb.connect("localhost","root","44123429","mininet" )
        cursor = db.cursor()
        sql = "SELECT * FROM HOSTS WHERE mac = '%s' " % (packet.dst)
        cursor.execute(sql)
        results = cursor.fetchall()
        for row in results:
            global teamDst 
            teamDst= row[2]
        db.close()

        #log.info("src %s", teamSrc)
        #log.info("dst %s", teamDst)
	#string1 = pkt.dstip.toStr();
	string2 = "10."
	#log.info("str %s", string1)
	#log.info(cmp(string1[0:3],string2[0:3]))
        if cmp(string1[0:3],string2[0:3])==0 and teamSrc != teamDst:
            log.info("Blocked: Not same team.")           
            event.halt = True


def launch():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
