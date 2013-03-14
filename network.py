import os
import time
import socket
import select
from logic import Logic
from multiprocessing import Process, Queue
from pyrad import packet
from log import *

@logged_class
class Worker:
	"""Multiprocessing worker."""

	@logged
	def __init__(self, server, id, config):
		self.proc = Process(target=self.Loop)
		self.server = server
		self.id = id
		self.mc = None
		self.db = None
		self.config = config

	@logged
	def Run(self):
		self.proc.start()

	@logged
	def Loop(self):
		self.server.Reinit(self.id)
		self.server.Run()

class Host:
	"""Generic RADIUS host."""

	def __init__(self, dict):
		self.dict = dict

	def CreatePacket(self, **args):
		return packet.Packet(dict=self.dict, **args)
	
	def CreateAuthPacket(self, **args):
		return packet.AuthPacket(dict=self.dict, **args)
	
	def CreateAcctPacket(self, **args):
		return packet.AcctPacket(dict=self.dict, **args)
	
	def SendPacket(self, fd, pkt):
		fd.sendto(pkt.Packet(), pkt.source)

	def SendReplyPacket(self, fd, pkt):
		fd.sendto(pkt.ReplyPacket(), pkt.source)

@logged_class
class Server(Host):
	"""Generic RADIUS server host."""
	MaxPacketSize   = 8192

	@logged
	def __init__(self, config, addresses, authport, acctport, secret, dict):
		Host.__init__(self, dict)

		self.id = None
		self.dict = dict
		self.authport = authport
		self.acctport = acctport
		self.secret = secret
		
		self.logger = logger(self)

		self.config = config

		self.authfds = []
		self.acctfds = []

		for addr in addresses:
			self.BindToAddress(addr)

	@logged
	def BindToAddress(self, addr):
		self.logger.info("Listening for auth requests on: %s:%d" % (addr, self.authport))
		authfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		authfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		authfd.bind((addr, self.authport))

		self.logger.info("Listening for acct requests on: %s:%d" % (addr, self.acctport))
		acctfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		acctfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		acctfd.bind((addr, self.acctport))

		self.authfds.append(authfd)
		self.acctfds.append(acctfd)

	@logged
	def HandleAuthPacket(self, pkt):
		self.logger.info("Handle auth packet [%d thread] from %s" % (self.id, pkt.source[0]))
		pkt.secret = self.secret

		if pkt.code != packet.AccessRequest:
			self.logger.error("Received non-authentication packet on authentication port")
			return False

		result = self.logic.AuthLogic(pkt)

		rpkt = self.CreateReplyPacket(pkt)
		if result:
			self.logger.info("AUTH SUCCESS")
			for key in result:
				rpkt[key] = result[key]
			rpkt.code = packet.AccessAccept
		else:
			self.logger.info("AUTH FAILED")
			rpkt.code = packet.AccessReject

		self.logger.info("Send reply auth packet [%d thread] to %s: %d\n" % (self.id, pkt.source[0], rpkt.code))
		self.SendReplyPacket(pkt.fd, rpkt)

	@logged
	def HandleAcctPacket(self, pkt):
		self.logger.info("Handle acct packet [%d thread]: %s" % (self.id, pkt.source[0]))
		pkt.secret=self.secret

		if not pkt.code in [ packet.AccountingRequest, packet.AccountingResponse ]:
			self.logger.error("Received non-accounting packet on accounting port")
			return False

		result = self.logic.AcctLogic(pkt)

		rpkt = self.CreateReplyPacket(pkt)
		if result: 
			self.logger.info("AUTH SUCCESS")
			rpkt.code = packet.AccessAccept
		else:
			self.logger.info("AUTH FAILED")
			rpkt.code = packet.AccessReject

		self.logger.info("Send reply acct packet [%d thread] to %s: %d\n" % (self.id, pkt.source[0], rpkt.code))
		self.SendReplyPacket(pkt.fd, rpkt)

	@logged
	def GrabPacket(self, pktgen, fd):
		(data,source) = fd.recvfrom(self.MaxPacketSize)
		pkt = pktgen(data)
		pkt.source = source
		pkt.fd = fd

		return pkt

	@logged
	def PrepareSockets(self):
		for fd in self.authfds + self.acctfds:
			self._fdmap[fd.fileno()] = fd
			self._poll.register(fd.fileno(), select.POLLIN|select.POLLPRI|select.POLLERR)

		self._realauthfds = map(lambda x: x.fileno(), self.authfds)
		self._realacctfds = map(lambda x: x.fileno(), self.acctfds)

	@logged
	def CreateReplyPacket(self, pkt, **attributes):
		reply = pkt.CreateReply(**attributes)
		reply.source = pkt.source

		return reply

	@logged
	def ProcessInput(self, fd):
		if fd.fileno() in self._realauthfds:
			pkt = self.GrabPacket(lambda data, s=self: s.CreateAuthPacket(packet=data), fd)
			self.HandleAuthPacket(pkt)
		else:
			pkt = self.GrabPacket(lambda data, s=self: s.CreateAcctPacket(packet=data), fd)
			self.HandleAcctPacket(pkt)

	@logged
	def Reinit(self, id):
		self.id = id
		self.logic = Logic(self.config)

	@logged
	def Run(self):
		self._poll = select.poll()
		self._fdmap = {}
		self.PrepareSockets()

		while 1:
			for (fd, event) in self._poll.poll():
				if event == select.POLLIN:
					try:
						fdo = self._fdmap[fd]
						self.ProcessInput(fdo)
					except packet.PacketError, err:
						self.logger.error("Received a broken packet: " + str(err))
				else:
					self.logger.error("Unexpected event in server main loop")

@logged_class
class Checker:
	@logged
	def __init__(self, addr, port):
		self.fd = None
		self.port = port
		self.logger = logger(self)
		self.BindToAddress(addr)
	@logged
	def BindToAddress(self, addr):
                self.logger.info("Listening for checkin requests on: %s:%d" % (addr, self.port))
                self.fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.fd.bind((addr, self.port))

	@logged
	def Run(self):

		self.fd.listen(5)
		while 1:
			conn, addr = self.fd.accept()
			self.logger.info("Got checkin request from: %s:%d" % addr)
			conn.close()
