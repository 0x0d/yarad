import memcache
import sys
from log import *

@logged_class
class Memcache:

	@logged
	def __init__(self, host, port, time):
		self.conn = None
		self.host = host
		self.port = port
		self.time = time
		self.logger = logger(self)
		self.Connect()

	@logged
	def Connect(self):
		self.conn = memcache.Client(['%s:%s' % (self.host, self.port)], debug=0)
		if not self.conn.set("junk", 1):
			self.logger.error("Could not connect to memcached server: %s:%s" % (self.host, self.port))

	@logged
	def Set(self, key, value):
		if not self.conn.set(key, value, self.time):
			self.logger.warn("Fail to store [%s] value in memcache" % key)
			self.Connect()

	@logged
	def Get(self, key):
		result = self.conn.get(key)
		if not result:
			self.logger.info("Fail to get [%s] value in memcache" % key)
		return result
