import ldap
from ipaddr import *
import urllib
import urllib2
import random
import time
import memcached
import database
import hashlib
from log import *

WHITELIST = (
	'213.180.192.0/19',
	'87.250.224.0/19',
	'77.88.0.0/18',
	'93.158.128.0/18',
	'95.108.128.0/17',
	'178.154.128.0/17',
	'199.36.240.0/22',
	'77.75.152.0/21'
)

APNLIST = (
	'178.154.198.0/23',
	'178.154.196.0/23'
)

ldap_servers = [
	('pretty.yandex.ru', 0.5), 
	('lucky.yandex.ru', 0.25), 
	('kind.yandex.ru', 0.25)
]

otp_host = "otp-dev.yandex.ru"

def ip_in_list(request_ip, list):
	user_ip = IPv4Address(request_ip)

	for whitelist_ip in list:
		w_ip = IPv4Network(whitelist_ip)

		if (user_ip == w_ip.network) or ((user_ip >= w_ip.network) and (user_ip < w_ip.broadcast)):
			return True

	return False

def w_choice(lst):
	n = random.uniform(0, 1)
	for item, weight in lst:
		if n < weight:
			break
		n = n - weight
	return item

def ldap_auth(username, password):

	host = w_choice(ldap_servers)
	username = "%s@ld.yandex.ru" % (username)
	try:
		l = ldap.open(host)
		l.set_option(ldap.OPT_NETWORK_TIMEOUT, 1)
		l.protocol_version = ldap.VERSION3
		l.simple_bind_s(username, password)
		l.unbind()
		return True
	except ldap.LDAPError, e:
		print e
		return False

def checkMOTP(pin, otp, initsecret):
	maxperiod = 3*60
	etime = int(time.time())
	i = etime - maxperiod
	while i <= etime + maxperiod:
		n = hashlib.md5()
		n.update(str(i)[0:-1] + str(initsecret) + str(pin))
		md5 = n.hexdigest()[0:6]
		if otp == md5:
			return True
		i += 1
	return False

def otp_auth(username, password, db):
	
	username = db.Escape(username)

	db.Query("SELECT pin, initsecret FROM motp_users WHERE username = '%s' LIMIT 1" % (username))
	if db.Count() > 0:
		res = db.Fetchone()
		pin = res[0]
		initsecret = res[1]
		if checkMOTP(pin, password, initsecret):
			db.Close()
			return True		
	else:
		db.Close()
		return False

	db.Close()
	return False

def long_auth(username, password, db):

	username = db.Escape(username)
	password = db.Escape(password)
	db.Query("SELECT id FROM long_users WHERE username = '%s' AND password = '%s'" % (username, password))
	if db.Count() > 0:
		db.Close()
		return True
	db.Close()
	return False

# Check for control characters
def check_ctrl_char(key):
        for char in key:
            if ord(char) < 32 or ord(char) == 127:
                return False
	return True


@logged_class
class Logic:

	@logged
	def __init__(self, config):
		self.config = config
		self.logger = logger(self)
		self.memcache_enable = self.config.getboolean("Memcache", "enabled")
		self.database_enable = self.config.getboolean("Database", "enabled")
		if self.memcache_enable:
			self.mc = memcached.Memcache(self.config.get("Memcache", "host"), self.config.get("Memcache", "port"), self.config.getint("Memcache", "cache_time"))
		if self.database_enable:
			self.db = database.Database(self.config.get("Database", "host"), self.config.get("Database", "user"), self.config.get("Database", "password"), self.config.get("Database", "database"))

	@logged
	def AuthLogic(self, pkt):

		def getParameter(name, pkt):
			if name in pkt:
				return pkt[name][0]
			else:
				return None

		attrs = ""
		for attr in pkt.keys():
			attrs += " {%s: %s}" % (attr, pkt[attr])
		self.logger.info("Got attributes: %s" % (attrs))
		
		result = False

		username = getParameter('User-Name', pkt)
		password = getParameter('User-Password', pkt)
		if not username or not password:
			self.logger.error("Error! Packet does not have User-Name or User-Password attribute")
			return False

		password = pkt.PwDecrypt(password)

		if not check_ctrl_char(username) or not check_ctrl_char(password):
			self.logger.error("Error! Control characters is not allowed in  User-Name or User-Password attribute")
			return False

		self.logger.info("Trying to make auth as: %s/%s" % (username, password))

		user_ip = getParameter('Yandex-User-IP', pkt)
		if not user_ip:
			self.logger.error("Error! Packet does not have Yandex-User-IP attribute")
			return False

                allowed_ip = ip_in_list(user_ip, WHITELIST)
		if allowed_ip:
			self.logger.info("%s it is our internal IP" % (user_ip))
		else:
			self.logger.info("%s it is external IP" % (user_ip))

                retval = {'Yandex-External-IP': int(not allowed_ip)}

		if self.memcache_enable:
			mckey = "%s%s" % (username, user_ip)
			self.logger.info("Querying memcache")
			pwd = self.mc.Get(mckey)
			if pwd and pwd == password:
				self.logger.info("Memcache auth accepted")
				return retval
			else:
				self.logger.info("Memcache auth failed, continuing")

		service_name = getParameter('Yandex-Service', pkt)
		if service_name:
			if service_name == 'Yandex.Mail' or service_name == 'web':
				if not allowed_ip:
					self.logger.info("Choosing OTP auth")
					result = otp_auth(username, password, self.db)
			elif service_name == 'Yandex.CalDAV' or service_name == 'caldav' or service_name == 'xmpp':
				self.logger.info("Choosing Long auth")
				if self.database_enable:
					result = long_auth(username, password, self.db)
				else:
					self.logger.error("Database support is disabled, enable it to use long auth")
			else:
				self.logger.warn("Warning! Packet has unknown service name: %s" % (service_name))
		else:
			self.logger.warn("Warning! Packet does not have Yandex-Service parameter")

		if not result and allowed_ip:
			self.logger.info("Choosing LDAP auth")
			if ip_in_list(user_ip, APNLIST):
				self.logger.info("User IP in APN list, denying it")
				return False
			result = ldap_auth(username, password)

                # Temporary hack, try to auth in OTP when LDAP is failed
                #if not result:
                #        self.logger.warn("Temporary hack, LDAP is failed try to auth in OTP")
                #        result = otp_auth(username, password)

		if result:
			if self.memcache_enable:
				self.logger.info("Storing auth in memcache")
				self.mc.Set(mckey, password)
			return retval

		return False

	@logged
	def AcctLogic(self, pkt):
		self.logger.error("Nothing here!")
