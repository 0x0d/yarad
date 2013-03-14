#!/usr/bin/python

import optparse
import ConfigParser

from pyrad import dictionary
from network import Worker, Server, Checker
from log import *

@logged_class
class Yarad:
	@logged
	def __init__(self):
		self.options = None
		self.config =  ConfigParser.RawConfigParser()
		self.server = None
		self.checker = None
		self.workers = {}
		self.LoadConfig()

	@logged
	def Run(self):
		listen_on = self.config.get("General", "listen_on").split(" ")
		self.server = Server(self.config, listen_on, self.config.getint("General", "auth_port"), self.config.getint("General", "acct_port"), self.config.get("General", "secret_key"), dictionary.Dictionary(self.config.get("General", "dictionary")))
		for i in range(0, self.config.getint("General", "workers_count")):
			self.workers[i] = Worker(self.server, i, self.config)
			self.workers[i].Run()

		self.checker = Checker(self.config.get("Checker", "listen_on"), self.config.getint("Checker", "port"))
		self.checker.Run()
	

	@logged
	def LoadConfig(self):
		parser = optparse.OptionParser()
		parser.add_option('-c', '--config', dest='config_file', default='conf/yarad.cfg', help='Configuration file location: ./conf/yarad.cfg')
		self.options = parser.parse_args()[0]
		self.config.read(self.options.config_file)

if __name__ == "__main__":
	ya = Yarad()
	ya.Run()

