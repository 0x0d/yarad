import MySQLdb
import sys
from log import *

@logged_class
class Database:

	@logged
	def __init__(self, host, user, passwd, db):
		self.conn = None
		self.host = host
		self.user = user
		self.passwd = passwd
		self.db = db
		self.logger = logger(self)
		self.cursor = None
		self.Connect()

	@logged
	def Connect(self):
		try:
			self.conn = MySQLdb.connect(host = self.host, user = self.user, passwd = self.passwd, db = self.db)
		except MySQLdb.Error, e:
			self.logger.error("Could not connect to database: %s" % (e[1]))

	@logged
	def Query(self, statement):
		if self.conn:
			try:
				self.cursor = self.conn.cursor()
				self.cursor.execute(statement)
			except (AttributeError, MySQLdb.OperationalError), e:
				self.logger.error("General SQL error: %s : %s" % (statement, e[1]))
				self.logger.warn("Reconnecting...")
				self.cursor.close()
                                self.Connect()
				if self.conn:
					self.cursor = self.conn.cursor()
					self.cursor.execute(statement)
				else:
					self.logger.error("Reconnect failed!")
			except MySQLdb.ProgrammingError, e:
				self.logger.error("Fail to process SQL statement: %s : %s" % (statement, e[1]))
		else:
			self.logger.error("No SQL server connection, skipping")

	@logged
	def Count(self):
		if self.conn:
			return self.cursor.rowcount
		else:
			return False

	@logged
	def Fetchone(self):
		if self.conn:
			result = self.cursor.fetchone()
			return result
		else:
			return False

	@logged
	def Close(self):
		if self.conn and self.cursor:
			self.cursor.close()

	@logged
	def Escape(self, string):
		return MySQLdb.escape_string(string)

