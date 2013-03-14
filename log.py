import logging

class logger(object):

	def __init__(self, instance):
		self.module = str(instance)
		self.init()

	def init(self):
		self.logger = logging.getLogger(self.module)
		self.logger.setLevel(logging.INFO)

		ch = logging.StreamHandler()
		ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
		self.logger.addHandler(ch)

	def info(self, message):
		self.logger.info(message)

	def debug(self, message):
		self.logger.debug(message)

	def error(self, message):
		self.logger.error(message)

	def warn(self, message):
		self.logger.warn(message)


def logged_class(cls):
	cls.logger = logger(cls)
	return cls

def logged(f, name = None):

	def wrapped(*args, **kw):
		args[0].logger.debug("-> \"%s\" %s%s" % (f.__name__, str(args), str(kw) if kw else ''))
		try:
			result = f(*args, **kw)
		except BaseException, e:
			raise
		args[0].logger.debug("<- \"%s\" %s" % (f.__name__, repr(result))) 
		return result

	wrapped.__doc__ = f.__doc__
	wrapped.__name__ = f.__name__

	return wrapped

