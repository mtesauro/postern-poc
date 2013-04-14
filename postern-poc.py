#!/usr/bin/env python
"""
Postern
~~~~~~~~

A proof of concept implementation of a key management agent for
use with the barbican server (https://github.com/cloudkeep/barbican).

DO NOT USE THIS IN PRODUCTION. IT IS NOT SECURE IN ANY WAY.
YOU HAVE BEEN WARNED.

:copyright: (c) 2013 by Matt Tesauro
:license: Apache 2.0, see LICENSE for details
"""

import requests 
import json
import logging
import uuid
import netifaces
import socket
import platform
import time
import datetime

# Debugging
import pprint

from collections import defaultdict
from errno import ENOENT
from stat import S_IFDIR, S_IFLNK, S_IFREG
from sys import argv, exit
from fuse import FUSE, FuseOSError, Operations, LoggingMixIn
from ConfigParser import SafeConfigParser

if not hasattr(__builtins__, 'bytes'):
	bytes = str

class Memory(LoggingMixIn, Operations):
	'Memory filesystem for a POC for Cloud Keep'
	
	def __init__(self):
		self.files = {}
		self.data = defaultdict(bytes)
		self.policy = {}
		self.access_count = {}
		self.keys = {}
		self.fd = 0
		now = time.time()
		self.files['/'] = dict(st_mode=(S_IFDIR | 0755), st_ctime=now,
							   st_mtime=now, st_atime=now, st_nlink=2)
		
		# Add data from policy.json to filesystem
		for index in range(len(policy['policies'])):
			# Create files from policy
			new_file = '/' + \
						str(policy['policies'][index]['keys'][0]['filename'])
			self.files[new_file] = dict(st_mode=(S_IFREG | 33056), st_nlink=1,
										st_size=0, st_ctime=now, st_mtime=now,
										st_atime=now)
			
			self.data[new_file] = \
							str(policy['policies'][index]['keys'][0]['secret'])
			self.files[new_file]['st_size'] = len(self.data[new_file])
			
			# Set policies dict
			max_access = policy['policies'][index]['max_key_accesses']
			time_reboot = \
				       policy['policies'][index]['time_available_after_reboot']
			new_policy = {'max_access': max_access, 'time_reboot': time_reboot}
			self.policy[new_file] = new_policy
			
			# Initialize access count to zero
			self.access_count[new_file] = 0 
			
			# Initialize the file keys - e.g. UUID for each file for API
			self.keys[new_file] = \
							str(policy['policies'][index]['keys'][0]['uuid'])
			
			# Log to the API that policy has been downloaded
			msg = 'Policy being enforced for ' + new_file
			key = self.keys[new_file]
			api_log(key, msg)
		
		# Clear the policy.json dict to remove those values/secrets from memory
		policy.clear()
		print 'init() complete'
	
	def chmod(self, path, mode):
		# chmod is not allowed - clear data and panic if called
		self.clear_data()
		panic(self.keys[path])
		
		return 0
	
	def chown(self, path, uid, gid):
		# chown is not allowed - clear data and panic if called
		self.clear_data()
		panic(self.keys[path])
	
	def create(self, path, mode):
		# Nothing but policy defined files are in this filesystem
		#   so creating a new file is not allowed
		self.clear_data()
		panic("Create file attempt")
		
		return self.fd
	
	def getattr(self, path, fh=None):
		# getattr is used all the time for many operations
		# - no policy check needed
		if path not in self.files:
			raise FuseOSError(ENOENT)
		
		return self.files[path]
	
	def getxattr(self, path, name, position=0):
		# getxattr is used all the time for many operations
		# - no policy check needed
		attrs = self.files[path].get('attrs', {})
		
		try:
			return attrs[name]
		except KeyError:
			return '' # Should return ENOATTR
	
	def listxattr(self, path):
		# lists extended attributes - not supported but also not harmful
		# - no policy check needed 
		attrs = self.files[path].get('attrs', {})
		return attrs.keys()
	
	def mkdir(self, path, mode):
		# Nothing but policy defined files are in this filesystem
		#   so creating a new file is not allowed
		self.clear_data()
		panic("Create file attempt")
	
	def open(self, path, flags):
		# Reads are allowed under the constraint of the policy
		#   However, both reading and moving (unlink) end up calling read
		#   so policy enforcement is best handled there or max_access will be
		#   wrongly incremented since reading a file includes an open() and a 
		#   read() call.
		self.fd += 1
		return self.fd
	
	def read(self, path, size, offset, fh):
		# Since several filesystems operations end up here, this is a good
		#   policy enforcement point. Moving or reading files ends up with a 
		#   call here so this is the best (and last) place to enforce policy
		#   before access to the data is provided.
		# Check access against policy
		if not self.check_policy(path):
			# Violation of policy
			self.clear_data()
			panic(self.keys[path])
		else:
			# Log to the API that policy has been downloaded
			msg = 'Access of ' + path + ' allowed by policy'
			key = self.keys[path]
			api_log(key, msg)
		
		return self.data[path][offset:offset + size]
	
	def readdir(self, path, fh):
		# readdir is needed for ls and other operations
		#    may consider logging these outside policy in future
		return ['.', '..'] + [x[1:] for x in self.files if x != '/']
	
	def readlink(self, path):
		# Symlinks are not supported so calling this is a violation
		self.clear_data()
		panic(self.keys[path])
	
	def removexattr(self, path, name):
		# Extended attributes are not supported and this is a read-only 
		#   filesystem so panic if called
		self.clear_data()
		panic(self.keys[path])
	
	def rename(self, old, new):
		# Read-only filesystem so renames are not allowed, panic if called
		self.clear_data()
		panic(self.keys[old])
	
	def rmdir(self, path):
		# Read-only filesystem so renames are not allowed, panic if called
		self.clear_data()
		panic(self.keys["Remove dir attempt"])
	
	def setxattr(self, path, name, value, options, position=0):
		# Read-only filesystem so renames are not allowed, panic if called
		self.clear_data()
		panic(self.keys[old])
	
	def statfs(self, path):
		# Used by du and others to determine file sizes - seems harmless
		# - no policy check needed
		return dict(f_bsize=512, f_blocks=4096, f_bavail=2048)
	
	def symlink(self, target, source):
		# symlinks not supported - panic if called
		self.clear_data()
		panic("Attempt to create symlink")
	
	def truncate(self, path, length, fh=None):
		# Used for read/write file systems so panic if called
		self.clear_data()
		panic(self.keys[path])
	
	def unlink(self, path):
		# Used by mv if you move a file out of the fuse mounted directory
		#   plus this is read-only filesystem so panic if called
		self.clear_data()
		panic(self.keys[path])
	
	def utimens(self, path, times=None):
		## DEBUG
		print 'utimens call, path=', path, ' times=', times
		# Since this only modifies file access/modification times, no need
		#   to panic if called - no data is disclosed by this
		now = time.time()
		atime, mtime = times if times else (now, now)
		self.files[path]['st_atime'] = atime
		self.files[path]['st_mtime'] = mtime
	
	def write(self, path, data, offset, fh):
		# Read-only filesystem - panic if called
		self.clear_data()
		panic("Write attempt on filesystem")
		return 0
	
	def clear_data(self):
		# Clear existing memory structures
		self.files.clear()
		self.data.clear()
		self.policy.clear()
		for index in range(len(policy)):
			policy[index] = ''
		print 'PANIC:'
		print '\tViolation of policy. In memory filesystem erased.\n'
	
	def check_policy(self, path):
		# Check call against current access policy
		pass_policy = False
		if self.access_count[path] < self.policy[path]['max_access']:
			self.access_count[path] +=1
			pass_policy = True
		else:
			# max_access exceeded - policy check failure
			return False
		
		# Check against time since reboot
		max_seconds = float(self.policy[path]['time_reboot']) / 60
		with open('/proc/uptime', 'r') as f:
			uptime_seconds = float(f.readline().split()[0])
		if uptime_seconds < max_seconds:
			print 'Within uptime restriction'
			# pass_policy = True
		else:
			print 'Exceeded uptime restriction'
			# return False
		
		return pass_policy

def panic(key):
	"Warn the API that a violation of policy has occured"
	# Inform the API of the panic condition
	message = 'Policy violation on ' + socket.gethostname()
	panic_url = api_url + logging_uri
	# Stupid json.dumps() chokes on utcnow() so doing json manually for now
	#   no biscuit for json.dumps()
	panic_data = '{"agent_id": "' + agent_guid + '", '
	panic_data += '"received_on": "' + str(datetime.datetime.utcnow()) + '", '
	panic_data += '"severity": "PANIC", '
	panic_data += '"key_id": "' + key + '", '
	panic_data += '"message": "' + message + '"}'
	
	# Send the JSON log to the API
	headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 
		   'Accept-Charset': 'ISO-8859-1,utf8;q=0.7,*;q=0.3', 'Accept-Encoding': 'gzip,deflate,sdch'}
	panic = requests.post(panic_url, data=json.dumps(panic_data), headers=headers)
	
	if panic.status_code == 200:
		print 'Panic log sent to API'

def api_log(key, message):
	"Log data to the API"
	# Inform the API of the panic condition
	message += 'on host ' + socket.gethostname()
	log_url = api_url + logging_uri
	# Stupid json.dumps() chokes on utcnow() so doing json manually for now
	#   no biscuit for json.dumps()
	log_data = '{"agent_id": "' + agent_guid + '", '
	log_data += '"received_on": "' + str(datetime.datetime.utcnow()) + '", '
	log_data += '"severity": "INFO", '
	log_data += '"key_id": "' + key + '", '
	log_data += '"message": "' + message + '"}'
	
	# Send the JSON log to the API
	headers = {'Content-Type': 'application/json', 
			   'Accept': 'application/json', 
			   'Accept-Charset': 'ISO-8859-1,utf8;q=0.7,*;q=0.3', 
			   'Accept-Encoding': 'gzip,deflate,sdch'}
	log_call = requests.post(log_url, data=json.dumps(log_data), 
							 headers=headers)
	
	if log_call.status_code == 200:
		print 'INFO log sent to API'

def pair_data():
	"Returns the data needed to pair the agent"
	
	# Pairing requires id_guid, ip_addresses[], hostname, os/version, 
	# agent-version, tenant-id, tags[]
	pair_post = '{"uuid":"' + agent_guid + '"'
	
	pair_post += ',"agent_version": "0.1"'
	# IP addresses
	pair_post += ',"ip_addresses": [{'
	for key in netifaces.interfaces():
		pair_post += '"' + key + '": "' 
		pair_post += netifaces.ifaddresses(key)[2][0]['addr'] + '",'
	pair_post = pair_post[:-1] + '}],'
	
	# hostname, os, version and tentant ID
	pair_post += '"hostname": "' + socket.gethostname() + '",'
	pair_post += '"os_version": "' + platform.platform() + '",'
	pair_post += '"tenant_id": "' + tenant_id + '",'
	
	# tags from config file
	## currently hard coded.  
	## ToDo read these from config and set them here
	pair_post += '"tags": [{"0": "web server", "1": "Falcon API"}]'
	
	pair_post += '}'
	return pair_post

if __name__ == '__main__':
	
	# Set a few variables - some of this should probably be in the config
	config_file = '/etc/cloudkeep/postern.config'
	agent_version = '0.1'
	policy_uri = '/api/123/policies/'
	pair_uri = '/api/123/agents/'
	logging_uri = '/api/123/logs/'
	max_tries = 5
	retry_wait = 3
	
	# Read config for settings
	parser = SafeConfigParser()
	parser.read(config_file)
	
	# Set URL for the Barbican - aka the mothership
	if (parser.has_option('settings', 'api_url')):
		api_url = parser.get('settings', 'api_url')
	else:
		print 'ERROR:'
		exit('\tConfiguration file lacks a URL set for api_url\n')

	# And the rest of the settings
	if ((parser.has_option('settings', 'agent_guid')) and
		(len(parser.get('settings', 'agent_guid')) > 0)):
		agent_guid = parser.get('settings', 'agent_guid')
	else:
		agent_guid = uuid.uuid4()
		parser.set('settings', 'agent_guid', str(agent_guid))
		with open(config_file, 'wb') as new_config:
			parser.write(new_config)
	
	if (parser.has_option('settings', 'tenant_id')):
		tenant_id = parser.get('settings', 'tenant_id')
	else:
		print 'ERROR:'
		exit("\tConfiguration file lacks a ID set for tenant_id\n")
	
	if ((parser.has_option('settings', 'mount_point')) and 
		(len(parser.get('settings', 'mount_point')) > 0)):
		mount_point = parser.get('settings', 'mount_point')
	else:
		mount_point = '/etc/keys'
		#MAT# For Testing
		#mount_point = '/home/mtesauro/projects/keys'
	
	# Loop while pairing with API (if needed) and also downloading the policy
	policy = False
	paired = False
	while not policy:
		## Point this at my local server for now
		api_url = 'http://example.com/cloudkeep/'
		
		# Download the policy file
		r = requests.get(api_url + policy_uri)
		if r.status_code == 200:
			policy = r.json()
		else:
			policy = False
		
		if not policy and not paired:
			## Headers to remove the auto-gzip of the requests module
			headers = {'Content-Type': 'application/json', 'Accept': '*/*', 
						'Accept-Encoding': 'bogus'}
			pair = requests.post(api_url + pair_uri, data=pair_data(), 
								 headers=headers)
			if pair.status_code == 200:
				paired = True
		
		# Limit the number of times we'll attempt and exit if exceeded 
		max_tries-=1
		if max_tries == 0:
			print 'Error: \n\tUnable to pair and/or pull policy from the API'
			exit(1)
		
		time.sleep(retry_wait)
	
	#MAT# No logging for now
	##logging.getLogger().setLevel(logging.DEBUG)
	fuse = FUSE(Memory(), mount_point, foreground=True)
