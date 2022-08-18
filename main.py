import subprocess
import logging as log
import schedule
import time
from sys import exit
import json
import sys
import os
import requests
from collections import defaultdict
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


log.basicConfig(
	format='[%(asctime)s] %(message)s',
	#datefmt='%Y-%m-%d %H:%M:%S',
	datefmt='%H:%M:%S',
	level=log.DEBUG
)

def pprint(msg):
	print(json.dumps(msg, indent=4, sort_keys=True))

def nested_dict(n, type):
	if n == 1:
		return defaultdict(type)
	else:
		return defaultdict(lambda: nested_dict(n-1, type))

class landog():
	def __init__(self):
		self.devices_db = list()
		self.devices_found = list()
		self.watchlist = nested_dict(2, list)
		self.watchlist_mac = list()
		if not os.path.exists("config.json"):
			print("""
				ERROR! config.json is not exist. 
				Try to rename the config-dist.json to config.json and restart the script.
				""")
			exit()
		with open("config.json", 'r') as f:
			self.config = json.loads(f.read())
		if not os.path.exists(self.config["database"]):
			print("""
				ERROR! {} is not exist.
				""".format(self.config["database"]))
			exit()
		i = 0
		for device in self.config["watchlist"]:
			self.watchlist[device["mac"]]["state"] = "dead"
			self.watchlist[device["mac"]]["alias"] = device["alias"]
			self.watchlist_mac.append(device["mac"])
			i += 1
		self.network = self.config["network"]
		self.interval = self.config["interval"]
		self.dead_timeout = self.config["dead_timeout"]
		self.dummy_scan = self.config["dummy_scan"]
		self.line_enable = self.config["line_enable"]
		self.line_token = self.config["line_token"]
		self.db_json_file = self.config["database"]

	def line(self, msg):
		if self.line_enable:
			url = 'https://notify-api.line.me/api/notify'
			headers = {'Authorization':'Bearer '+self.line_token}
			try:
				return requests.post(url, headers=headers , data = {'message':msg}, files=None)
			except KeyError as e:
				print(e)

	def write_db(self):
		with open(self.db_json_file, "w") as outfile:
			json.dump(self.devices_db, outfile, indent=4)

	def setup(self):
		log.info("network: {}".format(self.network))
		log.info("interval: {} seconds".format(self.interval))
		if self.dummy_scan:
			log.info("dummy scan")
		if self.line_enable:
			log.info("LINE enabled")
		else:
			log.info("LINE disabled")
		with open(self.db_json_file, 'r') as f:
			self.devices_db = json.loads(f.read())
		self.line("{} LANDOG started".format(self.config["station_name"]))
		log.debug("set up completed.")

	def scan(self):
		self.devices_found = list()
		log.debug("scanning... {}".format(self.network))
		if not self.dummy_scan:
			result = subprocess.check_output(['nmap', '-sn', self.network], encoding="utf-8")
		else:
			result = '''Starting Nmap 7.70 ( https://nmap.org ) at 2022-04-16 17:05 +07
				Nmap scan report for 192.168.1.99
				Host is up (0.29s latency).
				MAC Address: 44:55:55:44:44:22 (New found dummy device)
				Nmap scan report for 192.168.1.125
				Host is up (0.11s latency).
				MAC Address: 5E:02:14:00:F4:94 (Unknown)
				Nmap scan report for 192.168.1.117
				Host is up.
				Nmap done: 256 IP addresses (2 hosts up) scanned in 10.57 seconds'''
		return result

	def search_index(self, mac, dataset):
		index = 0
		for keyval in dataset:
			if mac.lower() == keyval['mac_address'].lower():
				return index
			index += 1

	def monitor(self):
		update_db = False
		################################
		# surveillance phase
		################################
		data = self.scan()
		lines = data.splitlines()
		hostsup = [int(s) for s in lines[-1][lines[-1].find("(")+1:lines[-1].find(")")].split() if s.isdigit()][0]
		elapsed = lines[-1][lines[-1].find("in ")+3:lines[-1].find("seconds")]
		log.debug("discovered {} hosts in {} seconds".format(hostsup, elapsed))
		for index, line in enumerate(lines):
			if line.find("Nmap scan") > -1:
				ip = line[line.find("for")+4:]
				tail = lines[index+2]
				if tail.find("MAC Address: ") > -1:
					tail = tail[tail.find("MAC Address: ")+13:]
					tail = tail.split(" ", 1)
					mac = tail[0]
					desc = tail[1][1:-1]
					self.devices_found.append({
						"ip_address":ip,
						"mac_address":mac,
						"timestamp":str(int(time.time())),
						"description":desc
						})

		################################
		# classify
		################################
		temp_present_devices = list()
		temp_absent_devices = list()
		temp_new_devices = list()
		temp_dead_devices = list()
		for device in self.devices_found:
			if device["mac_address"] == "":
				continue
			index_in_db = self.search_index(device["mac_address"], self.devices_db)
			# present devices
			if index_in_db is not None:				
				desc = ""
				if len(device["description"]) > 0:
					desc = device["description"]
				temp_present_devices.append({
					"ip_address":device["ip_address"],
					"mac_address":device["mac_address"],
					"timestamp":device["timestamp"],
					"description":desc
					})
			# new devices found
			else:				
				desc = ""
				if len(device["description"]) > 0:
					desc = device["description"]
				temp_new_devices.append({
					"ip_address":device["ip_address"],
					"mac_address":device["mac_address"],
					"timestamp":device["timestamp"],
					"description":desc
					})

		for device in self.devices_db:
			if device["mac_address"] == "":
				continue
			index_in_found = self.search_index(device["mac_address"], self.devices_found)
			now = int(time.time())
			if index_in_found is None:
				# absent devices
				if now - int(device["timestamp"]) < self.dead_timeout:					
					desc = ""
					if len(device["description"]) > 0:
						desc = device["description"]
					temp_absent_devices.append({
						"ip_address":"",
						"mac_address":device["mac_address"],
						"timestamp":device["timestamp"],
						"description":desc
						})
				# dead devices		
				else:					
					desc = ""
					if len(device["description"]) > 0:
						desc = device["description"]
					temp_dead_devices.append({
						"ip_address":"",
						"mac_address":device["mac_address"],
						"timestamp":device["timestamp"],
						"description":desc
						})

		################################
		# operation phase
		################################

		# operate the present devices
		if len(temp_present_devices) > 0:
			for device in temp_present_devices:
				index_in_db = self.search_index(device["mac_address"], self.devices_db)
				# device already present
				if self.devices_db[index_in_db]["status"] >= 1:
					self.devices_db[index_in_db]["status"] = 1
					update_db = True
				# device reborn from death
				elif self.devices_db[index_in_db]["status"] <= -1:
					self.devices_db[index_in_db]["status"] = 0
					update_db = True
					# extra operation
					# still need improvement, use UPPER case in comparison
					if device["mac_address"] in self.watchlist_mac or self.config["force_alert_reborn"]:
						if self.watchlist[device["mac_address"]]["state"] == "dead":
							self.line("{} ({}) reborn at {}".format(
								device["mac_address"],
								self.watchlist[device["mac_address"]]["alias"],
								self.config["station_name"]
								))
							self.watchlist[device["mac_address"]]["state"] == "reborn"
				else:
					# device comback from absent
					self.devices_db[index_in_db]["status"] = 1
					update_db = True

		# punish the absent device
		if len(temp_absent_devices) > 0:
			log.debug("temp_absent_devices: {}".format(temp_absent_devices))
			for device in temp_absent_devices:
				index_in_db = self.search_index(device["mac_address"], self.devices_db)
				self.devices_db[index_in_db]["status"] = 0
				update_db = True

		# bury the dead device
		if len(temp_dead_devices) > 0:
			log.debug("temp_dead_devices: {}".format(temp_dead_devices))
			for device in temp_dead_devices:
				index_in_db = self.search_index(device["mac_address"], self.devices_db)
				self.devices_db[index_in_db]["status"] = -1
				update_db = True
				# extra operation for the dead device
				if device["mac_address"] in self.watchlist_mac:
					if self.watchlist[device["mac_address"]]["state"] == "reborn":
						self.line("{} ({}) dead".format(device["mac_address"], self.watchlist[device["mac_address"]]["alias"]))
						self.watchlist[device["mac_address"]]["state"] == "dead"

		# operate the new devices
		if len(temp_new_devices) > 0:
			log.debug("temp_new_devices: {}".format(temp_new_devices))
			for device in temp_new_devices:
				device["status"] = 1
				self.devices_db.append(device)
				# alert new device found
				if device["mac_address"] in self.watchlist_mac:
					index_in_watchlist_mac = self.search_index(device["mac_address"], self.watchlist_mac)
					self.line(
						"{} ({}) has connected to {}".format(
							device["mac_address"],
							self.watchlist[index_in_watchlist_mac]["alias"],
							self.config["station_name"]
						)
						)
				else:
					self.line(
						"{} ({}) first connect to {}".format(
							device["mac_address"],
							device["description"],
							self.config["station_name"]
						)
						)
				time.sleep(0.1)
			update_db = True

		# update database if needed
		if update_db:
			self.write_db()

	def run(self):
		self.setup()
		self.monitor()
		schedule.every(self.interval).seconds.do(self.monitor)
		while True:
			schedule.run_pending()
			time.sleep(1)

################################
# main
################################
dog = landog()
dog.run()