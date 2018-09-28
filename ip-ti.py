import sys
import re
from OTXv2 import OTXv2, IndicatorTypes
from cymon import Cymon
from threading import Thread, BoundedSemaphore
from datetime import datetime
import time
from os import walk, listdir, path, environ, system, makedirs
import whois
from ipwhois.net import Net
from ipwhois.asn import IPASN
import requests
import jinja2
import prettytable
import json
import ipaddress
import geoip2.database
import argparse


# Global Vars
time_to_be_appended_with_file_names = int(time.time())
max_threads = 15
dirs = ['output-{0}'.format(time_to_be_appended_with_file_names), '']
api_key_otx = ''
api_key_cymon = ''
pool_sema = []
# otx = OTXv2(api_key_otx)
output_csv = 'ti-output-csv-{0}.csv'.format(time_to_be_appended_with_file_names)
file_count = 0
# replace comma with this character
replace_char = '`'
# characters in between 2 pulses
pulse_separator = '---'
args = ''
# Dictionary to contain all malicious IPs
mal_ips_dict = {}
# list to hold stats for error for OTX and Cymon Requests, respectively
rl_hit = [0, 0]
# list to hold all the booleans for feed type
bool_feed_list = [False, False, False, False]
######


def setup_argparse():
	global args
	parser = argparse.ArgumentParser(
		description='''
		This script finds all unique IPs in each file and generates a CSV with related Threat Intelligence. 
		CSV contains only the malicious IPs. Outputs a directory which contains all records of an IP, as it is in the original log. \nIt is required to 
		setup OTX API Key, Cymon API Key and C1fapp API Key in environment variable before executing the script''',
		epilog="""All's well that ends well.""",
		usage="""
		**********************************
		********Really Important**********
		************Must Read*************
		**********************************
		Before running this script for the very first time on Linux, read Readme.md or following.
		Perform these steps in order to successfully execute the ip-ti.py script.
		1. cd into the current directory
		2. Run the command "cd cymon-python-master && python3 setup.py install && cd .."
		3. Run command "pip3 -r install requirements.txt"
		4. Enter the appropriate API Keys and run command "export API_KEY_OTX=<OTX-API-KEY> && export API_KEY_CYMON=<CYMON-API-KEY> && export API_KEY_C1FAPP=<C1FAPP-API-KEY>"
		5. Run command "python3 ip-ti.py -h" and get all information on how to execute the script with different feeds (OTX, Cymon, C1fapp and Custom feed files from Spamhaus)
		=================================================\n\n
		=================================================
		=================Example Usage===================
		1. python3 ip-ti.py -rd path/to/root/directory/with/log/files --feed all -cff <path_to_custom_feed_folder>
		2. python3 ip-ti.py -rd path/to/root/directory/with/log/files --feed otx -ako <Environment_varibale_name_with_OTX_API_KEY>
		3. python3 ip-ti.py -rd path/to/root/directory/with/log/files --feed cymon -akc <Environment_varibale_name_with_Cymon_API_KEY>
		4. python3 ip-ti.py -rd path/to/root/directory/with/log/files --feed custom -cff <path_to_custom_feed_folder>
		5. python3 ip-ti.py -rd path/to/root/directory/with/log/files --feed c1fapp -c1f <Environment_varibale_name_with_C1fapp_API_KEY>""")
	parser.add_argument('--out', '-o', '-O', '-OUTPUT', default='{0}/{1}'.format(dirs[0], output_csv), required=False,
						help='(Optional) path/to/name/of/output/file. Deafult is {0}'.format(output_csv))
	parser.add_argument('--rootDir', '-rd', default='', required=True,
						help='(Required) path/to/name/of/rootDirectory which contains all the log files and log folder')
	parser.add_argument('--api_key_otx', '-ako', default='API_KEY_OTX', required=False,
						help='Environment variable name for OTX API KEY. Required if feed used is otx')
	parser.add_argument('--api_key_cymon', '-akc', default='API_KEY_CYMON', required=False,
						help='Environment variable name for Cymon API KEY. Required if feed used is Cymon')
	parser.add_argument('--api_key_c1fapp', '-akc1f', default='API_KEY_C1FAPP', required=False,
						help='Environment variable name for C1FAPP API KEY. Required if feed used is C1FAPP')
	parser.add_argument('--feed', '-f', '-F', '-FEED', default='otx', required=True, help='(Required) Feed to use. Supported options --feed=otx or --feed=cymon or --feed=custom or --feed=c1fapp or --feed=all or a comma separated list like --feed=custom,cymon,otx,c1fapp. Use either of them.')
	parser.add_argument('--custom_feed_folder', '-cff', default='custom_feed_folder', required=False,
						help='(Optional) Geo IP DB to use. /path/to/custom/feed/folder. Default value is "custom_feed_folder"')
	parser.add_argument('--geo_ip_db', '-gid', '-GID', '-GEO_IP_DB', default='GeoLite2-Country_20180501/GeoLite2-Country.mmdb', required=False,
						help='(Optional) Geo IP DB to use. /path/to/geo/ip/db.mmdb. Default value is "GeoLite2-Country_20180501/GeoLite2-Country.mmdb"')
	parser.add_argument('--threads', '-t', '-T', '-THREADS', type=int, default=10, required=False,
						help='(Optional) Number of threads to use. Default value is 10')
	parser.add_argument('--pulse_separator', '-ps', default=pulse_separator, required=False,
						help='(Optional) Separate various pulses based on this separator')
	parser.add_argument('--comma_replacer', '-cr', default=replace_char, required=False,
						help='(Optional) Replace comma in a csv cell with this value')
	parser.add_argument('--ip_records_directory', '-ird', default='{0}/ip_records_directory'.format(dirs[0]), required=False,
						help='(Optional) Directory that contains all records where the malicious IP was found. Default value is ip_records_directory')
	parser.add_argument('--parallel_num_file', '-pnf', default=1, required=False, type=int,
						help='(Optional) Maximum number of files to check IPs from simultaneously. Lesser number will generate more accurate results. Default is 1 files')
	parser.add_argument('--threat_intel_type', '-ti_type', default='all', required=False,
						help='(Optional) Type of Threat Intel. allowed values are "domain", "ip", "all". Default is "all"')
	# parser.add_argument('--thread_wait_time', '-twt', default=2, required=False, type=int,
	#					 help='(Optional) Time in seconds to wait before calling each thread. Default is 2 seconds')
	args = parser.parse_args()

	max_threads = args.threads
	global pool_sema
	pool_sema = []
	pool_sema.append(BoundedSemaphore(value=max_threads))
	pool_sema.append(BoundedSemaphore(value=1))
	pool_sema.append(BoundedSemaphore(value=max_threads))
	pool_sema.append(BoundedSemaphore(value=args.parallel_num_file))

	# enforcing feed
	for i in str(args.feed).split(','):
		set_feed_from_args(i)

	print('Argparse setup complete')


def set_feed_from_args(cur_feed):
	global bool_feed_list, args
	if cur_feed == 'otx':
		print('Will Gather Threat Intel from OTX')
		if args.api_key_otx == '':
			print('Please enter the environment variable name that holds the OTX API Key in --api_key_otx')
			sys.exit()
		else:
			args.api_key_otx = environ[args.api_key_otx]
			bool_feed_list[0] = True
	elif cur_feed == 'cymon':
		print('Will Gather Threat Intel from Cymon feed')
		if args.api_key_otx == '':
			print('Please enter the environment variable name that holds the Cymon API Key in --api_key_cymon')
			sys.exit()
		else:
			args.api_key_cymon = environ[args.api_key_cymon]
			bool_feed_list[1] = True
	elif cur_feed == 'custom':
		print('Will Gather Threat Intel from Cymon feed')
		if args.custom_feed_folder == '':
			print('Please enter the path to custom feed folder files')
			sys.exit()
		if (not len(get_all_file_paths(args.custom_feed_folder)) > 0):
			print('No files found in folder {0}'.format(args.custom_feed_folder))
			sys.exit()
		bool_feed_list[2] = True
	elif cur_feed == 'C1FAPP':
		print('Will Gather Threat Intel from C1FAPP feed')
		if args.api_key_otx == '':
			print('Please enter the environment variable name that holds the C1FAPP API Key in --api_key_c1fapp')
			sys.exit()
		else:
			args.api_key_c1fapp = environ[args.api_key_c1fapp]
			bool_feed_list[3] = True
	elif cur_feed == 'all':
		print('Gathering Threat Intel from all feeds')
		if args.api_key_otx == '' or args.api_key_cymon == '' or args.api_key_c1fapp == '' or args.custom_feed_folder == '':
			print('Please enter the environment variable name that holds the Cymon API Key in --api_key_cymon')
			print('Please enter the environment variable name that holds the OTX API Key in --api_key_otx')
			print('Please enter the environment variable name that holds the OTX API Key in --api_key_c1fapp')
			print('Please enter the path to custom feed folder containing custom feed files in --custom_feed_folder')
			sys.exit()
		if (not len(get_all_file_paths(args.custom_feed_folder)) > 0):
			print('No files found in folder {0}'.format(args.custom_feed_folder))
			sys.exit()
		try:
			if not str(args.api_key_otx).isalnum():
				args.api_key_otx = environ[args.api_key_otx]
				print('OTX Key Set')
				bool_feed_list[0] = True
			if not str(args.api_key_cymon).isalnum():
				args.api_key_cymon = environ[args.api_key_cymon]
				print('Cymon Key Set')
				bool_feed_list[1] = True
			if not str(args.api_key_c1fapp).isalnum():
				args.api_key_c1fapp = environ[args.api_key_c1fapp]
				print('C1FAPP Key Set')
				bool_feed_list[3] = True
			bool_feed_list[2] = True
		except Exception as e:
			print('Error {0} occurred when checking for OTX, Cymon, C1FAPP API Keys in environment variables'.format(e))
			sys.exit()
	else:
		print('Please enter either "otx" or "cymon" or "custom" or "all" or "c1fapp" or comma separated list like custom,otx,cymon,c1fapp as --feed argument')
		sys.exit()	


def get_country(ip):
	'''
	reads country from Geo IP DB for given IP
	'''
	ret = ''
	try:
		reader = geoip2.database.Reader(args.geo_ip_db)
		response = reader.country(ip)
		ret = response.country.name
	except:
		ret = 'Unknown'
	return ret


def read_unique_ips_from_file(file_name):
	'''
	Finds all unique IPs in a given file
	'''
	mTime = [datetime.now(), 0]

	# Eg: {IP: Reputation}. By default reputation will be 0, i.e good
	mDict = {}
	print('Checking in file: {0}'.format(file_name))
	ValidIpAddressRegex = r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[\/\d+]*'
	with open(file_name) as inFile:
		for line in inFile:
			line = line.rstrip('\n')
			# foundList = (re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line))
			foundList = re.findall(ValidIpAddressRegex, line)
			if foundList and len(foundList) > 0:
				for item in foundList:
					if item not in mDict:
						try:
							# print('Initially found: {0}'.format(item))
							ip = ipaddress.ip_address(item.split('/')[0])
							mDict[item] = 0
							# print('Found item {0} from file: {1}'.format(item, file_name))
						except:
							# print('Exception {0} occurred in read_unique_ips_from_file'.format(e))
							pass
	print('Found total {0} unique IPs in file {1}'.format(len(mDict), file_name))
	print('Following unique IPs were found from file {0}:\n{1}'.format(file_name, mDict))


	mTime[1] = datetime.now()
	print('End Time: {0}'.format(mTime[1]))
	print('Start Time: {0}'.format(mTime[0]))
	print('End Time: {0}'.format(mTime[1]))
	print('Time Diff: {0}'.format(mTime[1] - mTime[0]))
	return mDict if len(mDict) > 0 else None


def getPulseNames(mPulses):
	try:
		ret = ''
		for pulse in mPulses:
			mStr = str(pulse['name'].replace(',', args.comma_replacer))
			# so pulse namesa re not repeated
			if mStr not in ret:
				ret += mStr + ' ' + args.pulse_separator + ' '

		ret = ret.rstrip(' ' + args.pulse_separator + ' ')
		return ret
	except Exception as e:
		return 'Pulse Info Error'


def write_to_output_file(mStr, out_file_name):
	pool_sema[1].acquire()
	with open(out_file_name, 'a') as o:
		o.write(mStr + '\n')
	pool_sema[1].release()


def add_to_malicious_ips(ip, reasons, type='otx'):
	'''
	Helps maintaining a dictionary with OTX and Cymon reason/pulses
	'''
	global mal_ips_dict
	if ip not in mal_ips_dict:
		# [1, 'otx TI', 'cymon TI', 'custom local TI', 'c1fapp TI', '', '', '', '']
		mal_ips_dict[ip] = [1, '', '', '', '', '', '', '', '', '', '']
	if type == 'otx':
		mal_ips_dict[ip][1] = reasons
	elif type == 'cymon':
		mal_ips_dict[ip][2] = reasons
	elif type == 'custom':
		mal_ips_dict[ip][3] = reasons
	elif type == 'c1fapp':
		mal_ips_dict[ip][4] = reasons
	else:
		print('Unknown type in add_to_malicious_ips')


def get_ti_from_OTX(ip, in_file_name, out_file_name, country, ti_type):
	mStr = ''
	ip_rep = 0
	pulses_names = ''
	res = ''
	try:
		if ti_type == 'ip':
			res = OTXv2(args.api_key_otx).get_indicator_details_full(IndicatorTypes.IPv4, ip)
			ip_rep = res['general']['reputation']
			print('IP rep: {0}'.format(ip_rep))
			# for malicious IPs, get pulse names
			if '1' in str(ip_rep):
				pulses_names = getPulseNames(res['general']['pulse_info']['pulses'])
				print('IP: {0}\tIP Rep: {1}\tIP Pulses'.format(ip, ip_rep, pulses_names))
		else:
			res = OTXv2(args.api_key_otx).search_pulses(ip)
			# res = OTXv2('0d89be741a69cb6cd8c3b56b0cd0d5ba9dedd0a9c0289b6148de9c3a3a3c2ba1').search_pulses(ip)
			if 'results' in res and len(res['results']) > 0:
				for result in  res['results']:
					pulses_names += result['name'] + ' ' + args.pulse_separator
					# pulses_names += result['name'] + ' ' + '---'

				pulses_names = pulses_names.rstrip(' ' + args.pulse_separator)

		print(res)

	except Exception as e:
		rl_hit[0] = rl_hit[0] + 1
		print('Exception {0} occurred when fetching TI for IP {1} from OTX{2}'.format(e, ip, res))

	# write only malicious IPs to output file
	if '1' in str(ip_rep):
		mStr = str(pulses_names)

		add_to_malicious_ips(ip, mStr, type='otx')

		# put IP records in a separate file
		if is_ip_malicious(ip):
			put_ip_records_in_separate_file(ip, in_file_name, 'otx')

		print('\n\n\n')
		print('IP: {0}\t OTX TI Results: {1}'.format(ip, mStr))
		print('\n\n\n')


def getValForKey_and_replaceCommas(key, mDict):
	mStr = ''
	try:
		mStr = str(mDict[key]).replace(',', args.comma_replacer)
	except:
		pass
	return mStr


def get_ti_from_Cymon(ip, in_file_name, out_file_name, country, ti_type):
	mStr = ''
	ip_events = ''
	try:
		ip_reasons = ''
		if ti_type == 'ip':
			ip_events = Cymon(auth_token=args.api_key_cymon).ip_events(ip)
		else:
			''' supported tags: malware, botnet, spam, phishing, dnsbl, blacklist '''
			# ip_events = Cymon(auth_token=api_key_cymon).ip_domains(ip)
			ip_events = Cymon(auth_token=args.api_key_cymon).domain_lookup(ip)

			if ip_events and 'ips' in ip_events and len(ip_events['ips']) > 0:
				for ip_record in ip_events['ips']:
					ip_record = str(ip_record).split('/')[-1]
					ip_reason = get_ti_from_Cymon(ip_record, in_file_name, out_file_name, get_country(ip_record), 'ip')
					if ip_reasons not in ip_reasons:
						ip_reasons += ip_reason + ' ' + args.pulse_separator + ' '
				
				if len(ip_reasons) > 0:
					ip_reasons = ip_reasons.rstrip(' ' + args.pulse_separator + ' ')
			# ip_events = Cymon(auth_token='f113e3e93cc469c638bc78d1cbe9d26b9e05f909').domain_lookup(ip)
			# # ip_events = Cymon(auth_token='f113e3e93cc469c638bc78d1cbe9d26b9e05f909').url_lookup(ip)
			# ip_events = Cymon(auth_token='f113e3e93cc469c638bc78d1cbe9d26b9e05f909').domain_blacklist('malware', days=180)
			# print(ip_events)
			# ip_events = Cymon(auth_token='f113e3e93cc469c638bc78d1cbe9d26b9e05f909').domain_blacklist('spam', days=180)
			# print(ip_events)
			# ip_events = Cymon(auth_token='f113e3e93cc469c638bc78d1cbe9d26b9e05f909').domain_blacklist('botnet', days=180)
			# print(ip_events)
			# ip_events = Cymon(auth_token='f113e3e93cc469c638bc78d1cbe9d26b9e05f909').domain_blacklist('dnsbl', days=180)
			# print(ip_events)

		# gather all IP reasons
		if ti_type == 'ip' and ip_events and 'results' in ip_events and len(ip_events['results']) > 0:
			for event in ip_events['results']:
				tag = title = ''
				tag = getValForKey_and_replaceCommas('tag', event)
				title = getValForKey_and_replaceCommas('title', event)
				ip_reason = '{0} {1} {2} {3} '.format(tag, args.comma_replacer, title, args.pulse_separator)

				# do not enter duplicate Cymon TI reasons
				if ip_reason not in ip_reasons:
					ip_reasons += ip_reason

			# remove last '--- ' from the end of ip_reasons
			ip_reasons = ip_reasons.rstrip(args.pulse_separator + ' ')


		# Write only malicious IPs to output file
		if ip_reasons != '':
			mStr = str(ip_reasons)
			add_to_malicious_ips(ip, mStr, type='cymon')

			# put IP records in a separate file
			if is_ip_malicious(ip):
				put_ip_records_in_separate_file(ip, in_file_name, 'cymon')
			
			print('\n\n\n')
			print('IP: {0}\t Cymon TI Results: {1}'.format(ip, mStr))
			print('\n\n\n')
	except Exception as e:
		# if the error is rate limit on Cymon and the IP has already been marked as malicious by another TI feed, add ratelimiting as the Cymon TI feed value
		rl_hit[1] = rl_hit[1] + 1
		# Commented this, so, we don;t get Cymon Request Limit reached in final result for Cymon in case when the API limit is reached
		# if 'too many requests' in str(e).lower():
		# 	mStr2 = 'Cymon Request Limit Reached'
		# 	if is_ip_malicious(ip):
		# 		add_to_malicious_ips(ip, mStr2, type='cymon')
		# else:
		# 	print('Exception {0} occurred in get_ti_from_Cymon'.format(e))	
		print('Exception {0} occurred in get_ti_from_Cymon'.format(e))		

	return mStr 

	# release semaphore
	# pool_sema[2].release()


def put_ip_records_in_separate_file(ip, in_file_name, ti_feed, mStr=''):
	try:
		# grep_command = "grep -H {0} {1} >> {2}/{3}-{0}-ip-records.logs".format(ip, in_file_name, args.ip_records_directory, ti_feed)
		print('Putting records for {0} in file {1}/{2}-{3}-records.log'.format(ip, args.ip_records_directory, ti_feed, ip))
		if mStr == '':
			grep_command = "grep -r -H {0} {1} >> {2}/{3}-{4}-records.log".format(ip, args.rootDir, args.ip_records_directory, ti_feed, str(ip).split('/')[0])
			# print('Running command: {0}'.format(grep_command))
		else:
			grep_command = "echo '{1}' >> {2}/{3}-{0}-records.log".format(ip, mStr, args.ip_records_directory, ti_feed)
		system(grep_command)
	except Exception as e:
		print('Exception {0} occurred in put_ip_records_in_separate_file'.format(e))


def is_ip_malicious(ip):
	global mal_ips_dict
	return ip in mal_ips_dict


def get_reason_from_local_file(ip, what_to_look_for, in_file_name, ti_file_name):
	'''
	Finds line that contains the ip and extracts reason from that line
	'''
	mStr = ''
	with open(ti_file_name) as inFile:
		for line in inFile:
			if what_to_look_for in line:
				mStr = line.rstrip('\n')
	return mStr


def get_ti_from_local_file(ip, in_file_name, out_file_name, country, ti_type):
	# get all local feed files in custom feed folder
	fileSet = get_all_file_paths(args.custom_feed_folder)
	# fileSet = get_all_file_paths('custom_feed_folder')
	ip_reasons = ''
	records_put_atleast_once = False

	# if there are any files in custom feed folder
	if len(fileSet) > 0:
		for i in fileSet:
			ti_file_name = args.custom_feed_folder + '/' + i
			# ti_file_name = 'custom_feed_folder' + '/' + i
			if ti_type == 'ip':
				uniques = read_unique_ips_from_file(ti_file_name)
				if uniques is None or len(uniques) == 0:
					print('Continuing since no IPs were found from TI file {0}'.format(ti_file_name))
					continue
				unique_ip = ''
				for unique_ip in uniques:
					try:
						if (ipaddress.ip_address(ip) in ipaddress.ip_network(unique_ip)):
							ip_reasons = get_reason_from_local_file(ip, unique_ip, in_file_name, ti_file_name)
							if ip_reasons != '':
								# record_file_name = '{0}-{1}.log'.format(str(i).split('/')[-1], str(ip).split('/')[0])
								# print('\n\n\nPut Record in a separate file for {0}: {2} in {3} found in file {1}\n\n\n'.format(ti_type, ti_file_name, ip, record_file_name))
								put_ip_records_in_separate_file(ip, '', 'custom-{0}'.format(str(i).split('/')[-1]), ip_reasons)
								add_to_malicious_ips(ip, str(i).split('/')[-1], type='custom')
								records_put_atleast_once = True
								# print('\n\n\nPut Record in a separate file for {0}: {2} in {3} found in file {1}\n\n\n'.format(ti_type, ti_file_name, ip, record_file_name))
								break
					except Exception as e:
						print('Exception {0} occurred in get_ti_from_local_file for {3}: {1}, unique_ip: {2}'.format(e, ip, unique_ip, ti_type))
			else:
				uniques = read_unique_domains_from_file(ti_file_name)
				if ti_type != 'ip' and ip in uniques:
					ip_reasons = get_reason_from_local_file(ip, ip, in_file_name, ti_file_name)
					if ip_reasons != '':
						record_file_name = 'custom-{0}'.format(str(i).split('/')[-1], str(ip).split('/')[0])
						put_ip_records_in_separate_file(ip, in_file_name, record_file_name, mStr=ip_reasons)
						add_to_malicious_ips(ip, str(i).split('/')[-1], type='custom')
						records_put_atleast_once = True
						print('\n\n\nPut Record in a separate file for {0}: {2} in {3} found in file {1}\n\n\n'.format(ti_type, ti_file_name, ip, record_file_name))

			if records_put_atleast_once:
				break

	else:
		print('No local files found in {0}'.format(args.custom_feed_folder))
	pass


def get_whois_info(thing, ti_type):
	# ipwhois
	# {'asn': '15169', 'asn_date': '1992-12-01', 'asn_registry': 'arin', 'asn_country_code': 'US', 'asn_description': 'GOOGLE
	# - Google LLC, US', 'asn_cidr': '8.8.8.0/24'}

	# whois
	# {'country': US, 'org': 'Google LLC', 'registrar': ''}

	res = []
	try:
		if ti_type == 'ip':
			# ip_res = IPASN(Net('8.8.8.8')).lookup()
			ip_res = IPASN(Net(thing)).lookup()
			res.append(str(ip_res['asn_country_code']).replace(',', args.comma_replacer))
			res.append(str(ip_res['asn_description']).replace(',', args.comma_replacer))
			res.append('')
			res.append(str(ip_res['asn']).replace(',', args.comma_replacer))
			res.append(str(ip_res['asn_date']))
			res.append('')
		else:
			# ip_res = whois.whois('google.com')
			ip_res = whois.whois(thing)
			res.append(str(ip_res['country']).replace(',', args.comma_replacer))
			res.append(str(ip_res['org']).replace(',', args.comma_replacer))
			res.append(str(ip_res['registrar']).replace(',', args.comma_replacer))
			res.append('')
			res.append(str(ip_res['creation_date'][0]))
			res.append(str(ip_res['updated_date'][0]))
	except Exception as e:
		pass

	return res


def get_appended_elements_from_list(mList):
	res = ''
	for item in mList:
		item = str(item).replace(',', args.comma_replacer)
		if item not in res:
			res.append(item + ' ' + args.comma_replacer + ' ')
	if len(res) > 0 and res[-1] == ' ':
		res = res.rstrip(' ')
	return res


def append_string_to_final_result(mStr, fin_result):
	if mStr and len(mStr) > 0 and mStr not in fin_result:
		fin_result += mStr + ' ' + args.comma_replacer
	return fin_result


def get_ti_from_c1fapp(ip, in_file_name, out_file_name, country, ti_type):
	fin_result = ''
	c1fapp_query = requests.Session().post('https://www.c1fapp.com/cifapp/api/', 
		data=json.dumps({'key': args.api_key_c1fapp,
		   'format': 'json',
		   'backend': 'es',
		   'request': ip
		}))
	try:
		try:
			try:
				results = json.loads(c1fapp_query.text)
				if len(results) > 0:
					for res in results:
						if len(res['assessment']) > 0 and 'whitelist' in res['assessment']:
							continue
						if len(res['feed_label']) > 0:
							fin_result = append_string_to_final_result(get_appended_elements_from_list(res['domain']), fin_result)
							fin_result = append_string_to_final_result(get_appended_elements_from_list(res['ip_address']), fin_result)
							fin_result = append_string_to_final_result(get_appended_elements_from_list(res['description']), fin_result)
							fin_result = append_string_to_final_result(get_appended_elements_from_list(res['feed_label']), fin_result)

							fin_result = fin_result.rstrip(' ' + args.comma_replacer)
							fin_result += ' ' + args.pulse_separator

							add_to_malicious_ips(ip, fin_result, type='c1fapp')

						# confidence = str(res['confidence'][0])
						# asn = str(res['asn'][0])
						# res['confidence'] = confidence

						# c1fappTab.add_row([''.join(res['feed_label']),
						#						''.join(res['domain']),
						#						''.join(res['description']),
						#						''.join(res['assessment']),
						#						''.join(confidence),
						#						''.join(res['reportime']),
						#						''.join(res['ip_address']),
						#						''.join(asn)
							# ])
						# r.append(res)

					# put IP records in a separate file

					if len(fin_result) > 0:
						fin_result = fin_result.rstrip(' ' + args.pulse_separator)
						add_to_malicious_ips(ip, fin_result, type='c1fapp')
						put_ip_records_in_separate_file(ip, in_file_name, 'c1fapp')
			except Exception as e:
				print('Exception "{0}" occurred in get_ti_from_c1fapp'.format(e))
		except Exception as e:
			print('2nd Exception "{0}" occurred in get_ti_from_c1fapp'.format(e))
	except Exception as e:
		print('3rd Exception "{0}" occurred in get_ti_from_c1fapp'.format(e))

	return fin_result


def get_feed_count(tis):
	'''
	The tis array contains all reuslts from all feeds. This function counts how many feeds returned some results
	'''
	feed_count = 0
	for i in tis:
		if len(str(i)) > 0:
			feed_count += 1
	return feed_count


def get_feed_ioc_count(feed_ioc_list):
	ret_len = len(feed_ioc_list)
	if ret_len == 1 and feed_ioc_list[0] == '':
		ret_len = 0
	return ret_len


def get_threaded_ti(ip, in_file_name, out_file_name, country, ti_type):
	# list to keep track of all threads
	global bool_feed_list
	mThreads = []
	ti_otx = ti_cymon = ti_custom = ti_c1fapp = ''

	# get OTX TI feed results
	# if args.feed == 'otx' or args.feed == 'all':
	if bool_feed_list[0]:
		print('Checking otx feed for {1}: {0}'.format(ip, ti_type))
		try:
			ti_otx = get_ti_from_OTX(ip, in_file_name, out_file_name, country, ti_type)
			# mThreads.append(Thread(target=get_ti_from_OTX, args=(ip, in_file_name, out_file_name, country,)))
			# mThreads[-1].start()
		except Exception as e:
			print('Exception "{0}" covered for OTX in get_threaded_ti'.format(e))

	# get Cymon TI feed results
	# if args.feed == 'cymon' or args.feed == 'all':
	if bool_feed_list[1]:
		print('Checking cymon feed for {1}: {0}'.format(ip, ti_type))
		try:
			ti_cymon = get_ti_from_Cymon(ip, in_file_name, out_file_name, country, ti_type)
			# print('Checking cymon feed for IP: {0}'.format(ip))
			# mThreads.append(Thread(target=get_ti_from_Cymon, args=(ip, in_file_name, out_file_name, country,)))
			# mThreads[-1].start()
		except Exception as e:
			print('Exception "{0}" covered for Cymon in get_threaded_ti'.format(e))

	# get TI from local files
	# if args.feed == 'custom' or args.feed == 'all':
	if bool_feed_list[2]:
		print('Checking custom feed folder {1} for {2}: {0}'.format(ip, args.custom_feed_folder, ti_type))
		try:
			ti_local = get_ti_from_local_file(ip, in_file_name, out_file_name, country, ti_type)
		except Exception as e:
			print('Exception "{0}" covered for Custom TI in get_threaded_ti'.format(e))

	# get TI from C1FAPP 
	if bool_feed_list[3]:
		print('Checking c1fapp feed for {1}: {0}'.format(ip, ti_type))
		try:
			ti_c1fapp = get_ti_from_c1fapp(ip, in_file_name, out_file_name, country, ti_type)
		except Exception as e:
			print('Exception "{0}" covered for C1fapp in get_threaded_ti'.format(e))

	# if ti_type == 'domain' and ip not in mal_ips_dict:
	#	 d_whois = whois.whois(ip)

	# wait for TI feed threads to finish
	# for t in mThreads:
	#	 t.join()

	# if any of the TI feeds returns anything useful regarding this IP
	if is_ip_malicious(ip):
		# put_ip_records_in_separate_file(ip, in_file_name)

		# set ti_otx and ti_cymon here
		global mal_ips_dict
		ti_otx = mal_ips_dict[ip][1]
		ti_cymon = mal_ips_dict[ip][2]
		ti_custom = mal_ips_dict[ip][3]
		ti_c1fapp = mal_ips_dict[ip][4]

		# a list to hold all TI feed results so that the feed_count score can be calculated from an array and not individual feed variables
		tis = []
		tis.append(ti_otx)
		tis.append(ti_cymon)
		tis.append(ti_custom)
		tis.append(ti_c1fapp)
		feed_count = get_feed_count(tis)

		# if the whois record for malicious IP haven't been filled yet, then get the whois records now
		ti_whois = []
		if mal_ips_dict[ip][5] == '':
			ti_whois = get_whois_info(ip, ti_type)
		else:
			ti_whois.append(mal_ips_dict[ip][4])
			ti_whois.append(mal_ips_dict[ip][5])
			ti_whois.append(mal_ips_dict[ip][6])
			ti_whois.append(mal_ips_dict[ip][7])
			ti_whois.append(mal_ips_dict[ip][8])
			ti_whois.append(mal_ips_dict[ip][9])


		# This will be added to the output CSV file
		# mStr = ','.join([str(i) for i in [in_file_name, ip, country, feed_count, ti_otx, get_feed_ioc_count((str(ti_otx).split(args.pulse_separator))), ti_cymon, get_feed_ioc_count(str(ti_cymon).split(args.pulse_separator)), ti_custom, get_feed_ioc_count(str(ti_custom).split(args.pulse_separator)), ti_c1fapp, get_feed_ioc_count(str(ti_c1fapp).split(args.pulse_separator)), ti_whois[0], ti_whois[1], ti_whois[2], ti_whois[3], ti_whois[4], ti_whois[5]]])
		mStr = ''
		for i in [in_file_name, ip, country, feed_count, ti_otx, get_feed_ioc_count((str(ti_otx).split(args.pulse_separator))), ti_cymon, get_feed_ioc_count(str(ti_cymon).split(args.pulse_separator)), ti_custom, get_feed_ioc_count(str(ti_custom).split(args.pulse_separator)), ti_c1fapp, get_feed_ioc_count(str(ti_c1fapp).split(args.pulse_separator)), ti_whois[0], ti_whois[1], ti_whois[2], ti_whois[3], ti_whois[4], ti_whois[5]]:
			mStr += str(i) + ','
		mStr = mStr.rstrip(',')

		print('\n\n\n')
		print('Writing to output CSV: {0}'.format(ip))
		write_to_output_file(mStr, out_file_name)
		print('\n\n\n')

	# Release semaphore after the thread is finished
	pool_sema[0].release()


def get_ti(mIPsDict, in_file_name, out_file_name, ti_type):
	# list to retain all vars for threads
	mThreads = []
	try:
		for ip, v in mIPsDict.items():
			country = None
			print('Checking IP: {0} from File: {1}'.format(ip, in_file_name))

			if ti_type == 'ip':
				# if ip is marked malicious already, no need to fetch results again
				if is_ip_malicious(ip): 
					print('IP {0} is already marked as malicious. Therefore, continuing'.format(ip))
					continue

				# print('Working for IP: {0}'.format(ip))
				country = get_country(ip)

			# necessary to sleep threads to avoid hitting rate limit
			# if args.parallel_num_file == 1:
			#	 time.sleep(args.thread_wait_time)

			pool_sema[0].acquire()
			mThreads.append(Thread(target=get_threaded_ti, args=(ip, in_file_name, out_file_name, country, ti_type,)))
			mThreads[-1].start()

		# wait for threaded TI feed threads to finish
		for t in mThreads:
			t.join()
	except Exception as e:
		print('Exception {0} occurred in get_ti'.format(e))

	pool_sema[3].release()


def ready_output_file(outFile):
	'''
	Write header in the output file
	'''
	
	# make separate output directory, everytime when the script is executed
	if not path.isdir(dirs[0]):
		makedirs(dirs[0])

	# setup ip_records_directory, i.e: the directory that'll contain all IP logs
	if not path.isdir(args.ip_records_directory):
		makedirs(args.ip_records_directory)

	with open(outFile, 'w') as o: o.write(','.join(['filename',
											'item',
											'country',
											'feed_count',
											'otx_ti','otx_ioc_count',
											'cymon_ti','cymon_ioc_count',
											'custom_spamhaus_ti','custom_ioc_count',
											'c1fapp_ti','c1fapp_ioc_count',
											'whois_country','whois_organization','whois_registrar','whois_asn', 'whois_creation_date', 'whois_updated_date',
											'\n']))
	print('Output File created {0} is ready'.format(outFile))


def get_all_file_paths(rootDir):
	'''
	Get path to all files inside the root directory
	'''
	fileSet = set()

	for dir_, _, files in walk(rootDir):
		for fileName in files:
			relDir = path.relpath(dir_, rootDir)
			relFile = path.join(relDir, fileName)
			relFile = relFile.lstrip('./')
			fileSet.add(relFile)

	print('Gathered File Paths: {0}'.format(fileSet))
	return fileSet


def read_unique_domains_from_file(file_name):
	mDict = {}
	print('Checking Domains in file: {0}'.format(file_name))
	with open(file_name) as inFile:
		for line in inFile:
			foundList = re.findall(r'(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', line)
			if foundList and len(foundList) > 0:
				for item in foundList:
					if item not in mDict:
						try:
							mDict[item] = 1
							# print('Found domain: {0} in file: {1}'.format(item, file_name))
						except:
							pass

	print('Read {0} unique domains from file {1}'.format(len(mDict), file_name))
	return mDict


def output_info():
	print('\n\n\n')
	print('Output Threat Intel CSV: {0}'.format(args.out))
	print('For each IP/Domain, records can be found under directory {0}'.format(args.ip_records_directory))
	print('Total malicious IPs count {0}'.format(len(mal_ips_dict)))
	# print('Total exceptions for OTX API: {0}'.format(rl_hit[0]))
	# print('Total exceptions for Cymon API: {0}'.format(rl_hit[1]))
	print('\n\n\n')


def get_my_ti(fileSet, rootDir, ti_type):
	mThreads = []
	file_count = 0
	for i in fileSet:
		try:
			mfile_name = '{0}/{1}'.format(rootDir, i)
			# print('Checking in file: {0}'.format(mfile_name))
			uips = {}
			if ti_type == 'ip':
				uips = read_unique_ips_from_file(mfile_name)
			else:
				uips = read_unique_domains_from_file(mfile_name)

			# we have unique IPs from a file in mDict
			if uips and len(uips) > 0:
				pool_sema[3].acquire()
				print('{0} unique IPs in {1}'.format(len(uips), mfile_name))

				mThreads.append(Thread(target=get_ti, args=(uips, mfile_name, args.out, ti_type,)))
				mThreads[-1].start()

			file_count += 1
		except Exception as e:
			print('Exception {0} occurred in for loop in get_my_ti for ti_type {1}'.format(e, ti_type))

	for t in mThreads:
		t.join()


def main():
	mThreads = []
	setup_argparse()

	# get user arguments to set critical variables
	rootDir = args.rootDir
	ready_output_file(args.out)

	fileSet = get_all_file_paths(rootDir)
	print('Total number of files gathered: {0}'.format(len(fileSet)))

	try:
		if args.threat_intel_type == 'all' or args.threat_intel_type == 'ip':
			print('Getting TI for IPs')
			get_my_ti(fileSet, rootDir, 'ip')
		if args.threat_intel_type == 'all' or args.threat_intel_type == 'domain':
			print('Getting TI for Domains')
			get_my_ti(fileSet, rootDir, 'domain')
	except Exception as e:
		print('Exception {0} occurred in main when calling get_my_ti'.format(e))

	# Output information
	output_info()


if __name__ == '__main__':
	mTime = [datetime.now(), 0]
	print('Start Time: {0}'.format(mTime[0]))

	main()

	mTime[1] = datetime.now()
	print('End Time: {0}'.format(mTime[1]))
	print('Main Start Time: {0}'.format(mTime[0]))
	print('Main End Time: {0}'.format(mTime[1]))
	print('Main Time Diff: {0}'.format(mTime[1] - mTime[0]))