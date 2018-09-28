import sys
from datetime import datetime
import os
import time
import argparse
import requests
import apache_log_parser
import re
from elasticsearch import Elasticsearch
import resource
from pprint import pprint
from datetime import datetime
from multiprocessing.pool import ThreadPool


# Global Vars
# first output file is the log file for this script
# second output file is the actual output file for this script
# mSemaphores = [BoundedSemaphore(value=1)]
args = ''
pool = [ThreadPool(processes=5)]
#############


def setup_argparse():
	global args
	argparse_setup_completed_gracefully = False
	parser = argparse.ArgumentParser(
		description='Before running this script, ensure that you have ran the instructions mentioned in Readme.md and have the IP and port for elasticsearch. \
		This script requires the output CSV file from ip-ti.py script and the related log entries directory that is generated alongwith the CSV file. \
		Optionally Requires path to output file that\'ll contain the logs for this script.\nImportant URLs: \nTo view Kibana: \'45.76.217.146:56065\'\nTo send logs to Elasticsearch: \'45.76.217.146:45654\'\n\n', 
		epilog="""All's well that ends well.""",
		usage="""Example:
		1. python3 {0} -ex ti-index-2018-08-29-01 -ei 45.76.217.146 -ep 45654 -id output-1531851538 -if output-1531851538/ti-output-csv-1531851538.csv'""".format(str(__file__)))
	parser.add_argument('--in_file', '-if', '-IF', '-IN_FILE', required=True,
						help='path/to/name/of/input/file that is actually the output file from ip-ti.py script (ti-output-csv-<XXXXXXXX>.csv)')
	parser.add_argument('--in_dir', '-id', required=True,
						help='path/to/name/of/directory that is actually the output logs directory files from ip-ti.py script (outpput-<XXXXXXXX>)')
	parser.add_argument('--api_token_testing', '-atl', required=False, default='API_TOKEN_TESTING',
						help='Environment variable name for Testing API Token. Do not use in Production. Only for testing purposes')
	parser.add_argument('--es_ip', '-ei', required=True,
						help='IP or hostname of the server hosting Elasticsearch')
	parser.add_argument('--es_port', '-ep', required=False, type=int, default=9200,
						help='Port used by Elasticsearch. Default is 9200')
	parser.add_argument('--es_index', '-ex', required=True, default='test-index',
						help='Index to throw logs to. Default is test-index')
	parser.add_argument('--thread_count', '-t', required=False, default=10, type=int,
						help='Threads count that\'ll simultaneously send data to log receiver')
	parser.add_argument('--replace_with_comma', '-rwc', default='`', required=False,
						help='(Optional) Replace this value in a csv cell with comma')
	parser.add_argument('--split_individual_records_on', '-siro', default='---', required=False,
						help='(Optional) Break over this value in a TI csv cell')
	parser.add_argument('--testing', '-tg', default=False, type=bool, required=False,
						help='(Optional) If testing or not')
	args = parser.parse_args()

	try:
		pool[0] = ThreadPool(processes=args.thread_count)
		if args.testing:
			args.api_token_testing = ''
		# else: args.api_token_testing = os.environ[args.api_token_testing]
	except Exception as e:
		print('Please enter the environment variable name that holds the Testing API Token in --api_token_testing')
		sys.exit()

	argparse_setup_completed_gracefully = True
	print('Argparse setup complete')
	return argparse_setup_completed_gracefully


def send_dict_for_testing(mDict, api_token_testing):
	ret = False

	if args.testing:
		print('Testing - Sending log "{0}" for testing'.format(mDict))
		ret = True

	# else: 
	# 	if (mDict and len(mDict) > 0):
	# 		try:
	# 			response = requests.post('http://logs-01.loggly.com/inputs/{0}/tag/custom-ti/'.format(api_token_testing), 
	# 					headers={
	# 					'content-type': 'application/x-www-form-urlencoded',
	# 					}, 
	# 					data=mDict
	# 				)
	# 			print('Response: {0}'.format(response))
	# 			if response and '200' in str(response):
	# 				print('\n\n\nSuccessfully sent {0} to loggly\n\n\n'.format(mDict))
	# 				ret = True
	# 		except Exception as e:
	# 			print('Exception {0} occurred in send_dict_for_testing'.format(e))
	return ret


def send_doc_to_elasticsearch(doc, es, index_name):
	ret = "Doc Sent"
	try:
		doc['utc_time_at_execution'] = datetime.utcnow().isoformat()
		res = ''
		if not args.testing:
			res = es.index(index=index_name, doc_type='ti_doc', body=doc, refresh=True)
			print('\n\nres: {0}\n\n'.format(res))
		print('\n\nPushed document: "{0}" to Elasticsearch index: "{1}"\n\n'.format(doc, index_name))

	except Exception as e:
		print('\n\nException "{0}" occurred in send_doc_to_elasticsearch while sending doc "{1}"\n\n'.format(e, doc))
		# input()
		ret = "Doc not sent"
		with open('act-out.txt', 'a') as o: 
			o.write('\n\nUnable to send to Elasticsearch because exception {1}\n{0}\n\n'.format(doc, e))
	return ret


def get_csv_header(inFileLinesList):
	line_arr = []
	for idx, line in enumerate(inFileLinesList):
		if idx == 0:
			line = line.rstrip('\n')
			line_arr = line.split(',')
			break
	# print('Returning header "{0}"'.format(line_arr))
	return line_arr


def get_csv_lines_except_header_in_a_dict(line, headerList):
	mDict = {'ti_results': {}}
	line = line.rstrip('\n')
	line_arr = line.split(',')
	for idx2, i in enumerate(line_arr):
		# if idx2 > 0:
		header = headerList[idx2]
		lh = header.lower()
		if '_ti' in lh:
			# count = int(len(str(str(i).replace(args.replace_with_comma, ',')).split(args.split_individual_records_on)))
			# split all --- separated pulse fields into an array
			ti_arr = str(i).replace(args.replace_with_comma, ',').split(' ' + args.split_individual_records_on + ' ')
			if 'otx' in lh:
				# mDict['ti_results_otx'].update({'otx': ti_arr})
				mDict['ti_results_otx'] = ti_arr
			elif 'cymon' in lh:
				# mDict['ti_results_cymon'].update({'cymon': ti_arr})
				mDict['ti_results_cymon'] = ti_arr
			elif 'c1fapp' in lh:
				# mDict['ti_results_c1fapp'].update({'c1fapp': ti_arr})
				mDict['ti_results_c1fapp'] = ti_arr
			elif 'custom' in lh:
				# mDict['ti_results_custom'].update({'custom': ti_arr})
				mDict['ti_results_custom'] = ti_arr
			else:
				# mDict['count'] = count
				pass
			continue

		# for handling numeric values, there header must contain the word 'count'
		if (not 'country' in lh) and '_count' in lh:
			try:
				mDict[header] = int(i)
				continue
			except Exception as e:
				print('Exception "{0}" occurred when converting string "{1}" to int'.format(e, i))

		# if header is filename, skip, since we are already catering for the file name via the raw log file
		if 'filename' in lh: continue

		# for everything else, simply write them as it is
		mDict[header] = str(i).replace(args.replace_with_comma, ',')

	return mDict


def get_files(item, rootDir):
	'''
	Get path to all files inside the root directory
	'''
	fileSet = set()

	for dir_, _, files in os.walk(rootDir):
		for fileName in files:
			relDir = os.path.relpath(dir_, rootDir)
			relFile = os.path.join(relDir, fileName)
			relFile = relFile.lstrip('./')

			# only get files that have the item name in the filename
			if item in relFile:
				fileSet.add(rootDir + '/' + relFile)

	print('Gathered File Paths: {0}'.format(fileSet))
	return fileSet


def get_raw_log_and_custom_line(line):
	ret = ['', '']
	try:
		# index of : in custom log file
		idx = line.index(':')
		# custom part of raw log is the file name where this log was found
		ret[0] = (line[:idx])
		# omit custom part and get the rest of the raw log file
		ret[1] = (line[idx + 1:])
	except Exception as e:
		print('Exception "{0}" occurred while finding index of : in line "{1}"'.format(e, line))
	
	# print('\n\nRaw Log broken into custom "{0}" and finding "{1}" parts. Actual array is "{2}"\n\n'.format(ret[0], ret[1], ret))
	# input()

	return ret


	# regexes = [r"^(\[[^\]]+\]) (\[[^\]]+\]) (\[[^\]]+\]) (\[[^\]]+\]) (.*)$"]
def get_time(item, parsed_dict):
	try:
		item = item.lstrip('[').rstrip(']').split(' ')
		item[-2] = item[-2][:item[-2].find('.')]
		item = ' '.join(item)
		# parsed_dict['time_received_utc_isoformat'] = datetime.strptime(item, '%c').strftime('%Y-%m-%dT%H:%M:%SZ+00:00')
		parsed_dict['time_received_utc_isoformat'] = datetime.strptime(item, '%c').strftime('%Y-%m-%dT%H:%M:%SZ')
	except Exception as e:
		pass
	return parsed_dict


def get_severity(item, parsed_dict):
	try:
		item = item.lstrip('[').rstrip(']')
		print(item)
		parsed_dict['severity'] = item
	except Exception as e:
		pass
	return parsed_dict


def get_pid(item, parsed_dict):
	try:
		item = item.lstrip('[').rstrip(']').split(' ')
		parsed_dict['pid'] = item[1]
	except Exception as e:
		pass
	return parsed_dict


def get_ip_address(item, parsed_dict):
	try:
		item = item.lstrip('[').rstrip(']').split(' ')
		parsed_dict['client_ip'] = item[1].split(':')[0]
		parsed_dict['client_port'] = item[1].split(':')[1]
	except Exception as e:
		pass
	return parsed_dict


def get_remaining_error_log(item, parsed_dict):
	try:
		parsed_dict['message'] = item
		parsed_dict['uri'] = item.split(': ')[1] if '/' in item.split(': ')[1] else ''
		parsed_dict['request_url_path'] = item.split(': ')[1] if '/' in item.split(': ')[1] else ''
	except Exception as e:
		pass
	return parsed_dict


def parse_on_your_own_error_log(log):
	ret = None
	regexes = [r"^(\[[^\]]+\]) (\[[^\]]+\]) (\[[^\]]+\]) (\[[^\]]+\]) (.*)$"]
	# '[Sat May 05 02:18:59.763988 2018] [core:error] [pid 17586] [client 80.82.77.33:48328] AH00135: Invalid method in request quit'
	parsed_log = {}
	for regex in regexes:
		try:
			for idx, item in enumerate(re.match(regex, log).groups()):
				print('\n\n In parse_on_your_own_error_log, Parsing \nidx: "{0}"\nitem: "{1}"'.format(idx, item))

				if idx == 0:
					# first index is for time in error log
					parsed_log = get_time(item, parsed_log)
					continue
				elif idx == 1:
					# severity level of the log
					parsed_log = get_severity(item, parsed_log)
					continue
				elif idx == 2:
					# the IP address
					parsed_log = get_pid(item, parsed_log)
					continue
				elif idx == 3:
					# the IP address
					parsed_log = get_ip_address(item, parsed_log)
					continue
				else:
					# the IP address
					parsed_log = get_remaining_error_log(item, parsed_log)
					break

				print(parsed_log)
					
			print('\n\nParsed in parse_on_your_own_error_log: "{0}"\n\n'.format(parsed_log))
		except Exception as e:
			print('\n\nException "{0}" occurred while parsing \nlog "{1}" with \nregex "{2}"\n\n'.format(e, log, regex))

	if parsed_log == {}:
		print('\n\nUnable to parse \nlog "{0}"\n\n'.format(log))
		# break if it's parsed_log
		# if parsed_log: break
	# return None if parsed_log == {} else parsed_log
	if parsed_log and parsed_log != {}:
		ret = parsed_log
	return ret



def parse_apache_log(log):
	# default parser is for APache Access Logs
	parsed = None

	# i the identified file name is apache access log
	# if 'access_log' == str(id_helper[:10]):
	parser_regex = ["%h <<%P>> %t %Dus \"%r\" %>s %b  \"%{Referer}i\" \"%{User-Agent}i\" %l %u", "%h %l %u %t \"%r\" %>s %b", "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"]
	for regex in parser_regex:
		
		try:
			parser = apache_log_parser.make_parser(regex)
			parsed = parser(log)
		except: 
			parsed = None
			pass

		# if parser has something in it
		if parsed: break

	# else:
	# print('\n\nUnidentified file name "{0}" in get_parser\n\n'.format(id_helper))
	print('\n\nParsed Apache Log \n"{0}" to: \n"{1}"\n\n'.format(log, parsed))
	if not parsed:
		parsed = parse_on_your_own_error_log(log)
	
	if not parsed:
		print('Unable to parse: "{0}"'.format(log))
		# input()
		with open('act-out.txt', 'a') as o: o.write('\nUnable to parse log:\n{0}\n\n'.format(log))

	return parsed


def convert_raw_log_to_json(findings):
	json_log = {}
	try:
		file_name = findings[0]
		json_log = parse_apache_log(findings[1])
		# json_log['threat_intelligence'] = { 'log_found_in_file' : file_name }
		json_log['log_found_in_file'] = file_name
	except Exception as e:
		print('\n\nException "{0}" occurred for findings "{1}" in convert_raw_log_to_json\n\n'.format(e, findings))
	
	print('Raw Log to JSON: "{0}"'.format(json_log))
	# input()

	return json_log


def remove_from_list(mList, unwanted):
	# returns a list that only contains the items that are not in the unwanted list
	return [e for e in mList if e not in unwanted]


def get_parsed_json_raw_logs_from_file(file, ti_dict):
	file_findings = []
	with open(file) as reading:
		# read all lines from file
		reading = reading.readlines()
		for line in reading:
			# for each line, remove newline character from the end
			file_findings.append(
				merge_dicts(
					convert_raw_log_to_json(
						get_raw_log_and_custom_line(
							line.rstrip('\n')
						)
					), ti_dict
				)
			)

	print('\n\nFindings from file {0} after merging with ti_dict: \n"{1}"'.format(file, file_findings))
	# input()

	return file_findings


def merge_dicts(dict1, ti_dict):
	try:
		if dict1 and ti_dict:
			if 'threat_intelligence' in dict1:
				dict1['threat_intelligence'].update(ti_dict)
			else:
				dict1['threat_intelligence'] = ti_dict
	except Exception as e:
		print('\n\nException "{0}" occurred while merging dicts\n\n'.format(e))
	return dict1


def append_with_all_raw_logs(ti_dict, raw_logs_dir):
	'''
	Takes as input the output of get_csv_lines_except_header_in_a_dict. Returns a list that contains all raw logs of the item (IP or domain) appended with the output from get_csv_lines_except_header_in_a_dict
	'''
	# [{
	# 'http_raw_log': {},
	# 'ti_json': {}
	# }]
	
	all_appended_raw_logs = []

	# get all files whose name contain this item
	# open each file. Read content line by line. Find custom and actual raw_log
	# if 'item' not in ti_dict:
	# 	print('\n\nPrinting ti_dict_in append_with_all_raw_logs: {0}\n\n')
	# 	# input()
	# 	sys.exit()
	for file in get_files(ti_dict['item'], raw_logs_dir):
		all_appended_raw_logs += get_parsed_json_raw_logs_from_file(file, ti_dict)

	return all_appended_raw_logs


def convert_to_json(in_file, api_token_testing, es_ip, es_port, index_name):
	'''
	Converts each line of CSV into a Threat Intel dictionary, appends it to every raw log for the item and sends it to loggly
	'''
	mJson = {}
	async_result = []
	with open(in_file) as inFile:
		# headerList = get_csv_header(inFile.readlines())
		# headerList = []
		file_lines = inFile.readlines()
		for idx, line in enumerate(file_lines):

			# if it's the first line in file, i.e: the header, skip it, since there is a separate method for retrieving header
			if idx == 0: continue

			list_to_send_to_logmanager = append_with_all_raw_logs(get_csv_lines_except_header_in_a_dict(line, get_csv_header(file_lines)), args.in_dir)

			# Once the list has been prepared. Upload to loggly
			for mDict in list_to_send_to_logmanager:
				if mDict and len(mDict) > 0:
					# tuple of args for send_dict_for_testing
					
					# with open('act-out.txt', 'a') as o: o.write(str(mDict) + '\n\n')

					# print('\n\nSending "" to loggly:\n')
					# pprint(mDict)
					# input()

					# async_result.append(pool[0].apply_async(send_dict_for_testing, (mDict, api_token_testing)))
					async_result.append(pool[0].apply_async(send_doc_to_elasticsearch, (mDict, Elasticsearch(hosts=[{'host': es_ip, 'port': es_port}]), index_name)))

					# time.sleep(2)

		for thread in async_result:
			print('Thread Result: {0}'.format(thread.get()))

	return mJson



def parse_and_send_file_to_logmanager(in_file, api_token_testing, es_ip, es_port, index_name):
	mJson = convert_to_json(in_file, api_token_testing, es_ip, es_port, index_name)


def set_resource_limit_for_open_files():
	resource.setrlimit(resource.RLIMIT_NOFILE, (110000, 110000))


def main():
	setup_argparse()
	set_resource_limit_for_open_files()
	parse_and_send_file_to_logmanager(args.in_file, args.api_token_testing, args.es_ip, args.es_port, args.es_index)
	# print(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
	# print(datetime.utcnow().isoformat())


if __name__ == '__main__':
	mTime = [datetime.now(), 0]
	print('Start Time: {0}'.format(mTime[0]))

	main()

	mTime[1] = datetime.now()
	print('End Time: {0}'.format(mTime[1]))
	print('Start Time: {0}'.format(mTime[0]))
	print('End Time: {0}'.format(mTime[1]))
	print('Time Diff: {0}'.format(mTime[1] - mTime[0]))
else:
	main()