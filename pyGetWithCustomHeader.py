"""
pyGetWithCustomHeader

Per each host in the host list, and each header in the header list, send two consecutive GET requests. 
The first request contains the specific header with crafted value, and the second does not. 
If the crafted value appears in the second request, it is *immediately* vulnerable to the cache poisoning attack. 
If the crafted value appears in the first but not the second request, it is *potentially* vulnerable: it reflects the header value but the response is not cached, however it may be cached in the future. 
If the crafted value appears in the second but not the first request, it is *discrepancy*. This is a bit wired case but does exist.
 

usage:

python3 pyGetWithCustomHeader host_list start_line_number end_line_number header_list start_line_num end_line_num

Mingkui Wei 
Computer Science
Sam Houston State University
https://www.shsu.edu/mxw032/
Feb 2020

"""


import concurrent.futures
import requests
import time
import sys


def send_request(urlRaw, header, buster):
	[index, domain] = urlRaw.split(',')
	try:		
		
		#compose the url, start with HTTP but many will be redirected to HTTPS
		url = 'http://' + domain + '/?cdnbuster='  + buster		
		
		#composing 2 requests
		r1 = requests.get(url, timeout = 5, headers = {header:'cdnpos' + header.replace('-', '') + 'cdnpos<>'}) 
		r2 = requests.get(url, timeout = 5) 
		
		sys.stdout.write(str(index) + '(r1:' + str(r1.status_code) + ',r2:' + str(r1.status_code) + ') ' + header + '\n')
		sys.stdout.flush()
			
		risk1 = 'none'
		if 'cdnpos' in r1.text:
			if 'cdnpos<>' in r1.text:
				risk1 = 'high'
			elif '/cdnpos' in r1.text:
				risk1 = 'medium'
			else:
				risk1 = 'low'

		if risk1 != 'none':		
			#find out the header, and write the response to file named with header name
			body1 = r1.text.split('cdnpos')[1]
			if body1.lower() == header.replace('-', '').lower(): 					
				print('\nPotential === {:<40} {:<20} {:<5} ===\n'.format(domain, header, risk1))
				# write simple information into the summary file
				with open('./summary_potential.csv', 'a') as file:
					file.write(domain + ',' + header + ',' + risk1 + '\n')
					
		risk2 = 'none'
		if 'cdnpos' in r2.text:
			if 'cdnpos<>' in r2.text:
				risk2 = 'high'
			elif '/cdnpos' in r2.text:
				risk2 = 'medium'
			else:
				risk2 = 'low'
			
		if risk2 != 'none':		
			#find out the header, and write the response to file named with header name
			body2 = r2.text.split('cdnpos')[1]
			if body2.lower() == header.replace('-', '').lower(): 					
				print('\nImmediate: === {:<40} {:<20} {:<5} ===\n'.format(domain, header, risk2))

				# write simple information into the summary file
				with open('./summary_immediate.csv', 'a') as file:
					file.write(domain + ',' + header + ',' + risk2 + '\n')
					
		if risk1 == 'none' and risk2 != 'none':
			with open('./summary_discrepancy.csv', 'a') as file:
				file.write(domain + ',' + header + ',' + risk1 + ',' + risk2 + '\n')
	

					
	except requests.exceptions.RequestException as e:
		pass
		
		
		

CONNECTIONS = 20


print('Begin loading url and header files...')

urls = open(sys.argv[1]).read().splitlines()[int(sys.argv[2]) : int(sys.argv[3])]

headers = open(sys.argv[4]).read().splitlines()

if len(sys.argv) > 5:
	headers = headers[int(sys.argv[5]) : int(sys.argv[6])]


for header in headers:
	print('\n=====================\n' + header + '\n===\n')
	# use current time as a cache buster
	buster = str(int(time.time()))
	with concurrent.futures.ThreadPoolExecutor(max_workers = CONNECTIONS) as executor:
		args = ((url, header, buster) for url in urls)
		executor.map(lambda p: send_request(*p), args) 
		executor.shutdown(wait = False)