#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import division
import getpass
import requests
from jira import JIRA
import re
import base64
import hashlib
import hmac
import uuid
import datetime
import urllib2
import ssl
import time
import json
from threading import _BoundedSemaphore as BoundedSemaphore, Timer
from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.options import Options
from pyvirtualdisplay import Display
from bs4 import BeautifulSoup
import email
import os


#pip install selenium, requests, jira, bs4, pyvirtualdisplay
#need to install chrome web driver


#For testing purposes
enable_Jira_Actions = True

#VT's acceptable level of positive hits on a URL
#Using 2 because it gets all angry about google
ACCEPTABLE_CLEAN_VALUE = 1

regexString = r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))"""
#hyperlinkString = r"""<a +href="(.+?)" *>"""
NumberOfMaxResults = 200

#This is our Rate Limiting Class - we use it to make sure that we don't send too many requests to virus total.  There is additional
#Handling in the VTCheck() method that looks for 204s (which mean you need to wait to send more requests) so the program won't crash
class RatedSemaphore(BoundedSemaphore):
	#Limit to 1 request per `period / value` seconds (over long run).
	def __init__(self, value=1, period=1):
		BoundedSemaphore.__init__(self, value)
		t = Timer(period, self._add_token_loop,
				  kwargs=dict(time_delta=float(period) / value))
		t.daemon = True
		t.start()

	def _add_token_loop(self, time_delta):
		#Add token every time_delta seconds.
		while True:
			try:
				BoundedSemaphore.release(self)
			except ValueError: # ignore if already max possible value
				pass
			time.sleep(time_delta) # ignore EINTR

	def release(self):
		pass # do nothing (only time-based release() is allowed)

rate_limit = RatedSemaphore(4, 61)


#Here we utilize a regular expression string in an attempt to find all possible URL combinations in any string
def get_all_URLS_in_text(text):
	urlList = list()
	hyperlinkList = list()
	reconstructedHyperlinkList = list()
	urlList = re.findall(regexString, text)
	# hyperlinkList = re.findall(hyperlinkString, text)
	hyperlinkList = parseHTMLforLinks(text)
	if hyperlinkList:
		print 'Found ' + str(len(hyperlinkList)) + ' Hyperlinks'
		#print '\nHYPERLINKS FOUND:\n' + str(hyperlinkList)
	try:
		#print hyperlinkList[0]
		for link in hyperlinkList:
			if link.startswith('3D'):
				link = link[3:-1]
			elif link.startswith('"'):
				link = link[1:-1]
			#print link
			reconstructedHyperlinkList.append(str(link))
			#print 'reconstructed hyperlinks: ' + reconstructedHyperlinkList
	except:
		pass
	#print urlList
	urlList.extend(reconstructedHyperlinkList)
	#print urlList
	return urlList

def parseHTMLforLinks(text):
	soup = BeautifulSoup(text, 'html.parser')
	hyperlinkList = list()
	for link in soup.find_all('a'):
		hyperlinkList.append(link.get('href'))
	return hyperlinkList




#Our Virus Total API check method, we check to see if there is already a report for the URL inserted - and since 'scan' is set to '1'
#We will request the URL to be scanned if it hasn't been already.  If we get a 204 response or the report hasn't been generated yet 
#We will make another call to this function in our main method after waiting 15 seconds.  
def VTCheck(URL):
	malwareCount = 0
	totalCount = 0
	headers = {
	"Accept-Encoding": "gzip, deflate","User-Agent" : "gzip,  My Python requests library example client or username"}
	params = {'apikey': VTAPIToken, 'resource':URL, 'scan':'1'}
	#response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers = headers)
	with rate_limit, requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers = headers) as response:
		if response.status_code == 204:
			return['recheck',0,0]
		try:
			json_response = response.json()
		except: 
			return ['Unable to find URL report',0,0]
	waitCheck = json_response['verbose_msg']
	if waitCheck == 'Scan request successfully queued, come back later for the report':
		return['recheck',0,0]
	#if VT screws up (main module picks up on 0 total checks from VT)
	try:
		malwareCount = json_response['positives']
		totalCount = json_response['total']
		scanID = json_response['scan_id']
		#print malwareCount, totalCount, scanID
	except:
		return ['Unable to find URL report',0,0]


	if totalCount == 0:
		return ['Unable to find URL report',0,0]
	if malwareCount <= ACCEPTABLE_CLEAN_VALUE:
		#print 'URL: ' + URL + ' is CLEAN!\n'
		return ['CLEAN',malwareCount,totalCount]
	else:
		#print 'URL: ' + URL + ' is Possible Malware!\n'
		return ['Possible Malware', malwareCount, totalCount]


def initializeChromeWebDriver():
	options = Options()
	options.add_argument('--headless')
	options.add_argument('--no-sandbox')
	#options.add_argument('--disable-dev-shm-usage')
	driver = webdriver.Chrome(options=options, executable_path=r'/usr/bin/chromedriver')
	driver.get("http://google.com/")
	print ("Headless Chrome Initialized")
	return driver

# options = webdriver.ChromeOptions()
# options.binary_location = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
# chrome_driver_binary = "/usr/local/bin/chromedriver"
# driver = webdriver.Chrome(chrome_driver_binary, chrome_options=options)

def JiraGetTickets():
	jql = 'labels = "~Potential_Malware_Phishing~" AND status != "RESOLVED"'
	return jira.search_issues(jql, maxResults = NumberOfMaxResults)


#######################################################MAIN METHOD####################################################################



if __name__ == "__main__":

	if enable_Jira_Actions:
		print 'JIRA ACTIONS WILL TAKE PLACE ON TARGETTED ISSUES'
	else:
		print 'JIRA ACTIONS WILL NOT TAKE PLACE - CHANGE VARIABLE enable_Jira_Actions TO TRUE TO ENABLE'

	JiraUserName = raw_input("user?")
	JiraPassword = getpass.getpass("password?")

	while True:
		try:
			ticketResolveCount = 0
			start_time = time.time()
			display = Display(visible=0, size=(800, 600))
			display.start()
			jira = JIRA(basic_auth=(JiraUserName, JiraPassword), options = {'server': 'https://jira.company.com'})
			JiraTicketObjects = JiraGetTickets()
			numberOfTicketsToResolve = len(JiraTicketObjects)
			print 'Number of tickets to resolve: ' + str(numberOfTicketsToResolve)
			ticketCount = 0



			driver = initializeChromeWebDriver()

			for ticket in JiraTicketObjects:
				print("---Current Execution Time: %s Seconds ---" % round(time.time() - start_time, 2))
				specialMimecastMessageFound = False
				URL_FOUND = False
				URL_BLOCKED = False
				jiraBeforeMessage = ''
				jiraMessage = ''
				jiraAfterMessage = ''
				jiraStartMessage = ''
				dirtyMark = 0
				#THIS SEEMS REDUNDANT BUT ISSUES NEED TO BE LOOKED UP THIS WAY OR THEY WILL NOT HAVE ATTACHMENTS IN THEIR FIELDS
				issue = jira.issue(ticket.key)

				#TODO REMOVE
				#issue = jira.issue('SD-79299', expand="attachment")

				ticketCount += 1
				print '(' + str(ticketCount) + '/' + str(numberOfTicketsToResolve) + ')[' + str(ticketResolveCount) + ']resolved\nNow working on... ' + issue.key
				jiraBeforeMessage = "This is an automated message.\n\n"
				jiraStartMessage += "==========VIRUS TOTAL WAS ABLE TO FIND THE FOLLOWING URLs==========\n\n"
				jiraEndMessage = ''
				URL_List = list()
				Email_list = list()
				textField = issue.fields.description
				textField = textField.replace('|',' ')

				URL_List.extend(get_all_URLS_in_text(textField))

				comments = jira.comments(issue.key)
				skipIssue = False
				for comment in comments:
					#print comment.author.name
					if comment.author.name == 'ltang':
						skipIssue = True
						break
				if skipIssue == True:
					print '\nalready commented for this issue - skipping\n'
					numberOfTicketsToResolve -= 1
					ticketCount -= 1
					continue


				try:
					attachments = issue.fields.attachment
					for attachment in attachments:
						print("Name: '{filename}', size: {size}".format(filename=attachment.filename, size=attachment.size))

						#print("\n\nContent: '{}'\n\n".format(attachment.get()))
						if attachment.filename.endswith('.eml'):
							print 'found .eml file!'

							#print '\n\n\n ' + str(attachment) + ' \n\n\n'

							#print '\n\n\n ' + str(attachment.raw) + ' \n\n\n'

							#print '\n\nattachment:\n\n' + str(type(attachment))
							data = attachment.get()
							#with open('/tmp/Issue1_CA_JCD_6585.png', 'wb') as f:
							#	f.write(image)
							#print '\n\ndata:\n\n' + str(type(data))
							#TODO DELETE
							#print 'PREPARSE\n\n' + data
							data = data.replace('=\r\n', '')
							#print 'IMPORTANT PARSE\n\n' + data
							data = data.replace('\n', '').replace('\r', '')
							#print 'AFTER PARSE\n\n' + data
							attachmentURLS = get_all_URLS_in_text(data)
							URL_List.extend(attachmentURLS)
				except:
					print 'no attachments found'
				#removes duplicates
				URL_List = list(set(URL_List))
				tempList = list()
				#print '\nPotential URLs found:\n\n' + str(URL_List) + '\n\n'

				for URL in URL_List:
					if not URL.lower().endswith('outlook.com') and not URL.lower().startswith('http://www.w3.org') and not URL.lower().endswith('.png') and not URL.lower().endswith('.jpg') and not URL.lower().endswith('.gif'):


						#OUR CHROME DRIVER IS SO GOOD AND SO MUCH BETTER THAN URLLIB2 THAT WERE NOT GOING TO USE IT
						"""
						try:
							#get redirect URL
							context = ssl._create_unverified_context()
							req = urllib2.Request(URL)
							res = urllib2.urlopen(req, context = context)
							finalurl = res.geturl()
							print '	URL after redirect\n		' + finalurl
							tempList.append(finalurl)
						except Exception as e: print('failed urllib2')
						try:
							#try with requests module
							r = requests.get(URL)
							print '	requests redirect option:\n		' + r.url
							tempList.append(r.url)
							print '	requests history option:\n		' + r.history
						except Exception as e: print('failed requests')
						"""
						try:
							#try with chrome driver module
							driver.get(URL)
							print 'URL Before redirect: ' + URL
							print 'Driver redirect option: ' + driver.current_url
							try:
								req = requests.head(driver.current_url, verify=False)
								print 'Code: ' + str(req.status_code)
							except Exception as e:
								#print e
								pass
							else:
								if not (str(req.status_code) == 404 or str(req.status_code) == 301):
									print 'Adding:: ' + driver.current_url
									jiraEndMessage += 'Dead Link: ' + driver.current_url + '\n'
									tempList.append(driver.current_url)
						except Exception as e: print('Invalid URL: ' + URL)



				URL_List = tempList
				URL_List = list(set(URL_List))
				print '\nFinal URL list has been compiled:'
				#print str(URL_List) + '\n\n'
				print 'Found ' + str(len(URL_List)) + ' potential URLs\n'



				for URL in URL_List:
					URL_FOUND = True
					VTreport = ["",0,0]
					AlreadyBlocked = False
					#WE FOUND A BLOCKED URL THROUGH MIMECAST!  HUZZAH!!!
					if URL.startswith('MIMECAST BLOCK URL'):
						URL_BLOCKED = True
						jiraBeforeMessage += 'This link has already been blocked by Mimecast:\n' + URL + '\n\n'
						continue
					#WE FOUND A BLOCKED URL THROUGH UMBRELLA?!  HUZZAH!!! (This requires further testing)
					elif URL.startswith('OTHER BLOCK URL'):
						URL_BLOCKED = True
						jiraBeforeMessage += 'This link has already been blocked by OTHER.\n' + URL + '\n\n'
						continue
					elif URL.startswith('ANOTHER OTHER BLOCK URL'):
						URL_BLOCKED = True
						jiraBeforeMessage += 'This link has already been blocked by ANOTHER OTHER.\n' + URL + '\n\n'
						continue
					#I DON'T THINK WE WILL NEED THIS - CHROME DRIVER AUTO RESOLVES TO EITHER BLOCKED OR UNBLOCKED URL
					elif URL.startswith('MIMECAST URL'):
						print URL + "\nFound dead mimecast URL\n"
						jiraEndMessage += ' Dead mimecast link:\n' + URL + '\n\n'
						URL_BLOCKED = True
						#dirtyMark += 1
						# durl = mimecastCheckURL(URL)
						# if durl is blocked:
							# jiraMessage += 'URL: ' + durl + '(' + URL + ')' + ' has been blocked by mimecast.\n'
						# else:
							#pass
					#skip google
					elif URL == 'https://www.google.com/':
						continue
					elif URL.startswith('MIMECAST RELEASE URL'):
						specialMimecastMessageFound = True
					#SKIP OUT ON THIS CRAP THAT WE DON'T NEED TO CHECK
					elif URL == 'picutreurl' or URL == 'pictureurl':
						continue
					else:
						print 'SCANNING URL: ' + URL
						#We are going to continually look for the URL report from VT every 15 seconds until it gives it to us
						#If the report doesn't exist yet we automatically ask for VT to make a scan report of the URL
						expireCount = 0
						while True:
							try:
								VTreport = VTCheck(URL)
							except:
								print 'failed VTCheck for ' + URL
								jiraEndMessage += 'This URL should be manuallly checked, virustotal could not find anything:\n' + URL + '\n'
								break
							if not VTreport[0] == 'recheck':
								break
							time.sleep(15)
							expireCount += 1
							if expireCount > 5:
								print 'failed VTCheck for ' + URL
								jiraEndMessage += 'This URL should be manuallly checked, virustotal could not find anything:\n' + URL + '\n'
								break
						#print VTreport
						if VTreport[2] == 0: #total checks is zero somehow
							jiraEndMessage += 'This URL should be manuallly checked, virustotal could not find anything:\n' + URL + '\n'
							dirtyMark += 1
						else:
							VTmessage = 'Virus Total Check Results:\n'+ URL +'\n' + str(VTreport[0]) + '\n' + str(VTreport[1]) + ' out of ' + str(VTreport[2]) + ' flagged as malware\n\n'
							print VTmessage
							jiraMessage += VTmessage
					#We mark the issue with a dirtyMark for everytime VT finds a malicious link
					if VTreport[0] == 'Possible Malware':
						dirtyMark += 1

				jiraMessage += "\n=====VIRUS TOTAL WAS NOT ABLE TO FIND ANYTHING FOR THE URLs BELOW=====\n\n"
				jiraMessage = jiraBeforeMessage + jiraStartMessage + jiraMessage + jiraEndMessage



				if dirtyMark == 0 and URL_FOUND:
					#ASSIGN ISSUE TO WHOEVER RAN THE SCRIPT and RESOLVE THE TICKET
					#HAD TO EXCHANGE THIS - SOME TICKETS ARE BEING CLOSED B/C VT DID NOT PICK UP ON PHISH SITE
					#if enable_Jira_Actions
					if enable_Jira_Actions and (URL_BLOCKED or specialMimecastMessageFound):
						print 'completely clear - closing ticket'
						jira.assign_issue(issue, JiraUserName)
						#sleep to make sure the assign change goes through and we can find the resolve issue id
						time.sleep(5)
						transitions = jira.transitions(issue)
						#print [(t['id'], t['name']) for t in transitions]
						for t in transitions:
							if t['name'] == 'Resolve Issue':
								id = t['id']
								#print id
								continue
						try:
							jira.transition_issue(issue, id)
						except:
							time.sleep(1)
							try:
								jira.transition_issue(issue, id)
							except:
								print 'ERROR JIRA WAS UNABLE TO FINISH RESOLVING: ' + issue.key
								jira.add_comment(issue = issue.key, body = 'automation was unable to resolve this issue for unknown reasons', is_internal = True)

					jiraMessage += 'This ticket has been parsed as clean and can be resolved - recommended manually checking links for phishing attempts if left unresolved'



					#INTERNAL COMMENT and INCREMENT RESOLVE COUNT
					print '\n\n----------BEGIN INTERNAL JIRA MESSAGE----------\n\n' + jiraMessage + '\n\n----------END INTERNAL JIRA MESSAGE----------\n\n'
					#HAD TO EXCHANGE THIS - SOME TICKETS ARE BEING CLOSED B/C VT DID NOT PICK UP ON PHISH SITE
					#if enable_Jira_Actions:
					if enable_Jira_Actions and (URL_BLOCKED or specialMimecastMessageFound):
						jira.add_comment(issue = issue.key, body = jiraMessage, is_internal = True)
						ticketResolveCount += 1
						#print 'Resolved ' + str(ticketResolveCount) + ' tickets so far...'
						print 'du-du-du ... ANOTHER TICKET BITES THE DUST!!!'


					#EXTERNAL COMMENT for A BLOCKED URL HAS BEEN FOUND
					if URL_BLOCKED:
						externalComment = 'This is an automated message.\n\nThank you reporting this. Our security systems identified the link or attachment as malicious and has blocked it. Please go ahead and delete the email.\n\nThank you for helping keep Company secure.'
						print '\n\n----------BEGIN JIRA MESSAGE----------\n\n' + externalComment + '\n\n----------END JIRA MESSAGE----------\n\n'
						if enable_Jira_Actions:
							jira.add_comment(issue = issue.key, body = externalComment)


					#EXTERNAL COMMENT for NO BLOCKED URLs FOUND and NOTHING BAD FOUND BY VIRUS TOTAL
					#else:
					#HAD TO EXCHANGE THIS - SOME TICKETS ARE BEING CLOSED B/C VT DID NOT PICK UP ON PHISH SITE
					if specialMimecastMessageFound == True:
						if specialMimecastMessageFound == True:
							externalComment = 'This is an automated message.\n\nThis is a legitimate system generated email notification from Company’s email security system called Mimecast. This system detects and protects you against harmful emails. This system also detects emails that are not necessarily malicious but may be unwanted ‘spam’.\nMimecast will send daily digests three times throughout the day with information about emails that it suspects are unwanted ‘spam’ for your review.  Communications from Mimecast will come from a Postmaster email address and allow you to see a list of emails that you can choose to release, block, or permit.\n•	Release = releases the message to come into your inbox\n•	Block = adds the sender to your personal blocked senders list and blocks the message and future messages from this sender to your inbox\n•	Permit = adds the sender to your personal allow list and releases the message and future messages from this sender to your inbox\n'
						else:
							externalComment = 'This is an automated message.\n\nThe email you reported does not appear to have any malicious links or attachments. You should first check to see if this is a legitimate email as all links have been cleared by the security team.\n\nOtherwise this may either be spam or junk email. Due to this there is limited activities that we could do for these but you can block the sender on your end if you like. Open up the email and in the upper left click "Junk" then click on "Block Sender".'
						print '\n\n----------BEGIN JIRA MESSAGE----------\n\n' + externalComment + '\n\n----------END JIRA MESSAGE----------\n\n'
						if enable_Jira_Actions:
							jira.add_comment(issue = issue.key, body = externalComment)

				#NO URL FOUND internal comment: MANUAL INVESTIGATION MESSAGE
				elif not URL_FOUND:
					print 'No URL\'s found'
					jiraMessage = "No URL's were found automatically, manual investigation is advised."
					print '\n\n----------BEGIN INTERNAL JIRA MESSAGE----------\n\n' + jiraMessage + '\n\n----------END INTERNAL JIRA MESSAGE----------\n\n'
					if enable_Jira_Actions:
						jira.add_comment(issue = issue.key, body = jiraMessage, is_internal = True)

				#BAD URLs FOUND internal comment MANUAL INVESTIGATION MESSAGE
				else:
					print 'This could be dangerous'
					jiraMessage += 'This ticket will require manual interaction before closing'
					print '\n\n----------BEGIN INTERNAL JIRA MESSAGE----------\n\n' + jiraMessage + '\n\n----------END INTERNAL JIRA MESSAGE----------\n\n'
					if enable_Jira_Actions:
						jira.add_comment(issue = issue.key, body = jiraMessage, is_internal = True)

			#close out our long lost and forgotten driver and display
			driver.quit()
			display.stop()
			print 'chrome driver has properly quit'
			print 'resolved ' + str(ticketResolveCount) + ' out of ' + str(numberOfTicketsToResolve) + ' tickets (' + str(ticketResolveCount/numberOfTicketsToResolve) + '%)\n\n'
			print("---Total Execution Time: %s Seconds ---" % round(time.time() - start_time, 2))
		except:
			time.sleep(60)

#for capatcha
#https://jira.company.com/login.jsp


