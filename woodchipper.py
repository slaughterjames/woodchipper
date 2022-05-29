#! /usr/bin/env python3
'''
Woodchipper v0.2 - Copyright 2022 James Slaughter,
This file is part of Woodchipper v0.2.

Woodchipper v0.2 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Woodchipper v0.2 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Woodchipper v0.2.  If not, see <http://www.gnu.org/licenses/>. 
'''

#python import
import sys
import os
import datetime
import json
import subprocess
from termcolor import colored

#programmer generated imports
from controller import controller
from fileio import fileio

'''
Usage()
Function: Display the usage parameters when called
'''
def Usage():
    print ('Usage: [required] --dir [optional] --output --debug --help')
    print ('Example: ./woodchipper.py --dir 20220209/gov_emails --output 20220209-gov_emails.txt --debug')
    print ('Required Arguments:')
    print ('--dir - directory to start parsing')
    print ('Optional Arguments:')
    print ('--output - location of the output file')
    print ('--debug - Prints verbose logging to the screen to troubleshoot issues with a recon installation.')
    print ('--help - You\'re looking at it!')
    sys.exit(-1)

'''
ConfRead()
Function: - Reads in the intelscraper.conf config file and assigns some of the important
            variables
'''
def ConfRead():
        
    ret = 0
    intLen = 0
    FConf = fileio()
    data = ''

    try:
        #Conf file hardcoded here
        with open('woodchipper.conf', 'r') as read_file:
            data = json.load(read_file)
    except Exception as e:
        print (colored('[x] Unable to read configuration file.' + str(e), 'red', attrs=['bold']))
        return -1

    
    CON.manifest = data['manifest']
  
    if (CON.debug == True):
        print ('[DEBUG] data: ', data)
        print ('[DEBUG] CON.manifest: ' + str(CON.manifest))
            
    if (CON.debug == True):
       print ('[*] Finished configuration.')
       print ('')

    return 0
            
'''
Parse() - Parses program arguments
'''
def Parse(args):        
    option = ''

    print ('[*] Length Arguments: ' + str(len(args)))

    if (len(args) == 1):
        return -1

    print ('[*] Arguments: ')
    for i in range(len(args)):
        if args[i].startswith('--'):
            option = args[i][2:]
                
            if option == 'help':
                return -1

            if option == 'dir':
                CON.dir = args[i+1]
                print (option + ': ' + CON.dir)

            if option == 'output':
                CON.output = args[i+1]
                print (option + ': ' + CON.output)                              
                
            if option == 'debug':
                CON.debug = True
                print (option + ': ' + str(CON.debug))

    if ((len(CON.dir) < 3)):
        print (colored('[x] dir is a required argument.', 'red', attrs=['bold']))
        print ('')
        return -1

    if ((len(CON.output) < 3)):
        CON.output = 'woodchipper.txt'
        print (colored('[*] --output is set to default...', 'yellow', attrs=['bold']))
        print ('')
                                     
    print ('')   
    
    return 0

'''
ManifestRead()
Function: - Reads in the manifest file that will help prevent duplicate analysis

'''
def ManifestRead():
        
    ret = 0
    intLen = 0
    FConf = fileio()
    data = ''

    try:
        #Read in our manifest
        with open(CON.manifest, 'r') as read_file:
            data = read_file.readlines()
    except Exception as e:
        print (colored('[x] Unable to read manifest file.' + str(e), 'red', attrs=['bold']))
        return -1
    
    CON.manifestdata = data
 
    if (CON.debug == True):
        print ('[DEBUG] data: ', data)
        for line in data:
            print ('SHA256 Hash: ' + line)
            
    print ('[*] Manifest file successfully read!')
    print ('')

    return 0

'''
Execute()
Function: - Does the doing against a string
'''
def Execute():

    summarypath = ''
    fullpath = ''

    #Walk our root dir for more dirs and files 
    #underneath
    for root, dirs, files in os.walk(CON.dir):            
        for file in files:          
            if ((file.endswith('.msg.html')) or (file.endswith('.eml.html'))):
                fullpath = os.path.join(root, file)
                if (CON.debug == True):
                    print ('[DEBUG] Fullpath: ' + fullpath)
                summarypath = fullpath.rsplit("/", 3) [0]
                if (CON.debug == True):
                    print ('[DEBUG] Summarypath: ' + summarypath)
                secondary(summarypath, fullpath, file)
                summarypath = ''
                fullpath = ''
  
    print ('')

    return 0

'''
secondary()
Function: - Secondary ops  
'''
def secondary(summarypath, fullpath, file):

    #Suboptimal number local vars but it works here
    File = ''
    VT_Threat = ''
    Suspicious = ''
    Malicious = ''
    threat = ''
    suspicious = ''
    malicious = ''
    SHA256 = ''
    SizeOfFile = ''
    FileType = ''
    MessageDate = ''
    To = ''
    From = ''
    Subject = ''
    Attachment = ''
    bodytext = ''
    sum_data = ''
    sum_output_data = ''


    File = file.partition('.html')[0].strip()
    print ('File: ' + File)
    bodytext += 'File: ' + File + '\n'

    if (CON.debug == True):
        print ('[DEBUG] Fullpath: ' + fullpath)
        print ('[DEBUG] Summarypath: ' + summarypath)

    try:        
        with open(fullpath, 'r') as read_file:
            data = read_file.readlines()
    except Exception as e:
        print (colored('[x] Unable to read file. ' + str(e), 'red', attrs=['bold']))
        return -1

    read_file.close()

     
    subproc = subprocess.Popen('grep -r \"Number of A/V engines not marking sample as malicious\" ' +  summarypath + '/', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for sum_data in subproc.stdout.readlines():
         sum_output_data += sum_data.decode('utf-8')
         if (CON.debug == True):
             print ('[DEBUG] sum_output_data: ' + sum_output_data)
         sum_output_data = sum_output_data.partition(':')[2].strip()
         if (CON.debug == True):
             print ('[DEBUG] sum_output_data_partition: ' + sum_output_data)
         malicious = sum_output_data.partition(':')[2]
         Malicious = malicious.strip()
         if (CON.debug == True):
             print ('[DEBUG] Malicious: ' + Malicious)

    sum_data = ''
    sum_output_data = ''

    subproc = subprocess.Popen('grep -r \"Number of A/V engines not marking sample as suspicious\" ' +  summarypath + '/', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for sum_data in subproc.stdout.readlines():
         sum_output_data += sum_data.decode('utf-8')
         if (CON.debug == True):
             print ('[DEBUG] sum_output_data: ' + sum_output_data)
         sum_output_data = sum_output_data.partition(':')[2].strip()
         if (CON.debug == True):
             print ('[DEBUG] sum_output_data_partition: ' + sum_output_data)
         suspicious = sum_output_data.partition(':')[2].strip()
         Suspicious = suspicious.strip()
         if (CON.debug == True):
             print ('[DEBUG] Suspicious: ' + Suspicious)

    sum_data = ''
    sum_output_data = ''

    subproc = subprocess.Popen('grep -r \"VirusTotal suggested threat label\" ' +  summarypath + '/', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for sum_data in subproc.stdout.readlines():
         sum_output_data += sum_data.decode('utf-8')
         if (CON.debug == True):
             print ('[DEBUG] sum_output_data: ' + sum_output_data)
         sum_output_data = sum_output_data.partition(':')[2].strip()
         if (CON.debug == True):
             print ('[DEBUG] sum_output_data_partition: ' + sum_output_data)
         threat = sum_output_data.partition(':')[2].strip()
         VT_Threat = threat.strip()
         if (CON.debug == True):
             print ('[DEBUG] VT_Threat: ' + VT_Threat)
         

    if (CON.debug == True):
        print(data)

    for line in data:
        if (CON.debug == True):
            print ('Line: ' + line)

        if (line.find('Size of file') != -1):
            SizeOfFile = line.partition(':')[2].strip()
            print ('SizeOfFile: ' + SizeOfFile)
            bodytext += 'Size Of File: ' + SizeOfFile + '\n'
 
        if (line.find('SHA256') != -1):
            SHA256 = line.partition(':')[2].strip()
            for sha256hash in CON.manifestdata:
                if (SHA256.strip() == sha256hash.strip()):
                    print ('[*] SHA256 exists in the Woodchipper manifest.  Skipping...')
                    bodytext = ''
                    return 0
            print ('SHA256: ' + SHA256)
            bodytext += 'SHA256: ' + SHA256 + '\n'

        if (line.find('File type') != -1):
            FileType = line.split(":", 2)[2].strip()
            print ('File Type: ' + FileType)
            bodytext += 'FileType: ' + FileType + '\n'

        if (line.find('Message Date:') != -1):
            MessageDate = line.partition(':')[2].strip()
            print ('MessageDate: ' + MessageDate)
            bodytext += 'Message Date: ' + MessageDate + '\n'

        if (line.find('To:') != -1):
            To = line.partition(':')[2].strip()
            print ('To: ' + To)
            bodytext += 'Message To: ' + To + '\n'

        if (line.find('From:') != -1):
            From = line.partition(':')[2].strip()
            print ('From: ' + str(From))
            bodytext += 'Message From: ' + From + '\n'

        if (line.find('Subject:') != -1):
            Subject = line.partition(':')[2].strip()
            print ('Subject: ' + Subject)
            bodytext += 'Message Subject: ' + Subject + '\n'

        if (line.find('Attachment extracted:') != -1):
            Attachment = line.partition(':')[2].strip()
            print ('Attachment: ' + Attachment)
            bodytext += 'Attachment: ' + Attachment + '\n'

        if (line.find('total attachments failed to be extracted') != -1):
            Attachment = line.partition('>')[2].strip()            
            print ('Attachment: ' + Attachment)
            bodytext += 'Attachment: ' + Attachment + '\n'

        if (line.find('No attachments found to extract') != -1):
           Attachment = 'No attachments found to extract!'
           print ('Attachment: ' + Attachment)
           bodytext += 'Attachment: ' + Attachment + '\n'

    print ('VirusTotal suggested threat label: ' + VT_Threat)
    bodytext += 'VirusTotal suggested threat label: ' + VT_Threat + '\n'

    print ('VirusTotal Suspicious: ' + Suspicious)
    bodytext += 'VirusTotal Suspicious: ' + Suspicious + '\n'

    print ('VirusTotal Malicious: ' + Suspicious)
    bodytext += 'VirusTotal Malicious: ' + Malicious + '\n'

    print ('*' * 100 + '\n\r')
    bodytext += '*' * 100 + '\n\r'

    if (CON.debug == True):
        print ('[DEBUG] bodytext: ' + bodytext)

    FLOG.WriteLogFile(CON.output, bodytext)
    MLOG.WriteLogFile(CON.manifest, SHA256 +'\n')   
    bodytext = ''


    return 0


'''
Terminate()
Function: - Attempts to exit the program cleanly when called  
'''
     
def Terminate(exitcode):
    sys.exit(exitcode)

'''
This is the mainline section of the program and makes calls to the 
various other sections of the code
'''

if __name__ == '__main__':
    
    ret = 0

    #Stores our args
    CON = controller()
                   
    #Parses our args
    ret = Parse(sys.argv)

    #Something bad happened
    if (ret == -1):
        Usage()
        Terminate(ret)

    #Reads our conf
    ret = ConfRead()        

    if (ret == -1):       
        print (colored('[x] Terminated reading the configuration file... ' + str(e), 'red', attrs=['bold']))
        Terminate(ret)

    #Creates our log file
    FLOG = fileio()

    #Creates our manifest file
    MLOG = fileio()

    #Something bad happened
    if (ret == -1):
        Usage()
        Terminate(ret)

    #Reads our manifest
    ret = ManifestRead()        

    if (ret == -1):
        print (colored('[x] Terminated reading the manifest file... ' + str(e), 'red', attrs=['bold']))
        Terminate(ret)

    #Do the doing
    startdatetime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
    FLOG.WriteLogFile(CON.output, '*' * 100 + '\n')
    FLOG.WriteLogFile(CON.output, '****Woodchipper v0.2****\n')
    FLOG.WriteLogFile(CON.output, '****Starting Analysis On: ' + startdatetime + '****\n')
    FLOG.WriteLogFile(CON.output, '****Directory: ' + CON.dir + '****\n')
    FLOG.WriteLogFile(CON.output, '*' * 100 + '\n')
    Execute()

    print ('')
    print ('[*] Program Complete!')

    Terminate(0)
'''
END OF LINE
'''

