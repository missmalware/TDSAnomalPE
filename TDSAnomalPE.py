#Author: mm@missmalware.com
#Date: 20 February, 2017
#Version: 1.0


import pefile
import sys

def checks(pe):
	finalPrint = ""
	dataPoints = 0
	
	#identify the TimeDateStamp in the file header
	fileHeaderSt = pe.FILE_HEADER.TimeDateStamp
	epochZero = False
	if fileHeaderSt == 0:
		print("File's compile time is 00 Epoch Time. Likelihood of manipulation: 100%.\nIdentified DataPoints(s):\n")
	else:
		print("Identified Data Points(s):\nFile Header TimeDateStamp: " + str(fileHeaderSt))
	
	#identify the TimeDateStamp in the Debug header, if it exists
	#compare it to the file header TimeDateStamp
	try:
		hdMatch = True
		for x in pe.DIRECTORY_ENTRY_DEBUG:
			debugSt = x.struct.TimeDateStamp
			dataPoints = dataPoints + 1
			if debugSt != fileHeaderSt and debugSt > 0:
				hdMatch = False
			print("Debug Header(s) TimeDateStamp: " + str(debugSt))
		
		if hdMatch is False:
			finalPrint = finalPrint + "The Debug TimeDateStamp(s) and the file header TimeDateStamp do not match.\n"
	except AttributeError:
		pass
	
	#identify the TimeDateStamp in the import table, if it exists
	#compare it to the file header TimeDateStamp
	try:
		hiMatch = True
		for x in pe.DIRECTORY_ENTRY_IMPORT:
			importSt = x.TimeDateStamp()
			dataPoints = dataPoints + 1
			if importSt != fileHeaderSt and importSt > 0:
				hiMatch = False
			print("Import Table TimeDateStamp(s): " + str(importSt))
		
		if hiMatch is False:
			finalPrint = finalPrint + "The import table TimeDateStamp(s) and the file header TimeDateStamp do not match.\n"			
	except AttributeError:
		pass
	
	#identify the TimeDateStamp in the import table, if it exists
	#compare it to the file header TimeDateStamp
	try:
		heMatch = True
		exportSt = pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp
		dataPoints = dataPoints + 1
		if exportSt != fileHeaderSt and exportSt > 0:
			heMatch = False
		print("Export Header TimeDateStamp: " + str(exportSt))
		
		if heMatch is False:
			finalPrint = finalPrint + "The export table TimeDateStamp and the file header TimeDateStamp do not march.\n"
	except AttributeError:
		pass
	
	#identify the checksum in the file header and calculate the file check sum
	#compare the two values
	try:
		checksumMatch = True
		hChecksum = pe.OPTIONAL_HEADER.CheckSum
		cChecksum = pe.generate_checksum()
		dataPoints = dataPoints + 1
		if hChecksum != cChecksum:
			checksumMatch = False
		print("Header Checksum Value: " + str(hChecksum))
		print("Calculated Checksum Value: " + str(cChecksum))
		
		#if no data points were found, the checksum check is not testing for timeDateStamp manipulation
		if checksumMatch is False and dataPoints > 0: 
			finalPrint = finalPrint + "The header checksum and the calculated checksum do not match.\n"
	except AttributeError:
		pass 
	
	#print results
	if dataPoints == 0:
		print("\nNo Date Points found")
	elif len(finalPrint) > 1 and epochZero is False:
		print("\nTimeDateStamp manipulation is possible based on the following findings:\n")
		print(finalPrint)
	else:
		print("\nTimeDateStamp manipulation was not identified.")
	
	#print all TimeDateStamp findings
	
	
	#print pe.dump_info()
	
if __name__ == "__main__":
    if len(sys.argv) is 2:
		try:
			path = sys.argv[1]
			pe = pefile.PE(path)
			checks(pe)
		except WindowsError:
			print("Not an acceptable file path")