#!/usr/bin/python3
__author__ = 'harshagv'

import os
import sys
import zipfile
from os.path import join, isfile

zipFilePath=sys.argv[1]
zipExtractDirectoryPath=str(sys.argv[2])


def filesInDirPrint(directoryPath):
    if os.path.exists(directoryPath):
      for file in [os.listdir(directoryPath)]:
        print(file)


def filePathCheck(filePath):    
    #Check the existence of the "dirName"
    try:
        if os.path.exists(filePath):
            if os.path.isfile(filePath):
                print("File: " + filePath + " is available!")
            else:
                print("Unable to locate the file: " + filePath)
                #raise InstallerException("Unable to Create the directory" + filePath)
    except OSError as msg:
        print("OS Error " + str(msg))


def unzipMethod(zipFilePath,zipExtractDirectoryPath):    
    # check does the zip file exists
    filePathCheck(zipFilePath)

    # unzip the zip file to a specfied directory
    config_zip=zipfile.ZipFile(zipFilePath)
    config_zip.extractall(zipExtractDirectoryPath)
    config_zip.close()
 
 
if __name__ == "__main__":
  try:
    if len(sys.argv) == 3:
      print("Correct number of runtime arguments passed!")
    else:
      raise print("Usage: python3 main.py zipFilePath zipExtractDirectoryPath")
  except IndexError as msg:
      raise print("Runtime Arguments Error " + str(msg) + ' ' + __file__ + ':' + str(sys._getframe().f_lineno))

  # Unzip the file
  unzipMethod(zipFilePath,zipExtractDirectoryPath)
  # Lists the files under 
  print("Zip Extracted Contents are: ")
  filesInDirPrint(zipExtractDirectoryPath)
