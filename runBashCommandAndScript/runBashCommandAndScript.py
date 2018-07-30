#!/usr/bin/python3
__author__ = 'harshagv'

import subprocess
import sys
from subprocess import call
from os.path import join,isfile

try:
  if len(sys.argv) == 2:
    print("Correct number of runtime arguments passed!")
  else:
      raise print("Usage: python3 bashCommandAndScript.py bashScriptPath")
except IndexError as msg:
      raise print("Arguments Error " + str(msg) + ' ' + __file__ + ':' + str(sys._getframe().f_lineno))


# Run bash command to check java version >= 1.8 
javaVersion = subprocess.check_output(["javac", "-version"],stderr=subprocess.STDOUT).decode()
if (javaVersion.find("1.8") != -1):
  try:
    print( "JAVA SE KIT Version is : " + javaVersion)
  except OSError as exception:
    print(exception + "JAVA SE KIT is not installed or is either 1.8+ version not installed")


# Run bash "ls -l" command
cmd_line="ls "+ "-l " + "."
print("Command is: " + cmd_line)
result = subprocess.check_output(["ls","-l"],stderr=subprocess.STDOUT).decode()
print(result)


# Run a bash script to print fibonacci series of first 'n' natural numbers
bashScriptFileName=sys.argv[1] 
numValue='50'

try:
  result = subprocess.check_output(["bash",bashScriptFileName,numValue],stderr=subprocess.STDOUT).decode()
except subprocess.CalledProcessError as exception:
  print(str(cmd_line) + "execution exception:\n" + str(exception.output) + str(result))

print("Output of " + bashScriptFileName + " for printing Fibonnaci series of " + numValue + " numbers are : " + str(result) + "\n")


