#!/usr/bin/python3
__author__ = 'harshagv'

import fileinput
import re
import datetime

#Copy the current YAML as backup along with timestamp
copyFile=str(datetime.datetime.now().strftime("%Y-%m-%d-%H_%M_%S_%p"))
print(copyFile)

fp = fileinput.input('regex.yaml', inplace=True, backup='.bak'+copyFile)
try:
  for line in fp:
    print(line, end="")
except OSError as msg:
  print("OSError: " + str(msg))
finally:
  fp.close()
  print("created backup of regex.yaml")

# Update the ear path of deployment - 'VID' using regex
with open ('regex.yaml', 'r' ) as file:
    content = file.read()

earPattern = re.compile(r'(VID:\s+url:\s+).*?war')
result = earPattern.sub(r'\1http://gvh.com/gvh.war', content)

writefile = open('regex.yaml', 'w' )
writefile.write(result)
writefile.close()

with open ('regex.yaml', 'r' ) as file:
    content = file.read()

# Update the sha1sum of new war file for deployment - 'VID' using regex
sha1sumPattern = re.compile(r'(VID:\s+url:\s.*\s+sha1:)\s+\w+')
result = sha1sumPattern.sub(r'\1 gvh999e6d0af44dcd53ec8419681eca7152b011', content)

writefile = open('regex.yaml', 'w' )
writefile.write(result)
writefile.close()


# Display the updated YAMl file contents which was replaced by regex subsititution
print('\n Resulting YAML contents : ' + str(result))


# Display the new pattern matching regex for used for substituting war from YAML file content
war=re.search(r'(VID:\s+url:\s+).*?war', content)
print("\n\nMatched Group for .war replacement: \n" + war.group(0))


# Display the new pattern matching regex for used for substituting sha1sum from YAML file content
sha1=re.search(r'(VID:\s+url:\s.*\s+sha1:)\s+\w+', content)
print("\n\nMatched Group for sha1sum replacement: \n" + sha1.group(0))
