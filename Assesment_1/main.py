#!/usr/bin/python3

from lib.wget import download
from xlrd import open_workbook
import json
import boto3
from boto.s3.key import Key

url='https://www.iso20022.org/sites/default/files/ISO10383_MIC/ISO10383_MIC.xls'

try:
  excelFileName=download(url)
except Exception as downloadExcp:
  raise print(downloadExcp + "Unable to download " + url)

try:
workbook = open_workbook(excelFileName)
#worksheets = workbook.sheet_names()
worksheet = workbook.sheet_by_name('MICs List by CC')

# Read Workbook header values into a list
first_row_keys = [] 
for col in range(worksheet.ncols):
    first_row_keys.append( worksheet.cell_value(0,col) )

# Convert the workbook to a list of dictionary
row_data = []
for row in range(1, worksheet.nrows):
    elm = {}
    for col in range(worksheet.ncols):
        elm[first_row_keys[col]]=worksheet.cell_value(row,col)
    row_data.append(elm)

# Print the row header data
print("Workbook Row Headers are : " + first_row_keys)
print("\n")

# Store the list containing row data to a json file 
jsonFileName="row_data.json"

json = json.dumps(row_data)
f = open(jsonFileName,"w")
f.write(json)
f.close()


# Store the list from json file in an AWS S3 bucket using AWS lambda function
keyId = "our_aws_key_id"
sKeyId= "our_aws_secret_key_id"

def save_json_data_to_bucket(event,context):

	file = open(jsonFileName,"r")

	conn = boto.connect_s3(keyId,sKeyId)

	bucketName="myJsonBucket01"
	bucket = conn.get_bucket(bucketName)

	# Get the Key object of the bucket
	k = Key(bucket)

	# Crete a new key with id as the name of the json file
	k.key=jsonFileName
	
	# Upload the file
	# Result contains the size of the file uploaded
	result = k.set_contents_from_file(file)	
