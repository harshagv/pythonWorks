#!/usr/bin/python3
__author__ = 'harshagv'

import sys
import json
import boto3
from boto3.s3.key import Key
from lib.wget import download
from xlrd import open_workbook


def read_excel_write_json(xlsFileURL):
    worksheetName='MICs List by CC'
    
    # Download the excel file: xlsFileURL
    try:
        excelFileName=download(xlsFileURL)
    except Exception as downloadExcp:
        raise print(downloadExcp + "Unable to download " + xlsFileURL)

    workbook = open_workbook(excelFileName)
    #worksheets = workbook.sheet_names()
    
    # Read the worksheet with the name - 'MICs List by CC'
    worksheet = workbook.sheet_by_name(worksheetName)
    
    # Read Workbook header values into a list
    try:
        first_row_keys = [] 
        for col in range(worksheet.ncols):
            first_row_keys.append( worksheet.cell_value(0,col) )

        # Convert the workbook into a list of dictionary [key:pair values]
        row_data = []
        for row in range(1, worksheet.nrows):
            elm = {}
            for col in range(worksheet.ncols):
                elm[first_row_keys[col]] = worksheet.cell_value(row,col)
            row_data.append(elm)
    except Exception as xlsException:
        raise(xlsException + " Error getting bucket!")

    # Print the row header data
    print("Workbook Row Headers are : " + str(*first_row_keys))

    # Store the list containing workbook row data to a json file 
    global jsonFileName
    jsonFileName="row_data.json"

    jsonData = json.dumps(row_data)
    f = open(jsonFileName,"w")
    f.write(jsonData)
    f.close()


def save_json_data_to_bucket_handler(event,context):
    # Store the list from json file in an AWS S3 bucket using AWS lambda function
    bucketName = "myJsonBucket01"
    
    jsonFile = open(jsonFileName,"r")
    
    # create AWS s3 bucket in the region - '' and put the json file contents to the same
    try:
        s3 = boto3.resource('s3')
        response = s3.create_bucket(Bucket=bucketName, CreateBucketConfiguration={'LocationConstraint': 'ap-south-1'})
        s3.Object('jsonBucket', jsonFileName).put(Body=open(jsonFileName, 'rb'))

    except Exception as awsBucketException:
        raise(awsBucketException + " Error getting bucket!")

    return "Success in transferring json contents to an AWS S3 bucket"


if __name__ == "__main__":
    try:
        xlsFileURL='https://www.iso20022.org/sites/default/files/ISO10383_MIC/ISO10383_MIC.xls'
        
        read_excel_write_json(xlsFileURL)
        message = save_json_data_to_bucket_handler({},{})
        print(message)
    except Exception as msg:
        raise(msg + __file__ + ':' + str(sys._getframe().f_lineno))