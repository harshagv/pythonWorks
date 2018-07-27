Assessment:

1. Download the xlsx from - https://www.iso20022.org/sites/default/files/ISO10383_MIC/ISO10383_MIC.xls
2. Store the xlsx
3. Read the tab titled "MICs List by CC"
4. Create a list of dict containing all rows (except row 1). The values in row 1 would be the keys for in each dict.
5. Store the list from step 4) as a .json file in an AWS S3 bucket
6. The above function should be run as an AWS Lambda



### Running the Code:
use any terminal:

```
cd Assessment_1
python3 main.py
```

view the results