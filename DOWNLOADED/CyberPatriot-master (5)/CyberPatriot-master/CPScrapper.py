##Written by Ethan Fowler
##Team-ByTE 2016-2017 Oklahoma State Champion
##Github: https://github.com/C0ntra99
##Email: fowlerethan99@gmail.com

from bs4 import BeautifulSoup as BS
import requests
import re
import xlwt
import time
import sys
##used regular expressions to remove the tags from each line
def removeTag(raw_text):
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', raw_text)
    return cleantext

##Pull in the scoreboard and parse through it
try:
    page = requests.get('http://scoreboard.uscyberpatriot.org')
except:
    print("[!]Error: Webpage is unavailable...")
    sys.exit()

html = BS(page.content, 'html.parser')


##Set up for the Excel file
book = xlwt.Workbook()
sheetName = str(input("What round of competition is it?(ex. round1): "))
sheet = book.add_sheet(sheetName)

cols = ["Placement", "Team Number", "Location", "Division", "Teir", "Scored Images", "Play Time", "Current Score"]
row = sheet.row(0)
for index, col in enumerate(cols):
    row.write(index, col)

print("~"*15  + "Starting program" + "~"*15)
##Starts at 8 and ends at 15 in order to skip the labels at the top of the webpage
start = 8
end = 15
placement = 1
R = 1
start_time = time.time()

while True:
    ##Take out the table with the scores
    test = html.find_all('td')[start:end]

    ##make sure the line has a value
    if not len(test) == 0:
        ##insert a placement
        test.insert(0,placement)

        ##Created a new list for the newly formatted elements in the table
        L = []
        for x in test:
            x = str(x)
            x = removeTag(x)
            #print(removeTag(x))
            if x.isdigit():
                x = float(x)
            else:
                pass
            L.append(x)

        ##Adds the elements of the List to each column in the spreadsheet    
        row = sheet.row(R)
        for index, col in enumerate(cols):
            val = L[index]
            row.write(index, val)

        start += 8
        end += 8
        placement += 1
        R += 1

    else:
        break

elapsed_time = time.time() - start_time
elapsed_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
print("Time Elapsed: ", elapsed_time)
fileName = str(input("Please enter a fielname(ex. round1Scores.xls): "))
if not ".xls" in fileName:
    book.save(fileName +".xls")
else:
    book.save(fileName)