#https://github.com/RandomRhythm/CBC_Vuln_Assessment
import csv
import os
import io
# NVD CVE Imports #https://github.com/chanonong/nvd-cve-api # Copyright (c) 2021 Chanon Khamronyutha
import Dependencies.nvd 
from Dependencies.simple_cve import SimpleCVE
# end NVD CVE Imports

inputCSV = "assets-123ABCDE_2022-07-07-123456.csv" #file path to vulnerability CSV export
package_output_directory = "e:\\test" #directory folder path for output
outputEncoding = "utf-8"

dictCVE = {}
intComputerColumn = -1
intVulnColumn = -1
api = Dependencies.nvd.NVD()

def concatString(strBuild, strConcat, strSep):
  if strBuild == "":
    return strConcat
  else:
    return strBuild + strSep + strConcat

def logLine(fHandle, logline):
    fHandle.write("\"" + logline.replace("|", "\",\"") + "\"" + "\n")
    
with open(inputCSV) as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    boolHeader = False

    for row in csv_reader:
      if boolHeader == False:
        boolHeader = True
        tmpColumnCount = 0
        for cell in row:
          if cell == "Name":
            intComputerColumn = tmpColumnCount
          elif cell == "CVE Ids":
            intVulnColumn = tmpColumnCount
          tmpColumnCount +=1
            
      else:
          #print(row[intComputerColumn] +"|" + row[intVulnColumn])
          vulns = row[intVulnColumn]
          compName = row[intComputerColumn]
          if "," in vulns:
            arrayVulns = vulns.split(",")
            for cveID in arrayVulns:
              if cveID in dictCVE:
                dictCVE[cveID].append(compName)
                #print(cveID + "|" + str(dictCVE[cveID]))
              else:
                dictCVE[cveID] = [compName]
          else: 
            if vulns in dictCVE:
              dictCVE[vulns].append(compName)

              #print(dictCVE[vulns] )
            else:
              dictCVE[vulns] = [compName]

cveStatsFileHandle = io.open(os.path.join(package_output_directory, "cveStat.txt"), "a", encoding=outputEncoding) #open file handle for CVE stats
with open(os.path.join(package_output_directory, "vulns.txt"), 'w') as writer1:
  intRowCount = 0
  stillData = True
  while stillData == True:
    stillData = False
    rowout = ""
    for vuln in dictCVE:
      if intRowCount == 0:
        cve = api.get_cve_by_id(vuln) #REST API call to NVD
        scve = SimpleCVE(cve['CVE_Items'][0]) #JSON CSV Parse
        rowout = concatString(rowout, vuln, ",")
        logLine(cveStatsFileHandle, vuln + "|" + str(scve.cvss_score) + "|" + str(len(dictCVE[vuln]))  + "|" + scve.description)
        stillData = True
      elif len(dictCVE[vuln]) > intRowCount -1:
        rowout = concatString(rowout, dictCVE[vuln][intRowCount -1], ",")
        stillData = True
      else:
        rowout = rowout + ","
    writer1.write(rowout + "\n")
    intRowCount +=1
    cveStatsFileHandle.close()
