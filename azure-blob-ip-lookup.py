# azure-blob-ip-lookup.py is expecting the blob directory location, file of IPs to test, and desired output location

import json
import os
import sys

# Working vars
output = []
suspiciousIps = []
totalLogs = ""

def deleteFile(pathToFile):
    """Deletes the file from the passed absolute pathway."""
    try:
        os.remove(pathToFile)
    except:
        pass

def appendToFile(appendFilePath, toAppend):
    """Takes a file path and variable to append. Converts passed variable to a string."""
    try:
        appendFile = open(appendFilePath, "a")
        appendFile.write(str(toAppend))
        appendFile.write("\n")
        appendFile.close()
    except Exception as appendError:
        print(appendError)

def writeToFile(writeFilePath, toWrite):
    """Takes a file path and variable to write. Converts passed variable to a string."""
    try:
        writeFile = open(writeFilePath, "w")
        writeFile.write(str(toWrite))
        writeFile.close()
    except Exception as writeError:
        appendToFile(errorLogsPath, writeError)

def readFromFile(readFilePath):
    try:
        with open(readFilePath, "r") as readFile:
            returnedString = readFile.read()
            return returnedString
    except Exception as readSuspiciousIpsErr:
        appendToFile(errorLogsPath, readSuspiciousIpsErr)

def correctJson(invalidJson):
    """Takes a stringified JSON and adds a parent node and array.
    Also adds commas in between objects."""
    invalidJson = "{\n \"logs\": [\n" + invalidJson
    invalidJson = invalidJson.replace("}}", "}},")
    invalidJson = invalidJson + "]}"
    invalidJson = invalidJson.replace("}},\n]", "}}]")
    writeToFile(correctedJsonPath, invalidJson)
    return invalidJson

def checkForSuspiciousIps(ipsToFind, logsToCheck, output):
    for ip in ipsToFind:
        for request in logsToCheck["logs"]:
            if ip == request["properties"]["clientIp"]:
                output.append(request)
    return output

def makeOutputDir(outputPath):
    try:
        os.makedirs(outputPath, 0o777)
    except OSError as outputErr:
        pass

def checkForTrailingForwardSlash(input):
    if input[-1] == "/":
        returnedString = input[0:(len(input) - 1)]
        return returnedString
    else:
        return input

if __name__ == '__main__':

    blobPath = sys.argv[1]
    blobPath = checkForTrailingForwardSlash(blobPath)
    blobPath += "/m={}/d={}/h={}/m=00/PT1H.json"
    
    suspiciousIpsPath = sys.argv[2]
    suspiciousIpsPath = checkForTrailingForwardSlash(suspiciousIpsPath)

    outputPath = sys.argv[3]
    outputPath = checkForTrailingForwardSlash(outputPath)
    makeOutputDir(outputPath + "/azure-blob-ip-lookup")

    correctedJsonPath = outputPath + "/azure-blob-ip-lookup/PT1H-corrected.json"
    errorLogsPath = outputPath + "/azure-blob-ip-lookup/errorLogs.txt"
    outputPath += "/azure-blob-ip-lookup/output.json"

    deleteFile(errorLogsPath)
    deleteFile(outputPath)

    suspiciousIps = list(readFromFile(suspiciousIpsPath).split("\n"))

    for month in range(1, 13):
        for day in range(1, 32):
            for hour in range(24):
                try:
                    with open(blobPath.format(str(month).zfill(2), str(day).zfill(2), str(hour).zfill(2)), "r") as logs:
                        stringLogs = logs.read()
                        try:
                            suspiciousIps.append(checkForSuspiciousIps(suspiciousIps, json.loads(stringLogs), output))
                        except Exception as validJsonError:
                            appendToFile(errorLogsPath, 'JSON is not valid. Correcting...')
                            jsonDict = json.loads(correctJson(stringLogs))
                            suspiciousIps.append(checkForSuspiciousIps(suspiciousIps, jsonDict, output))
                except OSError as readBlobErr:
                    appendToFile(errorLogsPath, readBlobErr)
                except Exception as e:
                    appendToFile(errorLogsPath, e)

    writeToFile(outputPath, json.dumps(output))
