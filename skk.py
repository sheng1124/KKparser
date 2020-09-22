from glob import glob
import csv 
import datetime
import os
import sys
import itertools
import shutil
import re
import socket
import requests
import json



class Dir():
    def getParentDirByPath(self, filePath): #ff\gg\h\dd.txt = > ff\gg\h
        r = len(filePath) - filePath[::-1].find('\\') - 1 
        return filePath[0:r] 
        
    def mkdir(self, path):
        folder = os.path.exists(path)
        if not folder:
            os.makedirs(path)
            #print('-----建立成功-----')
    
class DateTime():
    def getDateYMD(self, dateTime):
        dateTime = dateTime.split(' ')[0]
        if(len(dateTime) > 10 ):
            dateTime = dateTime[0:10]
        for s in ['-', '/', ' ']:
            splitDate = dateTime.split(s)
            try:
                int(splitDate[0])
                if(int(splitDate[1]) > 0 and  int(splitDate[1]) <= 12 and int(splitDate[2]) > 0 and int(splitDate[2]) <= 31):
                    newDate = str(int(splitDate[0])) + '/' + str(int(splitDate[1])) + '/' + str(int(splitDate[2]))
                    return newDate
                else:
                    print('error date value')
            except ValueError:
                pass
            except IndexError:
                print('error date format', splitDate)
        return dateTime
    
    def TensZeroStuffing(self, number):
        if(int(number) < 10 and int(number) > -1):
            return '0' + str(number)
        else:
            return str(number)
    
    def getBatchTime(self, dateTime):
        YMDT = self.getDateTimeObject(dateTime)
        return '{}-{}-{}T{}:{}:{}{}'.format(YMDT['year'], self.TensZeroStuffing(YMDT['month']), self.TensZeroStuffing(YMDT['day']), self.TensZeroStuffing(YMDT['hour']),self.TensZeroStuffing(YMDT['minute']),self.TensZeroStuffing(YMDT['second']),YMDT['timeZone'])
    
    def getDateTimeFormat(self, dateTime):
        YMDT = self.getDateTimeObject(dateTime)
        return '{}-{}-{}T{}:{}:{}'.format(YMDT['year'], self.TensZeroStuffing(YMDT['month']), self.TensZeroStuffing(YMDT['day']), self.TensZeroStuffing(YMDT['hour']),self.TensZeroStuffing(YMDT['minute']),self.TensZeroStuffing(YMDT['second']))

    
    def getDateTimeObject(self, dateTime): #2020-09-01T00:43:10+0800
        if(len(dateTime) > 24 ):
            dateTime = dateTime[0:24]
        YMD = dateTime.replace(' ', '*')
        for letter in ['-', '/']:
            YMD = YMD.replace(letter, ' ')
        YMD = YMD.split(' ') #[year, month, day, ...]
        YMDT={}

        try:
            YMDT['year'] = int(YMD[0])
        except ValueError:
            input('你輸入的year {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))
        if(YMDT['year'] < 1900):
            input('你輸入的year {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))
        
        try:
            YMDT['month'] = int(YMD[1])
        except ValueError:
            input('你輸入的month {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))
        if(YMDT['month'] > 12 ):
            input('你輸入的month {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))

        try:
            YMDT['day'] = int(YMD[2][:2])
        except ValueError:
            try:
                YMDT['day'] = int(YMD[0][:1])
            except ValueError:
                input('你輸入的day {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))
        if(YMDT['day'] > 31 ):
            input('你輸入的day {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))

        YMD = dateTime.replace(' ', '*')
        for letter in [':']:
            YMD = YMD.replace(letter, ' ')
        YMD = YMD.split(' ')
        
        try:
            YMDT['hour'] = int(YMD[0][-2:])
        except ValueError:
            try:
                YMDT['hour'] = int(YMD[0][-1:])
            except ValueError:
                input('你輸入的hour {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))
        if(YMDT['hour'] > 23 or YMDT['hour'] < 0):
            input('你輸入的hour {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))
        
        try:
            YMDT['minute'] = int(YMD[1])
        except ValueError:        
            input('你輸入的minute {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))
        if(YMDT['hour'] > 59 or YMDT['hour'] < 0):
            input('你輸入的minute {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))

        try:
            YMDT['second'] = int(YMD[2][:2])
        except ValueError:        
            try:
                YMDT['second'] = int(YMD[2][:1])
            except ValueError:
                input('你輸入的second {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))
        if(YMDT['second'] > 59 or YMDT['hour'] < 0):
            input('你輸入的second {} 格式錯誤 應為 年/月/日...數字'.format(dateTime))
        
        timeZone = dateTime.find('+')
        if(timeZone > -1):
            try:
                int(dateTime[timeZone+1:timeZone+5])
                YMDT['timeZone'] = dateTime[timeZone:timeZone+5]
            except ValueError:
                YMDT['timeZone'] = '+0800'
        else:
            YMDT['timeZone'] = '+0800'

        return YMDT
        
class ParserInterface(Dir, DateTime):
    def trimISP(self, ispName):
        if(ispName.find('股份') > 0):
            return ispName[0:ispName.find('股份')]
        elif(ispName.find('有限') > 0):
            return ispName[0:ispName.find('有限')]
        else :
           return ispName
           
    def getISAC(self, ispName):
        if(ispName.find('ISAC') > -1):
            return ispName
        elif(ispName.find('教育部') > -1):
            return 'A-ISAC'
        elif(ispName.find('委員會') > -1):
            return 'N-ISAC'
        else :
            return 'C-ISAC'
    
    def isType12ISP(self, fileName):
        name = self.extractIspName(fileName)
        try :
            if(name in self.type12Isp):
                return self.type12Isp[name]
            else:
                print(name + ' is not in type1 type2 isp')
                return False
        except AttributeError:
            self.type12Isp = {}
            with open(os.getcwd() + "\\database\\Type1_Type2_ISP.csv", 'r', newline = '') as fin:
                rowsInput = csv.DictReader(fin)
                for row in rowsInput:
                    self.type12Isp[row['ISP']] = True
            return self.isType12ISP(fileName)
    
    def getBatchIpPortFormat(self, ip, port, port_description=''):
        return '[{"ip":"' + str(ip) + '","port":"' + str(port) +'","port_description":"' + port_description +'"}]'
    
    def getStrSectionByFind(self, oStr, temp_head, temp_tail):
        l = oStr.find(temp_head)
        if(l < -1):
            return ''
        oStr = oStr[l + len(temp_head):]
        r = oStr.find(temp_tail)
        return oStr[:r]
    
class FilesPathLoader(ParserInterface):
    def __init__(self, path):
        self.workPath = path
        self.outPutPath = path
        self.allTargetFilePathList = self.generateTargetFilePathList(self.workPath)

    def generateTargetFilePathList(self, workPath):
        filePathList = {}
        for dirPath, dirNames, fileNames in os.walk(workPath):
            for file in fileNames:
                if(self.isThisTargetFile(file)):
                    filePathList[dirPath + "\\" + file] = { 'fileName' : file }
        return filePathList

    def isThisTargetFile(self, fileName):
        return False
    
    def getTargetFilePathList(self):
        return self.allTargetFilePathList
    
class SKK_http(FilesPathLoader):
    def __init__(self, path, path2):
        super(SKK_http, self).__init__(path)
        self.outPutPath = path2
        self.events = {} #[{},{}...] {}=>{}
        self.field = ["Time", "Src IP", "Src Port", "Dest IP", "Dest Port", "Path", "ASN code" , "ASN name" ]
        for path in self.allTargetFilePathList:
            self.loadData(path)
        
    def isThisTargetFile(self, fileName):
        if(fileName.find('all_http_malice_log_today') > -1):
            return True
        else:
            return False
    
    def getLoadDataEvent(self, newline):
        event = {
            'datetime' : self.getDateTimeFormat(str(newline[0])),
            'ip' : str(newline[1]),
            'port' : str(newline[2]),
            'destIp' : str(newline[3]),
            'destPort' : str(newline[4]),
            'path' : str(newline[5])
        }
        return event
    
    def loadData(self, filePath):
        with open(filePath, 'r', newline = '') as fin:
            for line in fin:
                newline = line.split()
                if(newline == []):
                    continue
                event = self.getLoadDataEvent(newline)
                if(event['ip'] not in self.events):
                    self.events[event['ip']] = []
                self.events[event['ip']].append(event)

    def printEvents(self):
        for event in self.events:
            print(event)
            for accdient in self.events[event]:
                print(accdient)
            print()
    
    def parseCountryAndIsp(self):
        outPutPath = self.getEventLogOutputPath()
        rdpg = RdpgPareser('{}\\whois_result\\rdpg'.format(os.getcwd()))
        ipp = IplistPareser('{}\\whois_result\\iplist'.format(os.getcwd()))
        for event in self.events:
            headEvent = self.events[event][0]
            ippresult = ipp.parseAsnCountryByIP(headEvent['ip'])
            headEvent['country'] = ippresult['countrycode']
            headEvent['asn'] = {'code' : ippresult['asn']['code'] , 'name' : ippresult['asn']['name']}
            cert = CERTDB.certLookup(headEvent['country'])
            if(cert == None):
                print('{} 不在國家DB裡，請更新DB'.format(cert))
            headEvent['cert'] = cert
            if(cert == '' or cert == None):
                CC = headEvent['country']
                if(CC == 'TW' or CC == 'CN' or CC == 'HK' or CC == 'MO' or CC == 'RU' or CC == 'UNKNOWN'):
                    headEvent['abuse_email'] = ''
                else:
                    rdpgresult = rdpg.parseIP(headEvent['ip'])
                    headEvent['abuse_email'] = rdpgresult['abuse_email']
            else:
                headEvent['abuse_email'] = ''
            if(headEvent['country'] == 'TW'):
                twisp = TWISPDB.ispLookup('AS' + headEvent['asn']['code'])
                if(twisp != None):
                    headEvent['isp'] = twisp
                else:
                    headEvent['isp'] = '__AS__' + headEvent['asn']['code']
            else:
                headEvent['isp'] = headEvent['abuse_email']
            self.mkdir('{}\\{}'.format(outPutPath,headEvent['country']))
    
    def getEventLogOutputPath(self):
        return '{}\\http_log'.format(self.outPutPath)
    
    def getEventLogOutputWriterow(self, line, headEvent):
        return [line['datetime'], line['ip'], line['port'], line['destIp'], line['destPort'], line['path'], headEvent['asn']['code'], headEvent['asn']['name']]

    def outputEventLog(self):
        outPutPath = self.getEventLogOutputPath()
        self.mkdir(self.outPutPath)
        self.mkdir(outPutPath)
        for event in self.events:
            ipCountry = self.events[event][0]['country']
            headEvent = self.events[event][0]
            csvOutputPath = '{}\\{}\\{}_{}.csv'.format(outPutPath, ipCountry, event.replace('.', '-'), ipCountry)
            headEvent['logPath'] = csvOutputPath
            with open(csvOutputPath, 'a', encoding='utf-8',newline='') as fout:
                writer = csv.writer(fout)
                writer.writerow(self.field)
                for line in self.events[event]:
                    writer.writerow(self.getEventLogOutputWriterow(line, headEvent))
    
    def getBatchENTitle(self):
        return 'http malice ip (GMT+8) (kk)'
    
    def getBatchCHTitle(self, headEvent):
        return '{}設備用戶IP:「{}」疑似對外攻擊警訊 (kk)'.format(headEvent['isp'], headEvent['ip'])
    
    def getBatchENDescription(self):
        return 'The source of these messages is from National Kaohsiung University of Hospitality and Tourism.'
    
    def getBatchCHDescription(self, headEvent):
        return 'TWCERT/CC於{}UTC+8 接獲「高雄餐旅大學」通報，發現貴單位資訊設備IP:「{}」對外攻擊，疑似企圖入侵，建議盡速確認並解決相關問題。'.format(self.getBatchTime(headEvent['datetime']), headEvent['ip'])
    
    def getBatchFileName(self):
        return 'kk_batch.csv'
    
    def getBatchOutputWriterow(self, headEvent):
        newRow = {
            'contact_pu' : '黃士育(高雄餐旅大學)',
            'phone' : '07-060505#1253',
            'email' : 'kk@mail.nkuht.edu.tw',
            'ip' : self.getBatchIpPortFormat(headEvent['ip'], headEvent['port']),
            'title' : headEvent['batchTitle'],
            'discover_date' : self.getBatchTime(headEvent['datetime']),
            'confidential_impact' : '0',
            'integrity_impact' : '0',
            'usability_impact' : '0',
            'cross_unit_impact' : '0',
            'event_classification' : 'Z05',
            'event_description' : headEvent['batchDescription']
        }
        return newRow
    
    def outputBatch(self):
        BM = BatchMaker('{}\\{}'.format(self.outPutPath, self.getBatchFileName()))
        for event in self.events:
            headEvent = self.events[event][0]
            if(len(self.events[event]) < 6 or headEvent['country'] == 'UNKNOWN'):
                headEvent['isBulletin'] = False
                continue
            headEvent['isBulletin'] = True
            if(headEvent['country'] != 'TW'):
                headEvent['batchTitle'] = self.getBatchENTitle()
                headEvent['batchDescription'] = self.getBatchENDescription()
            else:
                headEvent['batchTitle'] = self.getBatchCHTitle(headEvent)
                headEvent['batchDescription'] = self.getBatchCHDescription(headEvent)
            newRow = self.getBatchOutputWriterow(headEvent)
            BM.addRow(newRow)
    
    def getMidSheetName(self):
        return 'midsheet.csv'
    
    def getMidSheetWriterow(self, headEvent):
        # "工單編號,IP,通報國家,通報ISP業者/單位,通報Cert,log檔路徑"
        newRow = {
            '工單編號' : '',
            'IP' : headEvent['ip'],
            '通報國家' : headEvent['country'],
            '通報ISP業者/單位' : headEvent['isp'],
            '通報Cert' : headEvent['cert'],
            'log檔路徑' : headEvent['logPath']
        }
        return newRow
        
    def outputMidSheet(self):
        midsheetPath = '{}\\{}'.format(self.outPutPath, self.getMidSheetName())
        MSM = MidSheetMaker(midsheetPath)

        for event in self.events:
            headEvent = self.events[event][0]
            if(not headEvent['isBulletin']):
                continue
            newRow = self.getMidSheetWriterow(headEvent)
            MSM.addRow(newRow) 

    def work(self):
        self.parseCountryAndIsp()
        self.outputEventLog()
        self.outputBatch()
        
    def work2(self):
        self.outputMidSheet()

class SKK_snort(SKK_http):
    def __init__(self, path, path2):
        super(SKK_http, self).__init__(path)
        self.outPutPath = path2
        self.events = {} #[{},{}...] {}=>{}
        self.field = ["Time", "Src IP", "Src Port","Message", "Classification", "ASN code" , "ASN name" ]
        for path in self.allTargetFilePathList:
            self.loadData(path)
            
    def isThisTargetFile(self, fileName):
        if(fileName.find('snort_log') > -1):
            return True
        else:
            return False
    
    def findDateTimeStr(self, dstr):
        dr = dstr.find('.')
        if(dr > 21):
            return ''
        return dstr[1:dr]
        
    def findClassification(self, cstr):
        temp1 = 'Classification: '
        temp2 = ']'
        return self.getStrSectionByFind(cstr, temp1, temp2)
    
    def findIp(self, ipstr):
        temp1 = '{TCP} '
        temp2 = ':'
        return self.getStrSectionByFind(ipstr, temp1, temp2)
    
    def findPort(self, pstr):
        temp1 = '{TCP} '
        temp2 = ' ->'
        layer1 = self.getStrSectionByFind(pstr, temp1, temp2)
        l = layer1.find(':')
        return layer1[l+1:]
    
    def findTitle(self, tstr):
        temp1 = '] '
        temp2 = ' ['
        return self.getStrSectionByFind(tstr, temp1, temp2)
    
    def getBatchENTitle(self, headEvent):
        return headEvent['title']
    
    def getBatchENDescription(self, headEvent):
        return headEvent['description']

    def getEventLogOutputPath(self):
        return '{}\\snort_log'.format(self.outPutPath)
    
    def getEventLogOutputWriterow(self, line, headEvent):
        return [line['datetime'], line['ip'], line['port'], line['description'], line['classification'], headEvent['asn']['code'], headEvent['asn']['name']]

    def getLoadDataEvent(self, newline):
        event = {
            'datetime' : self.getDateTimeFormat(self.findDateTimeStr(newline[0])),
            'classification' : self.findClassification(newline[1]),
            'title': self.findTitle(newline[1]),
            'description' : newline[1],
            'ip' : self.findIp(newline[1]),
            'port' : self.findPort(newline[1])
        }
        return event

    def loadData(self, filePath):
        with open(filePath, 'r', newline = '') as fin:
            fin.readline()
            for line in fin:
                newline = line.split(',')
                if(newline == []):
                    continue
                event = self.getLoadDataEvent(newline)
                if(event['ip'] not in self.events):
                    self.events[event['ip']] = []
                self.events[event['ip']].append(event)

class BatchMaker():
    def __init__(self, _filePath):
        self.head = "contact_pu,phone,email,ip,web_url,title,discover_date,model,fire_wall,anti_virus,detected_system,defend_system,others,confidential_impact,integrity_impact,usability_impact,cross_unit_impact,event_classification,event_description,contingency_measures"
        self.rowSplit = "聯絡人,電話,電子信箱,ip,網域或網址,主旨,事發時間,廠牌型號,防火牆,防毒軟體,入侵偵測系統,入侵防禦系統,其他,機密性衝擊(0-4),完整性衝擊(0-4),可用性衝擊(0-4),跨單位衝擊(0-4),情資分類,事件說明,應變措施"
        self.fieldNames = self.head.split(",")
        if(_filePath[-4:] != '.csv'):
            print('錯誤的路徑或檔名')
            return
        self.filePath = _filePath
        if(not os.path.isfile(self.filePath)):
            self.makeBatch()
    
    def makeBatch(self):
        rowSplit = self.rowSplit.split(",")
        headSplit = self.head.split(",")
        newRow = {}
        
        for i in range(len(headSplit)):
            newRow[headSplit[i]] = rowSplit[i]
        with open(self.filePath, 'w+', newline = '', encoding = 'utf-8') as csvfile:#, encoding = "utf-8"
            writer = csv.DictWriter(csvfile, self.fieldNames)
            writer.writeheader()
            writer.writerow(newRow)
    
    def addRow(self, newRow):
        with open(self.filePath, 'a+', newline = '', encoding = 'utf-8') as csvfile:#, encoding = "utf-8"
            writer = csv.DictWriter(csvfile, self.fieldNames)
            writer.writerow(newRow)

class TableMaker():
    def __init__(self, _filePath):
        if(_filePath[-4:] != '.csv'):
            print('錯誤的路徑或檔名')
            return
        self.filePath = _filePath
        self.setHead()
        self.fieldNames = self.head.split(",")
        if(not os.path.isfile(self.filePath)):
            self.makeTable()
            
    def setHead(self):
        self.head = "工單編號,日期,來源,筆數,通報國家,N-ISAC編號,N-ISAC分類,攻擊類型,N-ISAC通報單位,通報ISP業者/單位,接受日期,重要性,耗時工作日,被模仿屬於國內外,被模仿單位,類型,釣魚網站移除時間,DN國家,備註"

    def makeTable(self):
        with open(self.filePath, 'w+', newline = '') as csvfile:
            writer = csv.DictWriter(csvfile, self.fieldNames)
            writer.writeheader()
    
    def addRow(self, newRow):  
        with open(self.filePath, 'a+', newline = '') as csvfile:
            writer = csv.DictWriter(csvfile, self.fieldNames)
            writer.writerow(newRow)

class MidSheetMaker(TableMaker):
    def setHead(self):
        self.head = "工單編號,IP,通報國家,通報ISP業者/單位,通報Cert,log檔路徑"

class RdpgPareser():
    def __init__(self, path):
        self.workPath = path
        self.outPutPath = path
        self.url = 'https://rdpguard.com/free-whois.aspx?ip='
        self.headers = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
            "Connection" : "keep-alive",
            "Accept" : "text/html, application/xhtml+xml, */*",
            "Accept-Language": "en-US,en;q=0.8,zh-Hans-CN;q=0.5,zh-Hans;q=0.3"       
        }
        
    def removeTag(self, text):
        newText = text
        while(newText.find('<') > -1):
            l = newText.find('<')
            r = newText.find('>')
            newText = newText[0:l] + newText[r + 1: len(newText)]
        return newText
    
    def checkResult(self, context):
        results = {'abuse_email' : 'NULL'}
        for line in context:
            if(line.find('Abuse Email') > -1 and results['abuse_email'] == 'NULL'):
                emailList = line.split()
                if(len(emailList) > 2):
                    results['abuse_email'] = emailList[2]
                else:
                    results['abuse_email'] = 'UNKNOWN'
        return results
        
    def parseIP(self, ip):
        if(ip == ''):
            return ''
        url = '{}{}'.format(self.url, ip)
        results = requests.get(url, headers = self.headers)
        if(str(results) != '<Response [200]>'):
            print('email  ip: {:>15} {:>20}'.format(ip, str(results)))
        print('email  ip: {:>15} {:>20}'.format(ip, str(results)), end='\r')
        pen = False
        context = []
        for line in results.text.split('\n'):
            if(line.find('<pre') > -1):
                pen = True
            if(not pen):
                continue
            if(line.find('pre>') > -1):
                pen = False
                continue
            if(pen):
                context.append(self.removeTag(line))
        with open('{}\\{}.txt'.format(self.outPutPath, ip.replace('.','-').replace(':','-')), 'w', newline = '', encoding = 'utf-8') as fout:
            for line in context:
                fout.write(line)
        result_json = self.checkResult(context)
        return result_json
        
class URL():
    def isUrl(self, url):
        if(type(url) is not str):
            return False
        if(len(url.split('.')) < 2):
            return False
        return True

    def isDomain(self, domain):
        if(type(domain) is not str):
            return False
        if(len(domain.split('/')) > 1 or len(domain.split('.')) < 2):
            return False
        return True
    
    def getDomainFromUrl(self, url):
        if(not self.isUrl(url)):
            return ''
        if(url.find('http') > -1 and url.find('://')): #https://dddd.com/  
            domain = url.split('/')[2]
            return domain
        else:
            domain = url.split('/')[0]
            if(self.isDomain(domain)):
                return domain
            else:
                return ''
                
class IplistPareser(URL):
    def __init__(self, path):
        self.workPath = path
        self.outPutPath = path
        self.websiteApi = 'https://iplist.cc/api'
    
    def checkResult(self, result_json):
        newResult = result_json
        if('ip' not in result_json):
            newResult['ip'] = 'UNKNOWN'
        if('countrycode' not in result_json):
            newResult['countrycode'] = 'UNKNOWN'
        if('asn' not in result_json):
            newResult['asn'] = {'code': 'UNKNOWN', 'name' : 'UNKNOWN'}
        if('detail' not in result_json):
            newResult['detail'] = 'UNKNOWN'
        return newResult
            
    def parseAsnCountryByURL(self, url):
        domain = self.getDomainFromUrl(url)
        if(domain == ''):
            print('輸入的網址可能有錯: {}'.format(url))
            input('enter 繼續執行或重新輸入正確資料\n')
            return ''
        website = '{}/{}'.format(self.websiteApi, domain)
        results = requests.get(website)

        with open('{}\\{}.txt'.format(self.outPutPath, domain.replace('.','-')), 'w') as fout:
                fout.write(results.text)
        return json.loads(results.text)
        
    def parseAsnCountryByIP(self, ip):
        website = '{}/{}'.format(self.websiteApi, ip)
        results = requests.get(website)
        if(str(results) != '<Response [200]>'):
            print('email  ip: {:>15} {:>20}'.format(ip, str(results)))
        print('county ip: {:>15} {:>20}'.format(ip, str(results)), end='\r')
        with open('{}\\{}.txt'.format(self.outPutPath, ip.replace('.','-')), 'w') as fout:
                fout.write(results.text)
        result_json = json.loads(results.text)
        
        result_json = self.checkResult(result_json)
        return result_json

class CertList():
    #手動更新 https://isac.twcert.org.tw/cors/secondarycategory/136
    def __init__(self):
        self.dbTitle = "國家代碼,CERT"
        self.certList = self.loadCert()
    
    def certLookup(self, countrycode):
        if countrycode in self.certList:
            return self.certList[countrycode]
        else: 
            return None
            
    def getCertList(self):
        return self.certList
    
    def loadCert(self):
        with open('{}\\database\\cert.csv'.format(os.getcwd()),'r', encoding='utf-8', newline='') as csvin:
            rowsInput = csv.DictReader(csvin)
            certList = {}
            for rowInput in rowsInput:
                certList[rowInput['國家代碼']] = rowInput['CERT']
            return certList

class TWISP():
    def __init__(self):
        self.dbTitle = "ASN.,Netname,ASN單位,核發日期"
        self.twisp = self.loadAsn()

    def updateDB(self):
        pass
    
    def getTwasn(self):
        return self.twisp
    
    def loadAsn(self):
        with open('{}\\database\\twisp.csv'.format(os.getcwd()),'r', encoding='utf-8', newline='') as csvin:
            rowsInput = csv.DictReader(csvin)
            twisp = {}
            for rowInput in rowsInput:
                twisp[rowInput['ASN.']] = rowInput['ASN單位']
            return twisp
    
    def ispLookup(self, asn):
        if asn in self.twisp:
            return self.twisp[asn]
        return None
    
    def createDB(self):
        with open('{}\\database\\twisp.csv'.format(os.getcwd()),'w', encoding='utf-8', newline='') as csvout:
            head = self.dbTitle.split(',')
            writer = csv.DictWriter(csvout, head)
            writer.writeheader()
            asnTable = self.asnParser()
            ASNDot = asnTable[0::4]
            Netname = asnTable[1::4]
            ASNUnit = asnTable[2::4]
            ASNDate = asnTable[3::4]
            for i in range(len(ASNDot)):
                newrow = {
                    "ASN." : ASNDot[i],
                    "Netname" : Netname[i],
                    "ASN單位": ASNUnit[i],
                    "核發日期" : ASNDate[i]
                }
                writer.writerow(newrow)
            
    def asnParser(self):
        url = 'https://rms.twnic.net.tw/help_asn_assign.php'
        asnResult = requests.get(url)
        if(str(asnResult) != '<Response [200]>'):
            print(url + ' 連線錯誤' + str(asnResult))
            return None
        asnResult = asnResult.text.split('\n')
        track = False
        table = []
        for line in asnResult:
            if(line.find('ASN列表') > -1):
                track = True
            if(track == True and line.find('/table') > -1):
                track = False
            if(line.find('<td>') > -1 and track==True):
                
                h = line.find('<td>') + len('<td>')
                t = line.find('</td>')
                table.append(line[h:t])
        return table
        
CURRENTTIME = str(datetime.datetime.now().date())           
TWISPDB = TWISP()
CERTDB = CertList()

if __name__ == '__main__':
    #TT = TWASN() #更新TWASN DB 注意 AS3462為中華電信但不會更新進去，要更新後手動增加AS3462
    #TT.createDB()
    skk_http = SKK_http('{}\\input'.format(os.getcwd()), '{}\\output\\{}'.format(os.getcwd(), CURRENTTIME))
    skk_http.work()
    skk_snort = SKK_snort('{}\\input'.format(os.getcwd()), '{}\\output\\{}'.format(os.getcwd(), CURRENTTIME))
    skk_snort.work()
    
    skk_http.work2()
    skk_snort.work2()

     
if __name__ == '__main__2':
    pass