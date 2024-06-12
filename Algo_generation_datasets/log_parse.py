#from rawweb import RawWeb
from xml.etree import ElementTree as ET
import urllib
import base64
import csv
log_path = 'gr2.log'
output_csv_log = 'newme.csv'
class LogParse:
    def __init__(self):
        pass
    def parse_log(self,log_path):
        '''
        This fucntion accepts burp log file path.
        and returns a dict. of request and response
        result = {'GET /page.php...':'200 OK HTTP / 1.1....','':'',.....}
        '''
        result = {}
        try:
            with open(log_path):
                pass
        except IOError:
            print
            "[+] Error!!! ", log_path, "doesn't exis t.."
            exit()
        try:
            tree = ET.parse(log_path)
        except Exception as e:
            print
            '[+] Opps..!Please make sure binary data is not present in Log, Like    raw image dump,flash(.swf files) dump etc'
            exit()
        root = tree.getroot()
        for reqs in root.findall('item'):
            raw_req = reqs.find('request').text
            raw_req = urllib.unquote(raw_req).decode('utf8')
            raw_resp = reqs.find('response').text
            result[raw_req] = raw_resp
        return result

    def parseRawHTTPReq(self,rawreq):
        try:
            raw = rawreq.decode('utf8')
        except Exception:
            raw = rawreq    
        global headers,method,body,path
        headers = {}
        sp = raw.split('\r\n\r\n',1)
        if sp[1] != "":
            head = sp[0]
            body = sp[1]
        else :
            head = sp[0]
            body = ""
        c1 = head.split('\n',head.count('\n'))
        method = c1[0].split(' ',2)[0]
        path = c1[0].split(' ',2)[1]
        for i in range(1, head.count('\n')+1):
            slice1 = c1[i].split(': ',1)
            if slice1[0] != "":
                try:
                    headers[slice1[0]] = slice1[1]
                except Exception:
                    pass
        return headers,method,body,path
    
badwords = ['sleep', 'drop', 'uid', 'select','waitfor', 'delay', 'system', 'union', 'order by', 'group by']

def ExtractFeatures(method,path_enc,body_enc,headers):
    badwords_count = 0
    class_flag = "bad"
    path = urllib.unquote_plus(path_enc)
    single_q = path.count("'") + body.count("'")
    double_q = path.count("\"") + body.count("\"")
    dashes = path.count("--") + body.count("--")
    braces = path.count("(")+ body.count("(")
    spaces = path.count(" ") + body.count(" ")
    for word in badwords:
        badwords_count += path.count(word) + body.count(word)
    for header in headers:
        # single_q += headers[header].count("'")
        # double_q += headers[header].count("\"")
        # dashes += headers[header].count("-")
        # braces += headers[header].count("(")
        # spaces += headers[header].count(" ")
        badwords_count += headers[header].count(word) + headers[header].count(word)
    
    if single_q == 0 and double_q == 0 and dashes == 0 and braces ==0 and spaces == 0 and badwords_count == 0 : 
        class_flag = "good"
    return [method,path_enc.encode('utf-8').strip(),body_enc.encode('utf-8').strip(),single_q,double_q,dashes,braces,spaces,badwords_count,class_flag]
    raw_input('>>>')


#Open the log file
f = open(output_csv_log, "w")
c = csv.writer(f)
c.writerow(["method","path","body","single_q","double_q","dashes","braces", "spaces","badwords","class"])
f.close()
lp = LogParse()
result = lp.parse_log(log_path)
f = open(output_csv_log, "ab")
c = csv.writer(f)
for items in result :
    raaw = base64.b64decode(items)
    headers,method,body,path = lp.parseRawHTTPReq(raaw)
    result = ExtractFeatures(method,body,path,headers)
    c.writerow(result)
f.close()









