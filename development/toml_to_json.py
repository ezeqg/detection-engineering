import requests
import tomllib
import os

url = "https://2be3c797fc354a20917bf04047dd8304.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"
api_key = os.environ['ELASTIC_KEY']
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

data = ""
# converted_detections or custom_alerts
for root, dirs, files in os.walk("detections/"):
    for file in files:
        data = "{\n"
        if file.endswith(".toml"):
            full_path = os.path.join(root,file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)

                if alert['rule']['type'] == 'query':
                    required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','threat']
                elif alert['rule']['type'] == 'eql':
                    required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','language','threat']
                elif alert['rule']['type'] == 'threshold':
                    required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','threshold','threat']
                else:
                    print("Unsupported rule type found in " + full_path)
                    break
            
                for field in alert['rule']:
                    if field in required_fields:
                        if type(alert['rule'][field]) == list:
                            data += "\t" + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + ",\n"
                        elif type(alert['rule'][field]) == dict:
                            data += "\t" + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + ",\n"
                        elif type(alert['rule'][field]) == str:
                            if field == 'description':
                                data += "\t" + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n","").replace("\"","\\\"").replace("\\","\\\\") + "\",\n"
                            elif field == 'query':
                                data += "\t" + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n","").replace("\\","\\\\").replace("\"","\\\"")+ "\",\n"
                            else:
                                data += "\t" + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n","").replace("\"","\\\"") + "\",\n"
                        elif type(alert['rule'][field]) == int:
                            data += "\t" + "\"" + field + "\": " + str(alert['rule'][field]) + ",\n"
                data += "\t\"enabled\": true\n}"

        elastic_data = requests.post(url, headers=headers, data=data).json()
        print(elastic_data)