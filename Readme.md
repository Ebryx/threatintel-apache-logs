Install Python3 and Pip3 first and then perform these steps in order on Linux to successfully execute the ip-ti.py script.
1. cd into the current directory
2. Run the command "cd cymon-python-master && python3 setup.py install && cd .."
3. Run command "pip3 install -r requirements.txt"
4. Enter the appropriate API Keys and run command "export API_KEY_OTX=<OTX-API-KEY> && export API_KEY_CYMON=<CYMON-API-KEY> && export API_KEY_C1FAPP=<C1FAPP-API-KEY>"
5. Run command "python3 ip-ti.py -h" and get all information on how to execute the script with different feeds (OTX, Cymon, C1fapp and Custom feed files from Spamhaus)
6. After you have generated a CSV using ip-ti.py script, you can run the send_logs_to_logmanager.py script and upload TI alongwith logs to Elasticsearch.
7. send_logs_to_logmanager.py requires that you have the IP and Port of elasticsearch cluster
8. Further information on how to execute the respective scripts can be found using following commands:
	8.1. 'python3 ip-ti.py -h'
	8.2. 'python3 send_logs_to_logmanager.py -h'
9. Import 'es-material.json' from direcroty 'elasticsearch-material' into Elasticsearch to setup all the dashboards & visualizations