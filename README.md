# MISP IoC integration with Wazuh CDB [2024]
## This script facilitates the seamless integration of MISP IoCs with Wazuh, utilizing Python for implementation.<br /> It is essential to note that SYSMON or SYSLOG are prerequisites for successful execution.

Let us create a Python3 script dedicated to obtaining indicators of compromise from MISP.
```python
import json
from pymisp import PyMISP

misp_url = 'https://IP_MISP_MACHINE'
misp_key = 'APIKEY'
misp_verifycert = False
misp = PyMISP(misp_url, misp_key, misp_verifycert)
relative_path = 'attributes/returnAttributes/download/all/domain/true'
response = misp.direct_call(relative_path)

# Check if 'Attribute' key exists in the response
if 'Attribute' in response:
  # Extract 'value' from each dictionary in 'Attribute' list
  with open('/var/ossec/etc/lists/Blacklist-MISP', 'w') as file:
    for entry in response['Attribute']:
      if 'value' in entry:
        # Write domain followed by ': ' to the file
        file.write(f"{entry['value']}:\n")
else:
print("No valid 'Attribute' found in the response:", response)
```
This script initiates a GET call to MISP to retrieve domains in JSON format. In this instance, we specifically filtered for domains (yet it's feasible to filter for other indicators by adjusting attributes/returnAttributes/download/all/HERE/true).<br /><br /> Subsequently, the obtained domains are stored in Blacklist-MISP in the subsequent format:
```bash
ameteksen.com:
assso.net:
caref1rst.com:
careflrst.com:
empireb1ue.com:
facefuture.us:
healthslie.com:
```
Appending ':' immediately after the domain serves the purpose of facilitating the integration of the file into Wazuh's CDB lists.
## Incorporation of MISP IoCs into Wazuh

As evident from the developed script, a file is created within:

```bash
/var/ossec/etc/lists/Blacklist-MISP
```
This is deliberate, as it aligns with the default path for implementing CDB lists in Wazuh.
```bash
chown wazuh:wazuh Blacklist-MISP
```

Now, open the Wazuh configuration file ossec.conf
and add the following line (in Default ruleset) to identify our list:
```bash
<list>etc/lists/Blacklist-MISP</list>
```

Subsequently, navigate to /var/ossec/etc/rules/local_rules.xml and incorporate the ensuing script:

```bash
<group name="MISP_Alert,">
  <rule id="110006" level="12">
    <if_group>sysmon_event_22</if_group>
    <list field="win.eventdata.queryName" lookup="match_key">etc/lists/Blacklist-MISP</list>
    <description>[MISP] Blacklisted Domain - $(win.eventdata.queryName)</description>
  </rule>
</group>
```

