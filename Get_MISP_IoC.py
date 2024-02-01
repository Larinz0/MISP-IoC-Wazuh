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
