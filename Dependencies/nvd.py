import json
import requests
import re
from datetime import datetime, timedelta
import logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)


# common 
def _is_valid_cve_id(cve_id):
    return re.match(r'^CVE-\d+-\d+$', cve_id)

def _format_time(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S:%f')[:-3] + ' UTC+07:00'

'''
https://nvd.nist.gov/developers/vulnerabilities
'''
class NVD:
    def __init__(self):
        self.base_url = 'https://services.nvd.nist.gov/rest/json'
        self.cve_path = '/cve/1.0'
        self.cves_path = '/cves/1.0'

    def get_nvd_response(self, url, params=None):
        response = requests.get(url, params=params)
        if response.status_code != 200:
            logging.error(f'fetch failed {response.status_code}')
            return None
        else:
            return response.json()

    def get_cve_by_id(self, cve_id):
        if not _is_valid_cve_id(cve_id):
            logging.error(f'invalid cve_id {cve_id}')
            return None
        else:
            full_url = f'{self.base_url}{self.cve_path}/{cve_id}'
            nvd_response = self.get_nvd_response(full_url)
            return nvd_response['result']
    
    def _get_cves(self, index=0, mod_start_date=None):
        query_string = {
            "startIndex": index,
            "resultsPerPage": 1000 ## Max available
        }
        if mod_start_date:
            mod_start_date = _format_time(mod_start_date)
            mod_end_date = _format_time(datetime.now())
            query_string["modStartDate"] = mod_start_date
            query_string["modEndDate"] = mod_end_date
        full_url = f"{self.base_url}{self.cves_path}"
        nvd_response = self.get_nvd_response(full_url, query_string)
        return nvd_response

    def get_cves(self, last_n_mins=60):
        time_since = datetime.now() - timedelta(minutes=last_n_mins)
        logging.info(f"fetching cve since {time_since}")
        start_index = 0
        response = self._get_cves(start_index, time_since)
        cves_fetched = response['result']['CVE_Items']
        remaining = response['totalResults'] - len(cves_fetched)
        logging.debug(f'fetched: {len(cves_fetched)} / {response["totalResults"]}')
        while remaining > 0:
            start_index += len(cves_fetched)
            response = self._get_cves(start_index, time_since)
            logging.debug(len(response['result']['CVE_Items']))
            cves_fetched += response['result']['CVE_Items']
            remaining = response['totalResults'] - len(cves_fetched)
            logging.debug(f'fetched: {len(cves_fetched)} / {response["totalResults"]}')
        return cves_fetched

if __name__ == '__main__':
    nvd = NVD()
    print(nvd.get_cves(last_n_mins=1000))