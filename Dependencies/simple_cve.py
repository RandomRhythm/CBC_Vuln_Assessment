import json

class JSONSerializable:
    def reprJSON(self):
        d = dict()
        for a, v in self.__dict__.items():
            if (isinstance(v, list)):
                d[a] = [_.reprJSON() if hasattr(_, "reprJSON") else _ for _ in v]
            elif (hasattr(v, "reprJSON")):
                d[a] = v.reprJSON()
            else:
                d[a] = v
        return d
    
    def __repr__(self) -> str:
        return json.dumps(self.reprJSON(), indent=2)

class Reference(JSONSerializable):
    def __init__(self, ref_json) -> None:
        self.name = ref_json['name']
        self.url = ref_json['url']
        self.refsource = ref_json['refsource']
        self.tags = list()
        if 'tags' in ref_json.keys():
            self.tags = ref_json['tags']

class SimpleCVE(JSONSerializable):
    def __init__(self, cve_json) -> None:
        self.cve_id = None
        self.description = None
        self.references = None

        cve = cve_json['cve']
        self.cve_id = cve['CVE_data_meta']['ID']
        self.references = list(map(Reference, cve['references']['reference_data']))
        self.description = self.get_description(cve['description']['description_data'])
        self.published_date = cve_json['publishedDate']
        self.last_modified_date = cve_json['lastModifiedDate']

        if 'impact' in cve_json.keys():
            self.impact(cve_json['impact'])

    def impact(self, impact_data):
        cvss = None
        if 'baseMetricV3' in impact_data.keys():
            cvss = impact_data['baseMetricV3']['cvssV3']    
        elif 'baseMetricV2' in impact_data.keys():
            cvss = impact_data['baseMetricV2']['cvssV2']
        else:
            return
        self.cvss_score = cvss['baseScore']
        self.cvss_vector = cvss['vectorString']
        self.cvss_version = cvss['version']
        if 'baseSeverity' in cvss.keys():
            self.cvss_severity = cvss['baseSeverity']


    def get_description(self, description_data):
        for description in description_data:
            if description['lang'] == 'en':
                return description['value']
        else:
            return "No EN Description"
