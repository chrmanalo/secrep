from bs4 import BeautifulSoup
import numpy as np
import pandas as pd
import regex as re
import requests

from secrep.constants import HtmlCharacterConstants
from secrep.processing import to_OX

const_html = HtmlCharacterConstants()

def scrape_nvd(row, config):
    print('Scraping...')
    row[config.issues.col_name.cvss_version] = re.sub(r'(CVSS\s)([2,3].(?:0|x))', r'\2', row[config.issues.col_name.cvss_version])
    
    if row[config.issues.col_name.cve_id] == const_html.symbol.DASH:
        row[config.issues.col_name.ie] = const_html.symbol.DASH
        return row

    url = 'https://nvd.nist.gov/vuln/detail/' + row[config.issues.col_name.cve_id]
    headers = requests.utils.default_headers()
    headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36'
    print(f'Scraping {url}...')
    response = requests.get(url, proxies=config.proxies, verify=False, headers=headers) if config.enable_proxy else requests.get(url, verify=False, headers=headers)
    soup = BeautifulSoup(response.content, 'html.parser')

    if row[config.issues.col_name.cvss_version] == '2.0':
        cvss2_vector = None
        try:
            cvss2_vector_elem = soup.find('span', attrs={'data-testid': 'vuln-cvss2-panel-vector'})
            cvss2_vector = cvss2_vector_elem.get_text()
        except AttributeError:
            row[config.issues.col_name.ie] = const_html.symbol.DASH
            return row
        groups = re.search(r'(\(AV:)(.)(.*)', cvss2_vector)
        row[config.issues.col_name.ie] = const_html.symbol.CIRCLE if groups.group(2) == 'N' else const_html.symbol.CROSS
        return row
    elif row[config.issues.col_name.cvss_version] == '3.x':
        cvss3_vector = None
        try:
            cvss3_vector_elem = soup.find('span', attrs={'data-testid': 'vuln-cvss3-nist-vector'})
            if cvss3_vector_elem is None:
                cvss3_vector_elem = soup.find('span', attrs={'data-testid': 'vuln-cvss3-cna-vector'})
            cvss3_vector = cvss3_vector_elem.get_text()
        except AttributeError:
            row[config.issues.col_name.ie] = const_html.symbol.DASH
            return row
        groups = re.search(r'(CVSS:)(.{3})(/AV:)(.)(.*)', cvss3_vector)
        row[config.issues.col_name.cvss_version] = groups.group(2)
        row[config.issues.col_name.ie] = const_html.symbol.CIRCLE if groups.group(4) == 'N' else const_html.symbol.CROSS
    
    return row

def scrape(config):
    # Blackduck dataframe and drop duplicates
    bd = pd.read_excel(config.blackduck.path, sheet_name=config.blackduck.sheet,
        usecols=[config.blackduck.col_name[key] for key in config.blackduck.col_name]
    ).drop_duplicates('脆弱性ID')
    # Security Issues dataframe
    si = pd.DataFrame(columns=[config.issues.col_name[key] for key in config.issues.col_name if config.issues.col_name[key] != config.issues.col_name.cvss_score_color])

    # VULN ID
    si[config.issues.col_name.vuln_id] = bd[config.blackduck.col_name.vuln_id].copy()

    # VULN DESC
    si[config.issues.col_name.vuln_desc] = bd[config.blackduck.col_name.vuln_desc].copy()

    # COMP NAME
    si[config.issues.col_name.comp_name] = bd[config.blackduck.col_name.comp_name].copy()

    # COMP Version
    si[config.issues.col_name.comp_version] = bd[config.blackduck.col_name.comp_version].copy()

    # BDSA ID
    si[config.issues.col_name.bdsa_id] = bd[config.blackduck.col_name.vuln_id].copy()
    si[config.issues.col_name.bdsa_id] = si[config.issues.col_name.bdsa_id].replace(to_replace=r'(BDSA-\d{4}-\d{4,})(\s\()(CVE-\d{4}-\d{4,})(\))', value=r'\1', regex=True)
    si[config.issues.col_name.bdsa_id] = si[config.issues.col_name.bdsa_id].str.replace(r'CVE-\d{4}-\d{4,}', const_html.symbol.DASH, regex=True)
    
    # CVE ID
    si[config.issues.col_name.cve_id] = bd[config.blackduck.col_name.vuln_id].copy()
    si[config.issues.col_name.cve_id] = si[config.issues.col_name.cve_id].replace(to_replace=r'(BDSA-\d{4}-\d{4,})(\s\()(CVE-\d{4}-\d{4,})(\))', value=r'\3', regex=True)
    si[config.issues.col_name.cve_id] = si[config.issues.col_name.cve_id].str.replace(r'BDSA-\d{4}-\d{4,}', const_html.symbol.DASH, regex=True)

    # CVSS URL
    si[config.issues.col_name.cvss_url] = bd[config.blackduck.col_name.url].copy()

    # CVSS Version and Internet Exposure
    si[config.issues.col_name.cvss_version] = bd[config.blackduck.col_name.cvss_version].copy()
    si = si.apply(lambda row: scrape_nvd(row, config), axis=1)

    # CVSS Score
    si[config.issues.col_name.cvss_score] = bd[config.blackduck.col_name.cvss_score].copy()

    # Severity
    si[config.issues.col_name.severity] = bd[config.blackduck.col_name.security_risk].copy().str.title()

    # Official Fix Available
    si[config.issues.col_name.ofa] = bd[config.blackduck.col_name.solution_available].copy()
    si[config.issues.col_name.ofa] = to_OX(si[config.issues.col_name.ofa])
    
    # Unofficial Fix Available
    si[config.issues.col_name.ufa] = bd[config.blackduck.col_name.workaround_available].copy()
    si[config.issues.col_name.ufa] = to_OX(si[config.issues.col_name.ufa])
    si.loc[si[config.issues.col_name.ofa] == const_html.symbol.CIRCLE, config.issues.col_name.ufa] = const_html.symbol.DASH

    # Fix Policy
    fix_policies = [
        # Critical/High
        (
            [config.col_value.critical, config.col_value.high],
            [const_html.symbol.CIRCLE],
            const_html.symbol.CIRCLE,
            const_html.symbol.DASH,
            config.col_value.ofm
        ),
        (
            [config.col_value.critical, config.col_value.high],
            [const_html.symbol.CIRCLE],
            const_html.symbol.CROSS,
            const_html.symbol.CIRCLE,
            config.col_value.ufm
        ),
        (
            [config.col_value.critical, config.col_value.high],
            [const_html.symbol.CIRCLE],
            const_html.symbol.CROSS,
            const_html.symbol.CROSS,
            const_html.symbol.DASH
        ),
        (
            [config.col_value.critical, config.col_value.high],
            [const_html.symbol.CROSS, const_html.symbol.DASH],
            const_html.symbol.CIRCLE,
            const_html.symbol.DASH,
            config.col_value.ofr
        ),
        (
            [config.col_value.critical, config.col_value.high],
            [const_html.symbol.CROSS, const_html.symbol.DASH],
            const_html.symbol.CROSS,
            const_html.symbol.CIRCLE,
            config.col_value.ufr
        ),
        (
            [config.col_value.critical, config.col_value.high],
            [const_html.symbol.CROSS, const_html.symbol.DASH],
            const_html.symbol.CROSS,
            const_html.symbol.CROSS,
            const_html.symbol.DASH
        ),

        # Medium
        (
            [config.col_value.medium],
            [const_html.symbol.CIRCLE],
            const_html.symbol.CIRCLE,
            const_html.symbol.DASH,
            config.col_value.ofr
        ),
        (
            [config.col_value.medium],
            [const_html.symbol.CIRCLE],
            const_html.symbol.CROSS,
            const_html.symbol.CIRCLE,
            config.col_value.ufr
        ),
        (
            [config.col_value.medium],
            [const_html.symbol.CIRCLE],
            const_html.symbol.CROSS,
            const_html.symbol.CROSS,
            const_html.symbol.DASH
        ),
        (
            [config.col_value.medium],
            [const_html.symbol.CROSS, const_html.symbol.DASH],
            const_html.symbol.CIRCLE,
            const_html.symbol.DASH,
            config.col_value.ofo
        ),
        (
            [config.col_value.medium],
            [const_html.symbol.CROSS, const_html.symbol.DASH],
            const_html.symbol.CROSS,
            const_html.symbol.CIRCLE,
            config.col_value.ufo
        ),
        (
            [config.col_value.medium],
            [const_html.symbol.CROSS, const_html.symbol.DASH],
            const_html.symbol.CROSS,
            const_html.symbol.CROSS,
            const_html.symbol.DASH
        ),

        # Low
        (
            [config.col_value.low],
            [const_html.symbol.CIRCLE],
            const_html.symbol.CIRCLE,
            const_html.symbol.DASH,
            config.col_value.ofo
        ),
        (
            [config.col_value.low],
            [const_html.symbol.CIRCLE],
            const_html.symbol.CROSS,
            const_html.symbol.CIRCLE,
            config.col_value.ufo
        ),
        (
            [config.col_value.low],
            [const_html.symbol.CIRCLE],
            const_html.symbol.CROSS,
            const_html.symbol.CROSS,
            const_html.symbol.DASH
        ),
        (
            [config.col_value.low],
            [const_html.symbol.CROSS, const_html.symbol.DASH],
            const_html.symbol.CIRCLE,
            const_html.symbol.DASH,
            config.col_value.ofo
        ),
        (
            [config.col_value.low],
            [const_html.symbol.CROSS, const_html.symbol.DASH],
            const_html.symbol.CROSS,
            const_html.symbol.CIRCLE,
            config.col_value.ufo
        ),
        (
            [config.col_value.low],
            [const_html.symbol.CROSS, const_html.symbol.DASH],
            const_html.symbol.CROSS,
            const_html.symbol.CROSS,
            const_html.symbol.DASH
        )
    ]
    for policy in fix_policies:
        si.loc[si[config.issues.col_name.severity].isin(pd.Series(policy[0])) &
            si[config.issues.col_name.ie].isin(pd.Series(policy[1])) &
            (si[config.issues.col_name.ofa] == policy[2]) &
            (si[config.issues.col_name.ufa] == policy[3]), config.issues.col_name.fix_policy] = policy[4]

    # Start index with 1
    si.index = np.arange(1, len(si) + 1)

    print(si)
    si.to_excel(config.scrape.xlsx)