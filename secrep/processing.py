import numpy as np
import pandas as pd

from secrep.constants import HtmlCharacterConstants

const_html = HtmlCharacterConstants()

def to_OX(col, reverse=False):
    if reverse:
        condlist = [col == const_html.symbol.CIRCLE, col == const_html.symbol.CROSS, col == const_html.symbol.DASH]
        choicelist = ['TRUE', 'FALSE', '—']
        return np.select(condlist, choicelist)

    condlist = [col == True, col == False]
    choicelist = [const_html.symbol.CIRCLE, const_html.symbol.CROSS]

    return np.select(condlist, choicelist)

def query_patches(data, config, fix=''):
    OFM = config.col_value.ofm
    UFM = config.col_value.ufm
    OFR = config.col_value.ofr
    UFR = config.col_value.ufr
    if fix == 'Mandatory':
        return data.query('`Fix Policy` == @OFM or `Fix Policy` == @UFM')
    elif fix == 'Recommended':
        return data.query('`Fix Policy` == @OFR or `Fix Policy` == @UFR')
    return data.query('`Fix Policy` == @OFM or `Fix Policy` == @UFM or `Fix Policy` == @OFR or `Fix Policy` == @UFR')

def patch(config):
    print('Getting patch details...')

    # Blackduck dataframe
    bd = pd.read_excel(config.blackduck.path, sheet_name=config.blackduck.sheet,
        usecols=[config.blackduck.col_name[key] for key in config.blackduck.col_name]
    )

    # Security Issues dataframe
    si = pd.read_excel(config.scrape.xlsx)

    # Patch Items dataframe
    pi = si.copy()
    for key in config.patch_items.col_name:
        pi[config.patch_items.col_name[key]] = ''
    
    # # Summary
    # pi[config.patch_items.col_name.summary] = si[config.issues.col_name.vuln_desc]

    # Component Name
    pi[config.issues.col_name.comp_name] = si[config.issues.col_name.comp_name]

    # Component's Affected Version
    pi[config.issues.col_name.comp_version] = si[config.issues.col_name.comp_version]

    pi = pi.sort_values(by=config.issues.col_name.cvss_score, ascending=False)
    pi.index = np.arange(1, len(pi) + 1)

    # Component's Latest Version
    for key in config.comp_versions.keys():
        pi.loc[pi[config.issues.col_name.comp_name] == key, config.patch_items.col_name.latest_version] = config.comp_versions[key]
    
    # Internet Exposure Description
    pi.loc[pi[config.issues.col_name.ie] == const_html.symbol.CIRCLE, config.patch_items.col_name.ie_desc] = 'According to NVD, its Attack Vector is Network (AV:N).'
    pi.loc[pi[config.issues.col_name.ie] != const_html.symbol.CIRCLE, config.patch_items.col_name.ie_desc] = const_html.symbol.DASH

    # Impacted OSS
    # pi[config.detailed_report.col_name.impacted_oss_text] = f'{pi[config.issues.col_name.comp_name]} {pi[config.issues.col_name.comp_version]}'
    pi[config.detailed_report.col_name.impacted_oss_text] = pi[config.issues.col_name.comp_name] + ' ' + pi[config.issues.col_name.comp_version]
    
    # Official Fix Description
    pi.loc[pi[config.issues.col_name.ofa] == const_html.symbol.CIRCLE, config.patch_items.col_name.of_desc] = 'Upgrade ' + pi[config.issues.col_name.comp_name] + f' to the latest version ('+ pi[config.patch_items.col_name.latest_version] +').'
    pi.loc[pi[config.issues.col_name.ofa] != const_html.symbol.CIRCLE, config.patch_items.col_name.of_desc] = const_html.symbol.DASH
    
    # Unofficial Fix Description
    pi.loc[
        (pi[config.issues.col_name.ufa] == const_html.symbol.CIRCLE) &
        (pi[config.issues.col_name.ofa] != const_html.symbol.CIRCLE),
        config.patch_items.col_name.uf_desc] = 'Workaround is available.'
    pi.loc[
        (pi[config.issues.col_name.ufa] != const_html.symbol.CIRCLE) |
        (pi[config.issues.col_name.ofa] == const_html.symbol.CIRCLE),
        config.patch_items.col_name.uf_desc] = const_html.symbol.DASH

    # Only get rows with mandatory and recommended patch items
    # pi = query_patches(pi, config)

    print(pi)
    pi.to_excel(config.patch.xlsx)
