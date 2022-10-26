from turtle import home
from jinja2 import Environment, FileSystemLoader
import numpy as np
import operator as op
import pandas as pd

from secrep.processing import to_OX

CIRCLE = '&#9675;'
CROSS = '&#9747;'
DASH = '—'

def check_if(x, cond=None, ignore_solution=True):
    check_solution = False
    if not ignore_solution:
        check_solution = x['ソリューションが利用可能'] == True

    if cond is not None:
        cond_map = {
            'Critical': 'CRITICAL',
            'High': 'HIGH',
            'Med': 'MEDIUM',
            'Low': 'LOW'
        }
        return True if x['セキュリティ上のリスク'] == cond_map[cond] and (ignore_solution or check_solution) else False

    return True if ignore_solution or check_solution else False

def count_items(df, cond=None):
    items = df.apply(lambda x: check_if(x, cond), axis=1)
    num_items = len(items[items == True].index)

    items_with_solutions = df.apply(lambda x: check_if(x, cond, ignore_solution=False), axis=1)
    num_items_with_solutions = len(items_with_solutions[items_with_solutions == True].index)

    return f'{num_items}({num_items_with_solutions})'

def generate_summary_report(config):
    print('Generating summary report...')

    # convert config file's OSS list to dict
    oss_list_dict = {index: file for index, file in enumerate(config['oss_list'])}
    
    # convert oss_list_dict to a DataFrame
    oss_list_df = pd.DataFrame.from_dict(oss_list_dict, orient='index')

    # sort files by name
    oss_list_df = oss_list_df.sort_values(by=['name'], ignore_index=True)

    # create a DataFrame of summary reports
    summary_reports = pd.DataFrame()
    for index, row in oss_list_df.iterrows():
        # read the BlackDuck Excel file and drop duplicate vulnerability IDs
        blackduck_df = pd.read_excel(row['input_file'], sheet_name='security',
            usecols=[
                '脆弱性ID', # Vulnerability ID
                '総合スコア', # Overall Score
                'ソリューションが利用可能', # Solution Available  
                'CVSSバージョン', # CVSS Version,
                'セキュリティ上のリスク' # BDSA Severity
            ]
        ).drop_duplicates('脆弱性ID')

        new_row = pd.DataFrame(data={
            'OSS Container': f"{row['name']} {row['version']}",
            'Release': row['release_date'],
            'Critical': count_items(blackduck_df, cond='Critical'),
            'High': count_items(blackduck_df, cond='High'),
            'Med': count_items(blackduck_df, cond='Med'),
            'Low': count_items(blackduck_df, cond='Low'),
            'Total': count_items(blackduck_df)
        }, index=[index + 1])
        summary_reports = pd.concat([summary_reports, new_row])
    print(summary_reports)

    # Write summary report as HTML and XLSX
    data_dict = summary_reports.to_dict('index')
    environment = Environment(extensions=['jinja2.ext.loopcontrols'], loader=FileSystemLoader('templates/'))
    template = environment.get_template(config['summary_report']['template'])
    content = template.render(rows=data_dict)
    write_to_file(config['summary_report']['html'], content, file_type='html')
    write_to_file(config['summary_report']['xlsx'], summary_reports, file_type='xlsx')
    

def write_to_file(filepath, data, file_type='html'):
    if file_type == 'html':
        with open(filepath, 'w') as file:
            file.write(data)
    elif file_type == 'xlsx':
        data.to_excel(filepath)
    else:
        pass
    print(f'Data is written to {filepath}')

# def generate_detailed_report(config):
#     print('Generating detailed report...')

#     # read the BlackDuck Excel file and drop duplicate vulnerability IDs
#     blackduck_df = pd.read_excel(config['input_file'], sheet_name='security',
#         usecols=[
#             '脆弱性ID', # Vulnerability ID
#             '説明', # Vulnerability Description
#             'コンポーネント名', # Component Name
#             'URL', # URL
#             'CVSSバージョン', # CVSS Version
#             '総合スコア', # Overall Score
#             'セキュリティ上のリスク', # Security Risk
#             'ソリューションが利用可能' # Solution Available  
#         ]
#     ).drop_duplicates('脆弱性ID')



#     # Write the detailed report
#     pass

def style_cvss_score_color(score):
    N_SCORE_TYPES = 10
    condlist = [op.and_(op.ge(score,i),op.lt(score,i+1)) if i < 9 else op.and_(op.ge(score,i),op.le(score,i+1)) for i in range(N_SCORE_TYPES)]
    choicelist = [i for i in range(N_SCORE_TYPES)]
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

def generate_link(text, url):
    return f'<a href="{url}">{text}</a>' if text != DASH else DASH

def style_cvss_score(score):
    N_SCORE_TYPES = 10
    condlist = [op.and_(op.ge(score,i),op.lt(score,i+1)) if i < 9 else op.and_(op.ge(score,i),op.le(score,i+1)) for i in range(N_SCORE_TYPES)]
    choicelist = [f'<td class="tg-body tg-score cvssScore{i}">' + score.astype(str) + '</td>' for i in range(N_SCORE_TYPES)]
    return np.select(condlist, choicelist)

def style_OXDash(col):
    condlist = [op.eq(col, i) for i in [CIRCLE, CROSS, DASH]]
    choicelist = [
        f'<p class="valueO">{CIRCLE}</p>',
        f'<p class="valueX">{CROSS}</p>',
        f'<p class="valueDash">{DASH}</p>'
    ]
    return np.select(condlist, choicelist)

def style_default(data):
    return '<td class="tg-body">' + data.astype(str) + '</td>'

def generate_detailed_report(config):
    print('Generating security report...')

    # Security Issues dataframe
    si = pd.read_excel(config.scrape.xlsx)
    print(list(si.columns))

    # Patch Items dataframe
    # pi = pd.read_excel(config.patch.xlsx)
    
    # # CVSS Score Color
    # pi[config.issues.col_name.cvss_score_color] = ''
    # pi[config.issues.col_name.cvss_score_color] = style_cvss_score_color(pi[config.issues.col_name.cvss_score])
    
    # ofms = query_patches(pi, config, 'Mandatory')
    # ofrs = query_patches(pi, config, 'Recommended')

    # environment = Environment(extensions=['jinja2.ext.loopcontrols'], loader=FileSystemLoader('templates/'))
    # template = environment.get_template(config.template)

    # filename = 'security_issues.html'

    # si[config.issues.col_name.cve_id] = si.apply(lambda x: generate_link(x[config.issues.col_name.cve_id], x[config.issues.col_name.cvss_url]), axis=1)
    # si[config.issues.col_name.cvss_score] = style_cvss_score(si[config.issues.col_name.cvss_score])
    # si[config.issues.col_name.cvss_version] = '<td class="tg-body tg-version">' + si[config.issues.col_name.cvss_version].astype(str) + '</td>'
    
    # si[config.issues.col_name.ie] = style_OXDash(si[config.issues.col_name.ie])
    # si[config.issues.col_name.ofa] = style_OXDash(si[config.issues.col_name.ofa])
    # si[config.issues.col_name.ufa] = style_OXDash(si[config.issues.col_name.ufa])
    # si[config.issues.col_name.ie] = style_default(si[config.issues.col_name.ie])
    # si[config.issues.col_name.ofa] = style_default(si[config.issues.col_name.ofa])
    # si[config.issues.col_name.ufa] = style_default(si[config.issues.col_name.ufa])

    # si[config.issues.col_name.bdsa_id] = style_default(si[config.issues.col_name.bdsa_id])
    # si[config.issues.col_name.cve_id] = style_default(si[config.issues.col_name.cve_id])
    # si[config.issues.col_name.severity] = style_default(si[config.issues.col_name.severity])
    # si[config.issues.col_name.fix_policy] = style_default(si[config.issues.col_name.fix_policy])
    
    # si = si.sort_values(by=config.issues.col_name.cvss_score, ascending=False)
    # si.index = np.arange(1, len(si) + 1)
    # si_rows = si.to_dict('index')
    # mpi_rows = ofms.to_dict('index')
    # rpi_rows = ofrs.to_dict('index')
    # context = {
    #     'config': config,
    #     'si_rows': si_rows,
    #     'mpi_rows': mpi_rows,
    #     'rpi_rows': rpi_rows
    # }
    
    # content = template.render(**context)
    # write_to_file(config.report.html, content)

    # Patch Items dataframe
    pi = pd.read_excel(config.patch.xlsx)

    # pi = pd.merge(
    #     si,
    #     pi,
    #     how="left",
    #     on='BDSA ID',
    #     left_on=None,
    #     right_on=None,
    #     left_index=False,
    #     right_index=False,
    #     sort=True,
    #     suffixes=("_x", "_y"),
    #     copy=True,
    #     indicator=False,
    #     validate=None
    # )
    pi = merge_fix_cols(si, pi, config.issues.col_name.vuln_id)

    pi.loc[pi[config.issues.col_name.cve_id] == config.col_value.dash, config.issues.col_name.cve_id] = DASH
    pi.loc[pi[config.issues.col_name.bdsa_id] == config.col_value.dash, config.issues.col_name.bdsa_id] = DASH
    pi[config.issues.col_name.ie] = to_OX(si[config.issues.col_name.ie], reverse=True)
    # pi[config.issues.col_name.ofa] = to_OX(si[config.issues.col_name.ofa], reverse=True)
    # pi[config.patch_items.col_name.impact] = ''

    pi = pi[[
        config.issues.col_name.cve_id, # 'CVE ID'
        config.issues.col_name.bdsa_id, # 'BDSA ID'
        config.issues.col_name.cvss_url, # 'URL'
        config.issues.col_name.vuln_desc, # 'Vulnerability Description'
        config.issues.col_name.cvss_version, # 'CVSS Version'
        config.issues.col_name.cvss_score, # 'CVSS Score'
        config.issues.col_name.severity, # 'BDSA Severity'
        config.patch_items.col_name.ie_desc, # 'Internet Exposure Description'
        config.detailed_report.col_name.impacted_oss_text, # 'Impacted OSS'
        config.patch_items.col_name.of_desc # 'Official Fix Description'
    ]]
    
    pi = pi.rename(columns={
        'Vulnerability Description': 'Summary of Vulnerability',
        'CVSS Score': 'Overall Score',
        'Internet Exposure Description': 'Internet Exposure',
        'Official Fix Description': 'Official Fix Available'
    })

    pi = pi.sort_values(by='Overall Score', ascending=False)
    pi.index = range(1, pi.shape[0] + 1) 

    write_to_file(config.report.xlsx, pi, file_type='xlsx')

def merge_fix_cols(df1,df2,uniqueID):
    
    df_merged = pd.merge(df1,
                         df2,
                         how='left',left_on=uniqueID,right_on=uniqueID)    
    for col in df_merged:
        if col.endswith('_x'):
            df_merged.rename(columns = lambda col:col.rstrip('_x'),inplace=True)
        elif col.endswith('_y'):
            to_drop = [col for col in df_merged if col.endswith('_y')]
            df_merged.drop(to_drop,axis=1,inplace=True)
        else:
            pass
    return df_merged