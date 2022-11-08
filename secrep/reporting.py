from datetime import date
from jinja2 import Environment, FileSystemLoader
import numpy as np
import operator as op
import pandas as pd

from secrep.constants import HtmlCharacterConstants, BlackDuckColumnNameConstants
from secrep.processing import to_OX

const_html = HtmlCharacterConstants()
const_blackduck_colname = BlackDuckColumnNameConstants()

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
        # row.index = range(1, row.shape[0] + 1) 
        # row['#'] = row.index
        # cve_id_column_width = max(row['CVE ID'].astype(str).map(len).max(), len('CVE ID'))

        # read the BlackDuck Excel file and drop duplicate vulnerability IDs
        print(f'reading: {row["input_file"]}')
        blackduck_df = pd.read_excel(row['input_file'], sheet_name='security',
            usecols=[
                const_blackduck_colname.COMP_NAME,
                const_blackduck_colname.COMP_VERSION,
                '脆弱性ID', # Vulnerability ID
                '総合スコア', # Overall Score
                'ソリューションが利用可能', # Solution Available  
                'CVSSバージョン', # CVSS Version,
                'セキュリティ上のリスク' # BDSA Severity
            ]
        ).drop_duplicates(subset=[const_blackduck_colname.VULN_ID, const_blackduck_colname.COMP_NAME, const_blackduck_colname.COMP_VERSION])

        new_row = pd.DataFrame(data={
            '#': index + 1,
            # 'OSS Container': f"{row['name']} {row['version']}" if 'suffix' not in row else f"{row['name']} {row['version']} {row['suffix']}",
            'OSS Container': f"{row['name']} {row['version']}" if row['suffix'] is np.nan else f"{row['name']} {row['version']} {row['suffix']}",
            'Release': date.today().strftime('%Y/%m/%d'),
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

    # writer = pd.ExcelWriter(config.report.xlsx)
    writer = pd.ExcelWriter(config['summary_report']['xlsx'], engine='xlsxwriter')
    summary_reports.to_excel(writer, sheet_name='OSS Containers', index=False, na_rep='NaN', startrow=1, startcol=1)

    workbook  = writer.book
    worksheet = writer.sheets['OSS Containers']
    worksheet.hide_gridlines(option=2)

    # Auto-adjust column width
    worksheet.set_column(0, 0, 2.5)
    for column in summary_reports:
        col_idx = summary_reports.columns.get_loc(column)
        column_width = max(summary_reports[column].astype(str).map(len).max(), len(column))
        worksheet.set_column(col_idx + 1, col_idx + 1, column_width)
    border_format = workbook.add_format({'border': 1})
    worksheet.conditional_format(f'B2:I{summary_reports.shape[0]+2}', {
        'type': 'no_blanks',
        'format': border_format})
    header_format = workbook.add_format({'bg_color': '#95B3D7'})
    worksheet.conditional_format('B2:D2', {
        'type': 'no_blanks',
        'format': header_format
    })
    worksheet.conditional_format('I2', {
        'type': 'no_blanks',
        'format': header_format
    })
    header_crit_format = workbook.add_format({'bg_color': '#ff0000'})
    worksheet.conditional_format('E2', {'type': 'cell', 'criteria': 'equal to', 'value': '"Critical"', 'format': header_crit_format})
    header_high_format = workbook.add_format({'bg_color': '#ff7500'})
    worksheet.conditional_format('F2', {'type': 'cell', 'criteria': 'equal to', 'value': '"High"', 'format': header_high_format})
    header_med_format = workbook.add_format({'bg_color': '#cdff00'})
    worksheet.conditional_format('G2', {'type': 'cell', 'criteria': 'equal to', 'value': '"Med"', 'format': header_med_format})
    header_low_format = workbook.add_format({'bg_color': '#6afcb5'})
    worksheet.conditional_format('H2', {'type': 'cell', 'criteria': 'equal to', 'value': '"Low"', 'format': header_low_format})

    workbook.close()

    # write_to_file(config['summary_report']['xlsx'], summary_reports, file_type='xlsx')
    

def write_to_file(filepath, data, file_type='html'):
    if file_type == 'html':
        with open(filepath, 'w') as file:
            file.write(data)
    elif file_type == 'xlsx':
        data.to_excel(filepath)
    else:
        pass
    print(f'Data is written to {filepath}')

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

def wrap_hyperlink(text, link):
    return f'<a href="{link}">{text}</a>'

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
    # pi = merge_fix_cols(si, pi, config.issues.col_name.vuln_id)

    pi.loc[pi[config.issues.col_name.cve_id] == config.col_value.dash, config.issues.col_name.cve_id] = DASH
    pi.loc[pi[config.issues.col_name.bdsa_id] == config.col_value.dash, config.issues.col_name.bdsa_id] = DASH
    # pi[config.issues.col_name.ie] = to_OX(si[config.issues.col_name.ie], reverse=True)
    # pi[config.issues.col_name.ofa] = to_OX(si[config.issues.col_name.ofa], reverse=True)
    # pi[config.patch_items.col_name.impact] = ''
    pi['#'] = ''

    pi = pi[[
        '#', # Index
        config.issues.col_name.cve_id, # 'CVE ID'
        config.issues.col_name.bdsa_id, # 'BDSA ID'
        # config.issues.col_name.cvss_url, # 'URL'
        config.issues.col_name.vuln_desc, # 'Vulnerability Description'
        config.issues.col_name.cvss_version, # 'CVSS Version'
        config.issues.col_name.cvss_score, # 'CVSS Score'
        config.issues.col_name.severity, # 'BDSA Severity'
        config.issues.col_name.ie, # 'Internet Exposure'
        config.detailed_report.col_name.impacted_oss_text, # 'Impacted OSS'
        config.patch_items.col_name.of_desc # 'Official Fix Description'
    ]]
    
    pi = pi.rename(columns={
        'Vulnerability Description': 'Summary of Vulnerability',
        'CVSS Score': 'Overall Score',
        # 'Internet Exposure Description': 'Internet Exposure',
        'Official Fix Description': 'Fix Information'
    })

    pi = pi.sort_values(by='Overall Score', ascending=False)
    pi.index = range(1, pi.shape[0] + 1) 
    pi['#'] = pi.index
    cve_id_column_width = max(pi['CVE ID'].astype(str).map(len).max(), len('CVE ID'))
    pi['CVE ID'] = pi['CVE ID'].apply(lambda x: make_hyperlink(x))

    # convert config file's OSS list to dict
    # oss_list_dict = {index: file for index, file in enumerate(config['oss_list'])}
    oss_list_dict = {0: config}
    
    # convert oss_list_dict to a DataFrame
    oss_list_df = pd.DataFrame.from_dict(oss_list_dict, orient='index')
    print(oss_list_dict)
    print(oss_list_df)

    # sort files by name
    # oss_list_df = oss_list_df.sort_values(by=['name'], ignore_index=True)

    # create a DataFrame of summary reports
    summary_reports = pd.DataFrame()
    for index, row in oss_list_df.iterrows():
        print(f'row {row}')
        # read the BlackDuck Excel file and drop duplicate vulnerability IDs
        blackduck_df = pd.read_excel(row['blackduck']['path'], sheet_name='security',
            usecols=[
                const_blackduck_colname.COMP_NAME,
                const_blackduck_colname.COMP_VERSION,
                '脆弱性ID', # Vulnerability ID
                '総合スコア', # Overall Score
                'ソリューションが利用可能', # Solution Available  
                'CVSSバージョン', # CVSS Version,
                'セキュリティ上のリスク' # BDSA Severity
            ]
        ).drop_duplicates(subset=[const_blackduck_colname.VULN_ID, const_blackduck_colname.COMP_NAME, const_blackduck_colname.COMP_VERSION])
        
        text = f"{row['oss_name']} {row['oss_version']}"

        new_row = pd.DataFrame(data={
            'OSS Container': wrap_hyperlink(text, config.report.url),
            'Release': date.today().strftime('%Y/%m/%d'),
            'Critical': count_items(blackduck_df, cond='Critical'),
            'High': count_items(blackduck_df, cond='High'),
            'Med': count_items(blackduck_df, cond='Med'),
            'Low': count_items(blackduck_df, cond='Low'),
            'Total': count_items(blackduck_df)
        }, index=[index + 1])
        summary_reports = pd.concat([summary_reports, new_row])
    print(summary_reports)

    data_dict = summary_reports.to_dict('index')
    environment = Environment(extensions=['jinja2.ext.loopcontrols'], loader=FileSystemLoader('templates/'))
    template = environment.get_template(config['template'])
    content = template.render(rows=data_dict, config=config)
    write_to_file(config.report.html, content, file_type='html')

    # writer = pd.ExcelWriter(config.report.xlsx)
    writer = pd.ExcelWriter(config.report.xlsx, engine='xlsxwriter')
    pi.to_excel(writer, sheet_name='Vulnerabilities', index=False, na_rep='NaN', startrow=1, startcol=1)

    workbook  = writer.book
    worksheet = writer.sheets['Vulnerabilities']
    worksheet.hide_gridlines(option=2)

    # Auto-adjust column width
    worksheet.set_column(0, 0, 2.5)
    for column in pi:
        col_idx = pi.columns.get_loc(column)
        print(col_idx)
        if column == 'CVE ID':
            column_width = cve_id_column_width
            # worksheet.set_column(col_idx, col_idx, column_width, workbook.get_default_url_format())
            # continue
        elif column == 'Summary of Vulnerability':
            column_width = 50
        else:
            column_width = max(pi[column].astype(str).map(len).max(), len(column))
        
        worksheet.set_column(col_idx + 1, col_idx + 1, column_width)
    worksheet.conditional_format(f'C3:C{pi.shape[0]+1}', {
        'type': 'text',
        'criteria': 'not containing',
        'value': const_html.symbol.DASH,
        'format': workbook.get_default_url_format()})
    border_format = workbook.add_format({'border': 1})
    worksheet.conditional_format(f'B2:K{pi.shape[0]+2}', {
        'type': 'no_blanks',
        'format': border_format})
    header_format = workbook.add_format({'bg_color': '#95B3D7'})
    worksheet.conditional_format('B2:K2', {
        'type': 'no_blanks',
        'format': header_format
    })

    # # color is based on overall score
    # cvss_score_color_dict = {
    #     '0': '#00c400',
    #     '1': '#00e020',
    #     '2': '#00f000',
    #     '3': '#d1ff00',
    #     '4': '#ffe000',
    #     '5': '#ffcc00',
    #     '6': '#ffbc10',
    #     '7': '#ff9c20',
    #     '8': '#ff8000',
    #     '9': '#ff0000'
    # }
    # cvss_score_formats = {score_bin: workbook.add_format({'bg_color': color}) for score_bin, color in cvss_score_color_dict.items()}
    # for score_bin, format in cvss_score_formats.items():
    #     score_value = str(int(score_bin) + 1)
    #     print(score_value)
    #     worksheet.conditional_format(f'G3:G{pi.shape[0]+2}', {'type': 'cell', 'criteria': '<', 'value': score_value, 'format': format})
    
    # color is based on severity
    severity_color_dict = {
        'Critical': '#ff0000',
        'High': '#ff7500',
        'Medium': '#cdff00',
        'Low': '#6afcb5'
    }
    severity_format_dict = {severity: workbook.add_format({'bg_color': color}) for severity, color in severity_color_dict.items()}
    for severity, format in severity_format_dict.items():
        worksheet.conditional_format(f'H3:H{pi.shape[0]+2}', {'type': 'cell', 'criteria': '==', 'value': f'"{severity}"', 'format': format})

    # for score_bin, format in cvss_score_formats.items():
    #     score_value = str(int(score_bin) + 1)
    #     print(score_value)
    #     worksheet.conditional_format(f'G3:G{pi.shape[0]+2}', {'type': 'cell', 'criteria': '==', f'"{}"': score_value, 'format': format})

    # header_crit_format = workbook.add_format({'bg_color': '#ff0000'})
    # worksheet.conditional_format('E2', {'type': 'cell', 'criteria': 'equal to', 'value': '"Critical"', 'format': header_crit_format})
    # header_high_format = workbook.add_format({'bg_color': '#ff7500'})
    # worksheet.conditional_format('F2', {'type': 'cell', 'criteria': 'equal to', 'value': '"High"', 'format': header_high_format})
    # header_med_format = workbook.add_format({'bg_color': '#cdff00'})
    # worksheet.conditional_format('G2', {'type': 'cell', 'criteria': 'equal to', 'value': '"Med"', 'format': header_med_format})
    # header_low_format = workbook.add_format({'bg_color': '#6afcb5'})
    # worksheet.conditional_format('H2', {'type': 'cell', 'criteria': 'equal to', 'value': '"Low"', 'format': header_low_format})

    workbook.close()

    # write_to_file(config.report.xlsx, pi, file_type='xlsx')

def make_hyperlink(value):
    url = f'https://nvd.nist.gov/vuln/detail/{value}'
    return f'=HYPERLINK("{url.format(value)}", "{value}")' if value != const_html.symbol.DASH else const_html.symbol.DASH

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