from jinja2 import Environment, FileSystemLoader
import pandas as pd

def check_if(x, cond=None, ignore_solution=True):
    check_solution = False
    if not ignore_solution:
        check_solution = x['ソリューションが利用可能'] == True
    if cond == 'Critical':
        return True if x['CVSSバージョン'] == 'CVSS 3.x' and 9.0 <= x['総合スコア'] <= 10.0 and (ignore_solution or check_solution) else False
    elif cond == 'High':
        return True if ((x['CVSSバージョン'] == 'CVSS 2.0' and 7.0 <= x['総合スコア'] <= 10.0) or (x['CVSSバージョン'] == 'CVSS 3.x' and 7.0 <= x['総合スコア'] <= 8.9)) and (ignore_solution or check_solution) else False
    elif cond == 'Med':
        return True if 4.0 <= x['総合スコア'] <= 6.9 and (ignore_solution or check_solution) else False
    elif cond == 'Low':
        return True if ((x['CVSSバージョン'] == 'CVSS 2.0' and 0.0 <= x['総合スコア'] <= 3.9) or (x['CVSSバージョン'] == 'CVSS 3.x' and 0.1 <= x['総合スコア'] <= 3.9)) and (ignore_solution or check_solution) else False
    else:
        pass
    return True if (ignore_solution or check_solution) else False

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
                'CVSSバージョン' # CVSS Version
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
    write_to_file(config, summary_reports, file_type='html')
    write_to_file(config, summary_reports, file_type='xlsx')
    

def write_to_file(config, data, file_type='html'):
    if file_type == 'html':
        data_dict = data.to_dict('index')
        environment = Environment(extensions=['jinja2.ext.loopcontrols'], loader=FileSystemLoader('templates/'))
        template = environment.get_template(config['summary_report']['template'])
        filepath = config['summary_report']['html']
        with open(filepath, 'w') as file:
            file.write(template.render(rows=data_dict))
    elif file_type == 'xlsx':
        filepath = config['summary_report']['xlsx']
        data.to_excel(filepath)
    else:
        pass
    print(f'Data is written to {filepath}')

def generate_detailed_report(config):
    print('Generating detailed report...')
    # Write the detailed report
    pass