from dataclasses import dataclass

@dataclass
class HtmlCharacters:
    CIRCLE: str
    CROSS: str
    DASH: str

@dataclass
class HtmlCharacterConstants:
    symbol: HtmlCharacters = HtmlCharacters(CIRCLE='〇', CROSS='✕', DASH='—')
    code: HtmlCharacters = HtmlCharacters(CIRCLE='&#9675;', CROSS='&#9747;', DASH='&#8212;')

@dataclass
class BlackDuckColumnNameConstants:
    VULN_ID: str = '脆弱性ID'
    VULN_DESC: str = '説明'
    COMP_NAME: str = 'コンポーネント名'
    COMP_VERSION: str = 'コンポーネントバージョン名'
    CVSS_VERSION: str = 'CVSSバージョン'
    CVSS_SCORE: str = '総合スコア'
    URL: str = 'URL'
    SECURITY_RISK: str = 'セキュリティ上のリスク'
    SOLUTION_AVAILABLE: str = 'ソリューションが利用可能'
    WORKAROUND_AVAILABLE: str = '回避策が利用可能'
