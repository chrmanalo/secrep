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
