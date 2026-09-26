"""Bounded in-memory XLSX writing. Source selection and permissions live upstream."""
from datetime import date,datetime,timezone
from io import BytesIO
import math
import re
import time
from zipfile import ZipFile,ZIP_DEFLATED

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment,Font,PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.writer.excel import ExcelWriter
from openpyxl.worksheet._writer import WorksheetWriter
from openpyxl.drawing.spreadsheet_drawing import SpreadsheetDrawing

INVALID_XML_UNICODE = re.compile('[\ud800-\udfff\ufffe\uffff]')


class _MemoryExcelWriter(ExcelWriter):
    """Pinned openpyxl 3.1.5 adapter: keep worksheet XML off the filesystem."""

    def write_worksheet(self,ws):
        ws._drawing = SpreadsheetDrawing()
        ws._drawing.charts = ws._charts
        ws._drawing.images = ws._images
        with BytesIO() as xml:
            writer = WorksheetWriter(ws,out=xml)
            try:
                writer.write()
                ws._rels = writer._rels
                self._archive.writestr(ws.path[1:],xml.getvalue())
                self.manifest.append(ws)
            finally:
                writer.close()

MAX_ROWS = 50_000
MAX_CELLS = 500_000
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_SECONDS = 20


class ExportLimit(ValueError):
    pass


def workbook_bytes(sheets):
    """Write all supplied rows or fail explicitly; never return a partial book."""
    started = time.monotonic()
    book = Workbook()
    book.remove(book.active)
    rows_seen = cells_seen = text_bytes = 0
    titles = set()
    try:
        for title,headers,rows in sheets:
            if (not isinstance(title,str) or not title or len(title)>31
                    or title.casefold() in titles or re.search(r'[\\*?:/\[\]]',title)
                    or INVALID_XML_UNICODE.search(title) or ILLEGAL_CHARACTERS_RE.search(title)):
                raise ExportLimit('Некорректное название листа экспорта')
            titles.add(title.casefold())
            if not headers or len(headers)>128 or any(not isinstance(h,str) or not h for h in headers):
                raise ExportLimit('Количество колонок превышает бюджет экспорта')
            sheet = book.create_sheet(title)
            sheet.freeze_panes = 'A2'
            def append(values,header=False):
                nonlocal rows_seen,cells_seen,text_bytes
                rows_seen += 1
                cells_seen += len(values)
                if rows_seen>MAX_ROWS or cells_seen>MAX_CELLS or time.monotonic()-started>MAX_SECONDS:
                    raise ExportLimit('Выборка превышает бюджет Excel. Сузьте охват экспорта')
                if len(values)!=len(headers):
                    raise ExportLimit('Некорректная структура строки экспорта')
                number = sheet.max_row+1 if sheet.max_row>1 or sheet['A1'].value is not None else 1
                for column,value in enumerate(values,1):
                    if isinstance(value,str):
                        if INVALID_XML_UNICODE.search(value):
                            raise ExportLimit('Поле содержит недопустимый символ Unicode')
                        value = ILLEGAL_CHARACTERS_RE.sub('',value)
                        if len(value)>32767:
                            raise ExportLimit('Текст поля превышает предел Excel; файл не усечён')
                        text_bytes += len(value.encode('utf-8'))
                        if text_bytes>MAX_TEXT_BYTES:
                            raise ExportLimit('Текстовые данные превышают бюджет Excel. Сузьте охват')
                    elif isinstance(value,datetime):
                        value = value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
                    elif value is not None and not isinstance(value,(date,int,float,bool)):
                        raise ExportLimit('Неподдерживаемый тип поля экспорта')
                    if isinstance(value,float) and not math.isfinite(value):
                        raise ExportLimit('Некорректное числовое значение экспорта')
                    cell = sheet.cell(number,column,value)
                    if isinstance(value,str):
                        cell.data_type = 's'  # Overrides openpyxl's leading '=' formula inference.
                        cell.number_format = '@'
                    elif isinstance(value,datetime):
                        cell.number_format = 'yyyy-mm-dd hh:mm:ss'
                    elif isinstance(value,date):
                        cell.number_format = 'yyyy-mm-dd'
                    cell.alignment = Alignment(vertical='top',wrap_text=True)
                    if header:
                        cell.font = Font(name='Calibri',bold=True,color='FFFFFF')
                        cell.fill = PatternFill('solid',fgColor='264653')
                if header:
                    sheet.row_dimensions[number].height = 28
            append(headers,header=True)
            for row in rows:
                append(row)
            sheet.auto_filter.ref = f'A1:{get_column_letter(len(headers))}{sheet.max_row}'
            for column,label in enumerate(headers,1):
                sheet.column_dimensions[get_column_letter(column)].width = min(48,max(16,len(str(label))+3))
        if not titles:
            raise ExportLimit('Не заданы листы экспорта')
        output = BytesIO()
        with ZipFile(output,'w',ZIP_DEFLATED,allowZip64=True) as archive:
            _MemoryExcelWriter(book,archive).write_data()
        if output.tell()>MAX_FILE_BYTES or time.monotonic()-started>MAX_SECONDS:
            raise ExportLimit('Файл превышает бюджет Excel. Сузьте охват экспорта')
        return output.getvalue()
    finally:
        book.close()
