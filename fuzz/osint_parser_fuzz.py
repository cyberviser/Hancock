#!/usr/bin/env python3
import atheris
import sys
from collectors.osint_report_parser import OSINTReportParser

@atheris.instrument_func
def test_fuzz_parser(data):
    fdp = atheris.FuzzedDataProvider(data)
    fake_text = fdp.ConsumeUnicodeNoSurrogates(4096)
    parser = OSINTReportParser()
    parser._extract_finding_block(fake_text, 0)

if __name__ == "__main__":
    atheris.Setup(sys.argv, test_fuzz_parser)
    atheris.Fuzz()
