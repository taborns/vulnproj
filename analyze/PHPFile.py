import sys
from phplex import lexer
from phpparse import make_parser
from analyze.scanner import Scanner
from analyze.printer import Printer
import simplejson

class PHPFile:
    def __init__(self, file_name):
        self.file_name = file_name
        self.parser = make_parser()
        self.with_lineno = True

        self.vulnTree = self.getScanner()

    def export(self, items):
        result = []
        if items:
            for item in items:
                if hasattr(item, 'generic'):
                    item = item.generic(with_lineno=self.with_lineno)
                result.append(item)
        return result

    def getScanner(self):
        try:
            with open(self.file_name, "r") as f:
                input_file = f.read()
                input_file.replace('<?xml version="1.0" encoding="iso-8859-1"?>', '')
                tokens = self.export(self.parser.parse(input_file,
                                                    lexer=lexer.clone(),tracking=self.with_lineno))

                output = sys.stdout

                # simplejson.dump(tokens,output, indent=2)
                # output.write('\n')
                    
                scanner = Scanner(tokens, file_name=self.file_name)
                return scanner.scan()
        except (RuntimeError, SyntaxError) as e:
            scanner = Scanner([], file_name=self.file_name)
            return scanner.scan()
    
    
    def handle(self):
        Printer(self.vulnTree)
