import sys
from phply.phplex import lexer
from phply.phpparse import make_parser
import simplejson

output = sys.stdout
with_lineno = True

def export(items):
    result = []
    if items:
       for item in items:
           if hasattr(item, 'generic'):
               item = item.generic(with_lineno=with_lineno)
           result.append(item)
    return result

parser = make_parser()

file = "browse_form_fills.php"
# file = "test_json.py"
with open(file, "r") as f:
    input_file = f.read()

simplejson.dump(export(parser.parse(input_file,
                                    lexer=lexer,
                                    tracking=with_lineno)),
                output, indent=2)
output.write('\n')
