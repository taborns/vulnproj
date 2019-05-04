# find classes
# find variables
# find functions
# find method calls
# find sources
# find sinks

import phplex
from phpparse import make_parser
import simplejson

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

file = "auth_controller.php"
# file = "test_json.py"
with open(file, "r") as f:
    input_file = f.read()

parsed_result = export(parser.parse(input_file, lexer=phplex.lexer.clone(), tracking=with_lineno))

print(parsed_result)