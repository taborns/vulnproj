import sys
from phplex import lexer
from phpparse import make_parser
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

file = "test.php"
# file = "test_json.py"
with open(file, "r") as f:
    input_file = f.read()

lessons = export(parser.parse(input_file,
                                    lexer=lexer.clone(),
                                    tracking=with_lineno))

for lesson in lessons:
    lesson
    break;
#output.write('\n')
