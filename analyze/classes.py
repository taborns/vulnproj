class TokenName:
    T_ASSIGNMENT = 'Assignment'
    T_VARIABLE = 'Variable'
    T_ARRAYOFFSET = 'ArrayOffset'
    T_FUNCTION = 'Function'
    T_FUNCTIONCALL = 'FunctionCall'
    GLOBAL_SCOPE = 'globalscope'

class VulnTreeNode:
    def __init__(self):
        self.vulns = [] 
    
    def addVuln(self, vulnBlock):
        self.vulns.append(vulnBlock)
    
    def append(self, otherVulnNode):
        for vulnBlock in otherVulnNode.vulns:
            self.vulns.append(vulnBlock)

    def vulnerable(self):
        return len(self.vulns) > 0

class VulnBlock:
    def __init__(self, title):
        self.title = title 

class ArrayOffset():
    def __init__(self, raw_data):
        self.name = raw_data[1]['node'][1]['name']
        self.lnr = raw_data[1]['node'][1]['lineno']
        self.key = raw_data[1]['expr']
        self.userinput = self.isUserInput()

    def __str__(self):
        return self.name + '[' + self.key +  ']'
    
    def isUserInput(self):
        return True

class VarAccess:
    def __init__(self, raw_data):
        self.data = raw_data[1]['node']
        self.var = self.__getVar()
        
    def isUserInput(self):
        return self.var.userinput

    def __getVar(self):

        if type(self.data)==tuple:
            if self.data[0] == TokenName.T_ARRAYOFFSET:
                self.var = ArrayOffset(self.data)
        else:
            return Literal(self.data)

class FunctionCall:
    def __init__(self, raw_data):
        self.name = raw_data[1]['name']
        self.lnr = raw_data[1]['lineno']
        self.parameters = [VarAccess(param) for param in raw_data[1]['params']]
        from analyze.scanner import Scanner
        self.function = Scanner.functions.get(self.name)

    def isUserInput(self):
        if self.function:
            return self.function.isSecure()
        
        return False


class Literal():
    def __init__(self, data):
        self.name = 'literal'
        self.value = data
        self.userinput = False

    def isUserInput(self):
        return self.userinput

class Assignment():
    def __init__(self, raw_data):
        self.name = raw_data[1]['node'][1]['name']
        self.lnr = raw_data[1]['node'][1]['name']
        self.value = self.__setValue(raw_data[1]['expr'])
        self.is_safe = True 

    def __setValue(self, values):

        if type(values)==tuple:
            if values[0] == TokenName.T_ARRAYOFFSET:
                return ArrayOffset( values )
            if values[0] == TokenName.T_FUNCTIONCALL:
                return FunctionCall(values)
        else:
            return Literal(values)
    
    def __str__(self):
        return self.name + '=' + str(self.value)

class VarDeclared():
    def __init__(self,assignment):
        self.name = assignment.name
        self.value = assignment.value
        self.lnr = assignment.lnr
        self.dependencies = []
        self.userinput = self.isUserInput()

    def isUserInput(self):
        return self.value.isUserInput()

class FunctionDefParam():
    def __init__(self, parameterData):
        self.name = parameterData[1]['name']
        self.value = Literal(None)
        self.lnr = parameterData[1]['lineno']

class Function():
    def __init__(self, raw_data):
        from analyze.scanner import Scanner

        self.raw_data = raw_data[1]
        self.nodes = self.raw_data['nodes']
        self.name = self.raw_data['name']
        self.params = self.setParams()
        self.scanner = Scanner(self.nodes)
        self.vulnTreeNode = self.scanVuln()


    def isSecure(self):
        return self.vulnTreeNode.vulnerable()

    def setParams(self):
        params = []
        for param in self.raw_data['params']:
            paramVar = VarDeclared( FunctionDefParam(param) )
            paramVar.userinput = True
            params.append( paramVar )

        return params
        
    def scanVuln(self):
        self.scanner.in_function = True
        self.scanner.context_name = self.name
        vulnTreeNode = self.scanner.scan()

        for paramVar in self.params:
            self.scanner.variables[paramVar.name] = paramVar.value

        return vulnTreeNode
