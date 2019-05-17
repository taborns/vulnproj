class TokenName:
    T_ASSIGNMENT = 'Assignment'
    T_VARIABLE = 'Variable'
    T_ARRAYOFFSET = 'ArrayOffset'
    T_FUNCTION = 'Function'
    T_FUNCTIONCALL = 'FunctionCall'
    T_CLASS = 'Class'
    T_METHOD = 'Method'
    GLOBAL_SCOPE = 'globalscope'
    T_METHODCALL = 'MethodCall'
    T_NEW = 'New'
    T_CONSTRUCT = '__construct'

class SourceToken:
    def __init__(self, name):
        self.name = name
    
    def isUserInput(self):
        return True

class Utility:
    @staticmethod
    def getTokenObject(values, scanner):
        if type(values)==tuple:
            if values[0] == TokenName.T_ARRAYOFFSET:
                return ArrayOffset( values, scanner )
            elif values[0] == TokenName.T_FUNCTIONCALL:
                return FunctionCall(values, scanner)
        else:
            return Literal(values)

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
    
    def length(self):
        return len(self.vulns)


class VulnBlock:
    def __init__(self, title):
        self.title = title 

class ArrayOffset():
    def __init__(self, raw_data,scanner):
        self.scanner = scanner
        self.name = raw_data[1]['node'][1]['name']
        self.lnr = raw_data[1]['node'][1]['lineno']
        self.key = raw_data[1]['expr']
        self.userinput = self.isUserInput()

    def __str__(self):
        return self.name + '[' + self.key +  ']'
    
    def isUserInput(self):
        return self.name in self.scanner.sources

class FunctionCallArgument:
    def __init__(self, name, lnr,  param_raw_data):
        self.name = name 
        self.lnr = lnr
        self.expr = param_raw_data[1]['node']

class NewClass:
    def __init__(self, raw_data, scanner):
        self.raw_data = raw_data
        self.scanner = scanner
        self.className = self.instance = raw_data[1]['name']
        self.lnr = raw_data[1]['lineno']
        self.vulnTreeNode = VulnTreeNode()
        self.userinput = self.isUserInput()


    def isUserInput(self):
        pClass = self.scanner.classes.get(self.className, None)
        if pClass:
            constructor = pClass.scanner.functions.get(TokenName.T_CONSTRUCT)
            if constructor:
                self.raw_data[1]['name'] = TokenName.T_CONSTRUCT
                methodCall = MethodCall(self.raw_data, self.scanner)
                self.vulnTreeNode.append(methodCall.vulnTreeNode)
                return methodCall.isUserInput()
        
        return False
    

class VarAccess:
    def __init__(self, scanner, raw_data):
        self.scanner = scanner
        self.raw_data = raw_data
        self.name = raw_data[1]['name']
        self.lnr = raw_data[1]['lineno']
        self.var = self.__getVar()
        self.userinput = self.getUserInput()
    
    def isUserInput(self):
        return self.userinput;

    def getUserInput(self):
        return self.var.isUserInput() if self.var else False
    
    def __getVar(self):
        from analyze.scanner import Scanner

        if self.scanner.variables.get(self.name, None):
            return self.scanner.variables.get(self.name)
        
        elif self.name in self.scanner.sources:
            return SourceToken(self.name)
        


class FunctionCall:
    def __init__(self, raw_data,scanner):
        self.scanner = scanner
        self.name = raw_data[1]['name']
        self.lnr = raw_data[1]['lineno']
        self.param_raw_data = raw_data[1]['params']
        self.vulnTreeNode = VulnTreeNode()
        self.userinput = self.isUserInput()

    def isUserInput(self):
        from analyze.scanner import Scanner
        if self.scanner.functions.get(self.name):
            return self.taintScanFunction()

        elif self.name in self.scanner.securingFuncs:
            return False
        
        return False

    def getFunction(self, scanner=None):
        if not scanner:
            scanner = self.scanner
        return scanner.functions.get(self.name)

    def taintScanFunction(self, scanner=None):
        function = self.getFunction(scanner)
        param_names = []

        #loops through the function parameters
        for function_param in function.params:
            param_names.append( function_param.name )

        
        function_params = self.getParams(param_names )
        to_taint_params_index = []
        for index, function_param in enumerate(function_params):
            if function_param.isUserInput():
                to_taint_params_index.append( index )
        
        function.taintParams(to_taint_params_index)
        function.tainted = True 
        self.vulnTreeNode.append(function.scanVuln())
        function.tainted = False
        return function.isSecure()
        
    def getParams(self, param_names):
        params = []

        for index, param_name in enumerate(param_names):
            assignment = Assignment(self.scanner, object_data=FunctionCallArgument(param_name, self.lnr, self.param_raw_data[index]) )
            params.append( VarDeclared(assignment))
        
        return params




class Literal():
    def __init__(self, data):
        self.name = 'literal'
        self.value = data
    def isUserInput(self):
        return False

class Assignment():
    def __init__(self,scanner,raw_data=None, object_data=None):
        self.scanner = scanner
        if raw_data:
            self.name = raw_data[1]['node'][1]['name']
            self.lnr = raw_data[1]['node'][1]['name']
            self.value = self.__setValue(raw_data[1]['expr'])
        elif object_data:
            self.name = object_data.name 
            self.lnr = object_data.lnr 
            self.value = self.__setValue( object_data.expr )
        self.is_safe = True 

    def __setValue(self, values):
        if type(values)==tuple:
            if values[0] == TokenName.T_ARRAYOFFSET:
                return ArrayOffset( values, self.scanner )
            elif values[0] == TokenName.T_FUNCTIONCALL:
                return FunctionCall(values, self.scanner)
            elif values[0] == TokenName.T_VARIABLE:
                return VarAccess(self.scanner, values)
            
            elif values[0] == TokenName.T_NEW:
                return NewClass(values, self.scanner)

            elif values[0] == TokenName.T_METHODCALL:
                methodName = None 
                if self.scanner.in_function:
                    methodName = self.scanner.context_name

                return MethodCall(values, self.scanner, methodName)
                
        else:
            return Literal(values)
    
    def __str__(self):
        return self.name + '=' + str(self.value)

class VarDeclared():
    def __init__(self,assignment):
        self.name = assignment.name
        self.value = assignment.value
        self.lnr = assignment.lnr
        self.vulnTreeNode = VulnTreeNode()
        self.dependencies = []
        self.instance = self.getInstance()
        self.getVulnTreeNode()

    def isUserInput(self):
        return self.value.isUserInput()
    
    def getInstance(self):
        if hasattr(self.value, 'instance'):
            return self.value.instance
        
        return None

    def getVulnTreeNode(self):
        if hasattr(self.value, 'vulnTreeNode'):
            return self.vulnTreeNode.append(self.value.vulnTreeNode)

class FunctionDefParam():
    def __init__(self, parameterData):
        self.name = parameterData[1]['name']
        self.value = Literal(None)
        self.lnr = parameterData[1]['lineno']

class Function():
    def __init__(self, raw_data,scanner):
        from analyze.scanner import Scanner

        self.mainScanner = scanner
        self.raw_raw_data = raw_data
        self.raw_data = raw_data[1]
        self.nodes = self.raw_data['nodes']
        self.scanner = Scanner(self.nodes, scanner)
        self.name = self.raw_data['name']
        self.params = self.set_params()
        self.taintable_params = self.set_params()

        #control if the tainted version of variables is being used
        self.tainted = False 
        self.vulnTreeNode = self.scanVuln()
    
    def __unicode__(self):
        return self.name

    def isSecure(self):
        return not self.vulnTreeNode.vulnerable()

    def getRawRawData(self):
        return self.raw_raw_data

    #taintins variables for taint scan 
    def taintParams(self, to_taint_params_index):
        for to_taint_param_index in to_taint_params_index:
            self.taintable_params[to_taint_param_index].userinput = True    
        


    def set_params(self):
        params = []
        for param in self.raw_data['params']:
            params.append( VarAccess(self.scanner, param) )
        return params
       
    def scanVuln(self):

        self.scanner.in_function = True
        self.scanner.context_name = self.name
        param_list = self.params if not self.tainted else self.taintable_params

        for paramVar in param_list:
            self.scanner.variables[paramVar.name] = paramVar
        
        vulnTreeNode = self.scanner.scan()

        return vulnTreeNode

class MethodCall(FunctionCall):
    this = '$this'

    def __init__(self, raw_data, scanner, callerMethodName=None):
        self.scanner = scanner
        self.callerMethodName = callerMethodName
        self.raw_data = raw_data
        self.vulnTreeNode = VulnTreeNode()

        self.objct = self.__getObjct(raw_data[1].get('node', None))
        self.name = self.raw_data[1]['name']
        self.param_raw_data = raw_data[1]['params']

        self.lnr = self.raw_data[1]['lineno']
        self.userinput = self.isUserInput()
    def __getObjct(self, node):
        if not node:
            return None
        if node[0] == TokenName.T_VARIABLE:
            return node[1]['name']
    
    def getClass(self, className):
        return self.scanner.classes.get(className)



    def isUserInput(self):
        if not self.scanner.functions.get(self.name, None) and self.callerMethodName and self.objct == MethodCall.this:
            self.scanner.yet_to_scan_functions[self.name] = self.callerMethodName
        
        #if the method is called inside the class($this) just look for the function 
        #current scanner object is the class's 
        elif self.objct == MethodCall.this or not self.objct:
            return not self.taintScanFunction()


        #look for the class from which the object is instantiated then look for the method and check if it is secure
        elif self.scanner.variables.get(self.objct):

            objVar =  self.scanner.variables.get(self.objct)
            if hasattr(objVar, 'instance') and objVar.instance:
                pClass =  self.getClass(objVar.instance)
                if pClass:
                    if self.getFunction(pClass.scanner):
                        return not self.taintScanFunction(pClass.scanner)
        
          
        elif self.getFunction():
            return not self.taintScanFunction()

        return False

    

class PClass:
    def __init__(self, raw_data, parentScanner):
        self.raw_data = raw_data
        self.name = raw_data[1]['name']
        self.lnr = raw_data[1]['lineno']

        from analyze.scanner import Scanner

        self.nodes = self.raw_data[1]['nodes']
        self.scanner = Scanner(self.nodes, parentScanner)

        self.methods = self.__getMethods()
        self.vulnTreeNode = self.scanVuln()


    def __getMethods(self):
        methods = []
        for node in self.raw_data[1]['nodes']:
            if node[0] == TokenName.T_METHOD:
                method = Function(node, self.scanner)
                self.scanner.functions[method.name] = method
                methods.append( method )
        return methods
    
    def scanVuln(self):

        self.scanner.in_class = True
        self.scanner.context_name = self.name
        vulnTreeNode = VulnTreeNode()

        for method in self.methods:
            vulnTreeNode.append(method.vulnTreeNode)
        
        self.scanner.scan()

        return vulnTreeNode
