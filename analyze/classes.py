from analyze.sink_points import *
class TokenName:
    T_ASSIGNMENT = 'Assignment'
    T_VARIABLE = 'Variable'
    T_ARRAYOFFSET = 'ArrayOffset'
    T_FUNCTION = 'Function'
    T_RETURN = 'Return'
    T_FUNCTIONCALL = 'FunctionCall'
    T_CLASS = 'Class'
    T_METHOD = 'Method'
    GLOBAL_SCOPE = 'globalscope'
    T_METHODCALL = 'MethodCall'
    T_NEW = 'New'
    T_CONSTRUCT = '__construct'
    T_ARRAY = "Array"
    T_BINARYOP = 'BinaryOp'
    T_VULNBINARYOP = '.'
    T_FOREACH = "Foreach"
    T_FOR = "For"
    T_IF = "If"
    T_ELSE = "Else"
    T_ELSEIF = "ElseIf"
    T_BLOCK = "Block"
    T_CONSTANT = 'Constant'
    T_XSS = NAME_XSS
    T_HTTP_HEADER = NAME_HTTP_HEADER
    T_SESSION_FIXATION  = NAME_SESSION_FIXATION
    T_CODE = NAME_CODE
    T_REFLECTION = NAME_REFLECTION
    T_FILE_INCLUDE = NAME_FILE_INCLUDE
    T_FILE_READ = 'file-read'
    T_FILE_AFFECT = 'file-affect'
    T_EXEC = 'command-execution'
    T_SQLI = 'sql-injection'
    T_XPATH = 'xpath-injectin'
    T_LDAP = 'ldap-injection'
    T_CONNECT = 'protocol-injection'
    T_POP = 'php-object-injection'


class SourceToken:
    def __init__(self, name):
        self.name = name
    
    def isuserinput(self):
        return False

class Utility:
    @staticmethod
    def getTokenObject(values, scanner):
        if type(values)==tuple:
            if values[0] == TokenName.T_ARRAYOFFSET:
                return ArrayOffset( values, scanner )
           
            elif values[0] == TokenName.T_FUNCTIONCALL:
                return FunctionCall(values, scanner)

            elif values[0] == TokenName.T_VARIABLE:
                return VarAccess(scanner, values)
            
            elif values[0] == TokenName.T_NEW:
                return NewClass(values, scanner)
            
            elif values[0] == TokenName.T_ARRAY:
                return Array(values, scanner)

            elif values[0] == TokenName.T_BINARYOP:
                return BinaryOp(values, scanner)
            
            elif values[0] == TokenName.T_FOREACH:
                return ForEach(values, scanner)
            
            elif values[0] == TokenName.T_FOR:
                return ForLoop(values, scanner)
            
            elif values[0] == TokenName.T_IF:
                return IfMain(values, scanner)
            
            elif values[0] == TokenName.T_CONSTANT:
                return Constant(values)

            elif values[0] == TokenName.T_METHODCALL:
                methodName = None 
                if scanner.in_function:
                    methodName = scanner.context_name

                return MethodCall(values, scanner, methodName)
            elif values[0] == TokenName.T_BINARYOP:
                return  BinaryOp(values, scanner)
                
        else:
            return Literal(values)

class VulnTree:
    def __init__(self):
        self.vulns = []
    
    def addVuln(self, vulnTreeNode):
        if vulnTreeNode:
            self.vulns.append(vulnTreeNode)

    def merge(self, vulnTree):
        for vuln in vulnTree.vulns:
            self.addVuln(vuln)

    def length(self):
        return len(self.vulns)
    
class Sink:
    def __init__(self, raw_data, scanner):
        self.scanner = scanner
        self.raw_data = raw_data
        self.name = raw_data[0]
        self.values = self.__getValue()
        self.vulnTreeNode = None
        self.lnr = raw_data[1]['lineno']
        self.checkForVuln()

    def __getValue(self):
        if self.raw_data[1].get('expr'):
            return [Utility.getTokenObject( self.raw_data[1]['expr'], self.scanner)]
        
        elif self.raw_data[1].get('node'):
            return [Utility.getTokenObject( self.raw_data[1]['node'], self.scanner)]
           
        elif self.raw_data[1].get('nodes'):
            parsed_nodes = []
            for node in self.raw_data[1].get('nodes'):
                parsed_nodes.append( Utility.getTokenObject( node, self.scanner ))
            
            return parsed_nodes
        return []

    def isVulnerable(self):
        return self.vulnTreeNode
    
    def checkForVuln(self):
        sinkInfo, vulnName = self.getVulnerability()

        #loop through all params 
        if len(sinkInfo[0]) >0 and sinkInfo[0][0] == 0:
            values = self.values
        else:
            value_ind_list = sinkInfo[0]

            values = []
            for value_ind in value_ind_list:
                values.append(self.values[value_ind-1])
        for value in values:
            if hasattr(value, 'secure_from'):
                if self.name.lower() in value.secure_from:
                    return None

                elif value.vulnTreeNode:
                    vuln = self.getVulnerability()
                    if not self.vulnTreeNode:
                        self.vulnTreeNode = VulnTreeNode('A sink function is called with unsanitized parameter. This causes potential %s' % ( vulnName.upper()), self.lnr, self.__str__())

                    self.vulnTreeNode.addPatch( vuln[0][1] )

                    if value.vulnTreeNode:
                        self.vulnTreeNode.addChildren( value.vulnTreeNode)
            


    def getVulnerability(self):
        sink_info, vuln = self.scanner.getSink(self.name)
        return sink_info, vuln
    
    def __str__(self):
        params = ','.join([value.__str__() for value in self.values])
        return '%s(%s)' % (self.name.lower(), params)

class VulnTreeNode:

    def __init__(self, title, line, snippet=None):
        self.title = title 
        self.line = line
        self.snippet = snippet
        self.children = []
        self.patch_methods = set()

    def addChildren(self, vulnTreeNode):
        self.children.append( vulnTreeNode )

    def addChildrenFromTree(self, vulnTree):
        for vuln in  vulnTree.vulns:
            self.addChildren( vuln )

    def length(self):
        return len(self.children )
    
    def vulnerable(self):
        return self.length() > 0
    
    def __str__(self):
        if self.snippet:
            return "%s at line %s : '%s' " % (self.title, self.line, str(self.snippet))

        return "%s at line %s " % (self.title, self.line)
    
    def addPatch(self, methodNames):
        methodNames = set(methodNames)
        self.patch_methods = self.patch_methods.union( methodNames)

class ForEachKey:
    def __init__(self, name,lnr, value):
        self.name = name 
        self.lnr = lnr 
        self.value = value 
        self.userinput = self.isuserinput()
    
    def isuserinput(self):
        return self.value.isuserinput()
class ForEachValue:
    def __init__(self, raw_data, value):
        self.raw_data = raw_data
        self.lnr = raw_data[1]['name'][1]['lineno']
        self.name = raw_data[1]['name'][1]['name']
        self.value = value
        self.userinput = self.isuserinput()
    def isuserinput(self):
        return self.value.isuserinput()

class ForEach:
    def __init__(self, raw_data, scanner):
        from analyze.scanner import Scanner

        self.scanner = scanner
        self.raw_data = raw_data
        self.loopScanner = Scanner(self.raw_data[1]['node'][1]['nodes'], scanner)

        self.value = self.__getExpr(self.raw_data[1]['expr'])
        self.lnr = self.raw_data[1]['lineno']

        self.keyVar = self.getKeyAssignment(self.raw_data[1]['keyvar'])
        self.forEachValue = self.getValueAssignment(self.raw_data[1]['valvar'])
        self.vulnTreeNode = None

        self.loopScan()
        

    def getKeyAssignment(self, keyVar):
        forEachKey = VarDeclared(ForEachKey(keyVar[1]['name'], keyVar[1]['lineno'], self.value))
        self.loopScanner.variables[forEachKey.name] = VarDeclared(forEachKey)
        return forEachKey
    
    def getValueAssignment(self, value):
        forEachValue = VarDeclared(ForEachValue(value, self.value))
        self.loopScanner.variables[forEachValue.name] = VarDeclared(forEachValue)
        return forEachValue


    def __getExpr(self, expr):
        return Utility.getTokenObject(expr, self.scanner)

    def loopScan(self):
        self.vulnTreeNode = self.loopScanner.scan()
        self.scanner.mergeScannerData(self.loopScanner)

class ForLoop:
    def __init__(self, raw_data, scanner):
        from analyze.scanner import Scanner
        self.scanner = scanner
        self.loopScanner = Scanner(raw_data[1]['node'][1]['nodes'])
        self.lnr = raw_data[1]['lineno']
        self.start = self.__getAssignments( raw_data[1]['start'])
        self.count = self.__getAssignments( raw_data[1]['count'])
        self.vulnTreeNode = None

        self.loopScan()

    def __getAssignments(self,  data ):
        for datum in data:
            if datum[0] == TokenName.T_ASSIGNMENT:
                declaredVar = VarDeclared(Assignment(self.scanner, datum))
                self.loopScanner.variables[declaredVar.name] = declaredVar
    
    def loopScan(self):
        self.vulnTreeNode = self.loopScanner.scan()
        self.scanner.mergeScannerData(self.loopScanner)

class If:
    def __init__(self, raw_data, scanner):
        from analyze.scanner import Scanner
        self.scanner = scanner
        self.raw_data = raw_data
        self.ifScanner = Scanner(self.getNodes())
        self.lnr = raw_data[1]['lineno']
        self.vulnTreeNode = None
        self.getExpr()
        self.ifScan()
        self.getExtraParams()

    def getExpr(self):
        if self.raw_data[1].get('expr'):
            self.expr = Utility.getTokenObject( self.raw_data[1]['expr'], self.scanner)

    def getNodes(self):
        return self.raw_data[1]['node'][1]['nodes']

    def getExtraParams(self):
        return None
    
    def ifScan(self):
        scannedVulnTreeNode = self.ifScanner.scan()
        if scannedVulnTreeNode.length():
            self.vulnTreeNode = VulnTreeNode( 'requires %s' %( self.__str__()), self.lnr, '' )
            self.vulnTreeNode.addChildrenFromTree( scannedVulnTreeNode)

        if hasattr(self, 'expr'):
            if self.expr.vulnTreeNode:
                self.scanner.vulnTree.addVuln(self.expr.vulnTreeNode)

        self.scanner.mergeScannerData(self.ifScanner)
    
    def getStr(self):
        if  hasattr(self, 'expr'):
            return "if(%s)" % (self.expr.__str__())
        return "else"
    
    def __str__(self):
        return self.getStr()

class IfMain(If):

    def getExtraParams(self):
        #else block not null 
        if self.raw_data[1].get('else_'):
            self.elseBlock = Else(self.raw_data[1]['else_'], self.scanner)

        for elseif in self.raw_data[1].get('elseifs'):
            elseifBlock = If(elseif, self.scanner)
    
    def __str__(self):
        return self.getStr()


class Else(If):
    def getNodes(self):
        
        #check if it else if
        if self.raw_data[1]['node'][0] == TokenName.T_IF:
            return self.raw_data[1]['node'][1]['node'][1]['nodes']
        
        return self.raw_data[1]['node']['nodes']

    def __str__(self):
        return self.getStr()


class ArrayElement:

    def __init__(self, raw_data, scanner):
        self.scanner = scanner
        self.vulnTreeNode = None
        self.key = raw_data[1]['key']
        self.element = Utility.getTokenObject(raw_data[1]['value'], scanner)
        self.lnr = raw_data[1]['lineno']
        self.secure_from = set()
        self.userinput = self.isuserinput() 
        self.__scanVuln()
    def isuserinput(self):
        
        return self.element.isuserinput()
    
    def __scanVuln(self):
        if self.element.vulnTreeNode:
            self.vulnTreeNode = self.element.vulnTreeNode
        
        if hasattr(self.element, 'secure_from'):
            self.secure_from = self.secure_from.union( self.element.secure_from)


    def __str__(self):
        if self.key:
            return '%s => %s' % (self.key , self.element.__str__())
        else:
            return '%s' % (self.element.__str__(), )

class Array:
    def __init__(self, raw_data, scanner):
        self.scanner = scanner
        self.userinput = False
        self.vulnTreeNode = None
        self.secure_from = set()
        self.lnr = raw_data[1]['lineno']
        self.elements = self.__getElements( raw_data[1]['nodes'] )
        self.__scanVuln()
    
    def isuserinput():
        return self.userinput

    def __getElements(self, nodes):
        elements = []
        
        for node in nodes:
            element = ArrayElement( node, self.scanner )
            elements.append(element)
        
        return elements

    def __scanVuln(self):
        for element in self.elements:
            if element.isuserinput():
                
                if not self.vulnTreeNode:
                    self.vulnTreeNode = VulnTreeNode("Unsanitized user input is used as an array element ",  self.lnr, self.__str__()  )
                
                if element.vulnTreeNode:
                    self.vulnTreeNode.addChildren(element.vulnTreeNode)
                
                if hasattr(element, 'secure_from'):
                    self.secure_from = self.secure_from.intersection( element.secure_from)
                
                self.userinput = True

    def isuserinput(self):
        return self.userinput
    
    def __str__(self):
        return "array( %s )" % ','.join( [ str(element) for element in self.elements] )
        


class BinaryOp:
    def __init__(self, raw_data, scanner):
        self.scanner = scanner
        self.vulnTreeNode = None

        self.right = self.__getOperand(raw_data[1]['right'])
        self.left = self.__getOperand(raw_data[1]['left'])
        self.lnr = raw_data[1]['lineno']
        self.op = raw_data[1]['op']
        self.userinput = self.isuserinput()

    def isuserinput(self):
        if self.op == TokenName.T_VULNBINARYOP:
            if self.right.isuserinput() or self.left.isuserinput():
                self.vulnTreeNode = VulnTreeNode('Unsanitized input is used in the binary operation', self.lnr, self.__str__())   
                if self.right.vulnTreeNode:
                    self.vulnTreeNode.addChildren(self.right.vulnTreeNode)
                if self.left.vulnTreeNode:
                    self.vulnTreeNode.addChildren(self.left.vulnTreeNode)
                return True     

        return False
            
    def __getOperand(self, expr):
        return Utility.getTokenObject(expr, self.scanner)
    
    def __str__(self):

        return "%s %s %s" % (self.left.__str__(), self.op, self.right.__str__())

class ArrayOffset():
    def __init__(self, raw_data,scanner):
        self.scanner = scanner
        self.vulnTreeNode = None

        self.name = raw_data[1]['node'][1]['name']
        self.lnr = raw_data[1]['node'][1]['lineno']
        self.key = raw_data[1]['expr']
        self.userinput = self.isuserinput()
        self.secure_from = {}

    def __str__(self):
        return "%s[%s]" % (self.name , self.key)
    
    def isuserinput(self):
        if self.name in self.scanner.sources:
            self.vulnTreeNode = VulnTreeNode( "Sensitive sink used", self.lnr, self.__str__())
            return True
        
        return False

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
        self.vulnTreeNode = None
        self.userinput = self.isuserinput()


    def isuserinput(self):
        pClass = self.scanner.classes.get(self.className, None)
        if pClass:
            constructor = pClass.scanner.functions.get(TokenName.T_CONSTRUCT)
            if constructor:
                self.raw_data[1]['name'] = TokenName.T_CONSTRUCT
                methodCall = MethodCall(self.raw_data, self.scanner)
                if methodCall.vulnTreeNode and methodCall.vulnTreeNode.vulnerable():
                    self.vulnTreeNode = VulnTreeNode('The constructor of the class %s is insecure. ' % self.className, self.lnr, self.__str__())
                    self.vulnTreeNode.addChildren(methodCall.vulnTreeNode)

                return methodCall.isuserinput()
        
        return False

    
    def __str__(self):
        return 'new ' + self.className + '()'
    

class VarAccess:
    def __init__(self, scanner, raw_data):
        self.scanner = scanner
        self.raw_data = raw_data
        self.name = raw_data[1]['name']
        self.lnr = raw_data[1]['lineno']
        self.var = self.__getVar()
        self.userinput = self.getUserInput()
        self.vulnTreeNode = self.getVulnTeeNode()
        self.secure_from = set() 
        self.__getSecureFrom() 

        
    def isuserinput(self):
        return self.userinput;

    def getVulnTeeNode(self):
        if hasattr(self.var, 'vulnTreeNode'):
            return self.var.vulnTreeNode
        
        return None

    def getUserInput(self):
        return self.var.isuserinput() if self.var else False
    
    def __getVar(self):
        from analyze.scanner import Scanner
        if self.scanner.variables.get(self.name, None):
            return self.scanner.variables.get(self.name)
        
        elif self.name in self.scanner.sources:
            return SourceToken(self.name)
    
    def __getSecureFrom(self):
        if self.var and hasattr(self.var, 'secure_from'):
            self.secure_from = self.secure_from.union(self.var.secure_from)

    
    def __str__(self):
        return self.name;
        


class FunctionCall:
    def __init__(self, raw_data,scanner):
        self.scanner = scanner
        self.name = raw_data[1]['name']
        self.lnr = raw_data[1]['lineno']
        self.param_raw_data = raw_data[1]['params']
        self.params = self.getFuncCallParms()
        self.vulnTreeNode = None
        self.secure_from = set()
        self.userinput = self.isuserinput()

    def __str__(self):
        params = self.getFuncCallParms()
        params_ = []
        for param in params:
            params_.append( str(param))

        return self.name + '('  + ','.join(params_) + ')'
    
    #returns list of parameter objects 
    def getFuncCallParms(self):
        
        function = self.getFunction()
        
        if function:
            params =  function.params
        else:
            params = [FunctionParam(  param, self.scanner) for param in self.param_raw_data]
        
        return params


    def isuserinput(self):
        from analyze.scanner import Scanner

        if self.scanner.functions.get(self.name):
            return not self.taintScanFunction()

        elif self.scanner.getSink( self.name ):
            sinkInfo, vulnName = self.scanner.getSink( self.name ) 
            
            #loop through all params 
            if len(sinkInfo[0]) >0 and sinkInfo[0][0] == 0:
                params = self.params
            else:
                param_ind_list = sinkInfo[0]
                params = []
                for param_ind in param_ind_list:
                    params.append(self.params[param_ind-1])
            not_secure = False 
            for param in params:
                if hasattr(param, 'secure_from'):
                    if self.name.lower() in param.secure_from:
                        continue
                    elif param.isuserinput() or ( hasattr(param, 'isSecure')):
                        if not self.vulnTreeNode:
                            self.vulnTreeNode = VulnTreeNode('A sink function is called with unsanitized parameter. This causes potential %s' % ( vulnName.upper()), self.lnr, self.__str__())
                                            
                        self.vulnTreeNode.addPatch(sinkInfo[1] )
                        if param.vulnTreeNode:
                            self.vulnTreeNode.addChildren( param.vulnTreeNode)

                        not_secure = True

            return not_secure

        elif self.scanner.securingFor( self.name ):
            self.secure_from = self.secure_from.union( self.scanner.securingFor( self.name ))    
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
            if function_param.isuserinput():
                to_taint_params_index.append( index )

        function.taintParams(to_taint_params_index)
        function.tainted = True 
        vulnTree = function.scanVuln(function_params)
        
        if vulnTree.vulns:
            self.vulnTreeNode = VulnTreeNode("A function call triggered sensitive sink point", self.lnr, self.__str__())
            self.vulnTreeNode.addChildrenFromTree( vulnTree )
        self.secure_from = self.secure_from.union( function.secure_from)

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
        self.vulnTreeNode = None

    def isuserinput(self):
        return False

    def __str__(self):
        return str(self.value)

class Constant:
    def __init__(self, data):
        self.name = data[1]['name']
        self.lnr = data[1]['lineno']
        self.vulnTreeNode = None

    def isuserinput(self):
        return False

    def __str__(self):
        return self.name
class Assignment():
    def __init__(self,scanner,raw_data=None, object_data=None):
        self.scanner = scanner
        if raw_data:
            self.name = raw_data[1]['node'][1]['name']
            self.lnr = raw_data[1]['node'][1]['lineno']
            self.value = self.__setValue(raw_data[1]['expr'])
        elif object_data:
            self.name = object_data.name 
            self.lnr = object_data.lnr 
            self.value = self.__setValue( object_data.expr )
        self.is_safe = True 

    def __setValue(self, values):
        return Utility.getTokenObject(values, self.scanner)
    
    def __str__(self):
        return self.name + '=' + str(self.value)

class VarDeclared():
    def __init__(self,assignment):
        self.name = assignment.name
        self.value = assignment.value
        self.lnr = assignment.lnr
        self.vulnTreeNode = None
        self.instance = self.getInstance()

        # list of security vulns 
        self.secure_from = set()
        self.getVulnTreeNode()
        
    def isuserinput(self):
        return self.value.isuserinput()
    
    def getInstance(self):
        if hasattr(self.value, 'instance'):
            return self.value.instance
        
        return None

    def getVulnTreeNode(self):
        
        if hasattr(self.value, 'vulnTreeNode') and self.value.vulnTreeNode:
            self.vulnTreeNode = VulnTreeNode('Unsanitized value is assigned to the variable', self.lnr, self.__str__())
            self.vulnTreeNode.addChildren(self.value.vulnTreeNode)

        if hasattr(self.value, 'secure_from'):
            self.secure_from = self.secure_from.union(self.value.secure_from)

    def __str__(self):
        return "%s = %s" % ( self.name, str(self.value))

class FunctionParam:
    def __init__(self, parameterData, scanner):
        self.node = parameterData[1]['node']
        self.value = Utility.getTokenObject(self.node, scanner)
        self.lnr = parameterData[1]['lineno']
        self.secure_from = set()
        self.vulnTreeNode = None
        self.__setParams()

    def isuserinput(self):
        return self.value.isuserinput

    def __setParams(self):
        if hasattr(self.value, 'secure_from'):
            self.secure_from.union( self.value.secure_from )
        
        if self.value.vulnTreeNode:
            self.vulnTreeNode = self.value.vulnTreeNode

    def __str__(self):
        return self.value.__str__()

class Return:
    def __init__(self, raw_data, function, scanner):
        self.function = function
        self.raw_data = raw_data
        self.scanner = scanner
        self.lnr = self.raw_data[1]['lineno']
        self.value = Utility.getTokenObject(self.raw_data[1]['node'], scanner)
        self.vulnTreeNode = None
        self.secure_from = set()
        self.__scanVuln()

    def isUserInput(self):
        return self.value.isuserinput()

    def __scanVuln(self):
        if self.value.isuserinput():
            self.vulnTreeNode = VulnTreeNode('%s returns usanitized data' % (self.function.name), self.lnr, self.__str__())
            
            if self.value.vulnTreeNode:
                self.vulnTreeNode.addChildren(self.value.vulnTreeNode)
            
        if hasattr(self.value, 'secure_from'):
            self.secure_from = self.secure_from.union( self.value.secure_from )
            self.function.secure_from = self.function.secure_from.union( self.secure_from)

    def __str__(self):
        return 'return %s' %(self.value.__str__())
class Function:
    def __init__(self, raw_data,scanner):
        from analyze.scanner import Scanner
        self.secure_from = set()
        self.mainScanner = scanner
        self.raw_raw_data = raw_data
        self.raw_data = raw_data[1]
        self.nodes = self.raw_data['nodes']
        self.scanner = Scanner(self.nodes, scanner)
        self.name = self.raw_data['name']
        self.lnr = self.raw_data['lineno']
        self.params = self.set_params()
        self.taintable_params = self.set_params()
        self.userinput = False 
        #control if the tainted version of variables is being used
        self.tainted = False 
        self.vulnTreeNode = None
        self.getVulns()

    def isuserinput(self):
        return self.userinput

    def getVulns(self):
        vulnTree = self.scanVuln()
        if vulnTree.length() > 0:
            self.vulnTreeNode = VulnTreeNode('The function is suscetible to potential security vulnerability', self.lnr, self.name)
            self.vulnTreeNode.addChildrenFromTree( vulnTree )
        
    def __unicode__(self):
        return self.name

    def isSecure(self):
        return not self.scanner.vulnTree.length()

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
       
    def scanVuln(self, paramVariables=None):

        self.scanner.in_function = True
        self.scanner.context_object = self
        self.scanner.context_name = self.name
        param_list = self.params if not self.tainted else self.taintable_params
        if paramVariables:
            param_list = paramVariables
        for paramVar in param_list:
            self.scanner.variables[paramVar.name] = paramVar

        vulnTree = self.scanner.scan()

        return vulnTree
    


class MethodCall(FunctionCall):
    this = '$this'

    def __init__(self, raw_data, scanner, callerMethodName=None):
        self.scanner = scanner
        self.callerMethodName = callerMethodName
        self.raw_data = raw_data
        self.vulnTreeNode = None
        self.secure_from = set()

        self.objct = self.__getObjct(raw_data[1].get('node', None))
        self.name = self.raw_data[1]['name']
        self.param_raw_data = raw_data[1]['params']

        self.lnr = self.raw_data[1]['lineno']
        self.userinput = self.isuserinput()

    def __getObjct(self, node):

        if not node:
            return None
        if node[0] == TokenName.T_VARIABLE:
            return node[1]['name']
    
    def getClass(self, className):
        return self.scanner.classes.get(className)



    def isuserinput(self):
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
        self.vulnTreeNode = None
        self.scanVuln()

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
        foundVulnNodes = []
        for method in self.methods:
            if method.vulnTreeNode and method.vulnTreeNode.vulnerable():
                foundVulnNodes.append( method.vulnTreeNode)

        if foundVulnNodes:
            self.vulnTreeNode = VulnTreeNode('Requires %s' % self.__str__(), self.lnr)
            for foundVulnNode in foundVulnNodes:
                self.vulnTreeNode.addChildren( foundVulnNode)
        self.scanner.scan()

        return self.vulnTreeNode
    

    def __str__(self):
        return "class %s" % self.name 