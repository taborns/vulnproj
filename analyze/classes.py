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
    T_OROP = 'or'
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
    T_INCLUDE = 'Include'
    T_REQUIRE = 'Require'
    T_CLASSVARIABLES = 'ClassVariables'
    T_CLASSVARIABLE = 'ClassVariables'
    T_OBJECTPROPERTY =  'ObjectProperty'
    T_DEFINE = 'define'
    T__FILE__ = '__FILE__'
    T_MAGICCONSTANT = 'MagicConstant'
    T_ISSET = "IsSet"
    T_SILENCE = "Silence"
    

class SourceToken:
    def __init__(self, name):
        self.name = name
        self.userinput = self.isuserinput()
        self.vulnTreeNode = None

    def isuserinput(self):
        return False

class UnknowNode:
    def __init__(self, scanner):
        self.scanner = scanner
        self.userinput = self.isuserinput()
        self.vulnTreeNode = None
    
    def isuserinput(self):
        return False
    
    def __str__(self):
        return 'unknown'

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
            
            elif values[0] == TokenName.T_ASSIGNMENT:
                return VarDeclared( Assignment(scanner, values) )
            elif values[0] == TokenName.T_CLASSVARIABLES:
                return ClassVariables(values, scanner)

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
            
            elif values[0] == TokenName.T_ELSE:
                return Else(values,scanner)

            elif values[0] == TokenName.T_CONSTANT:
                return Constant(scanner, values)

            elif values[0] == TokenName.T_OBJECTPROPERTY:
                return ObjectProperty(values,scanner)
            elif values[0] == TokenName.T_MAGICCONSTANT:
                return MagicConstant(scanner, values)
            
            elif values[0] == TokenName.T_SILENCE:
                return Silence(values, scanner)

            elif values[0] == TokenName.T_METHODCALL:
                methodName = None 
                if scanner.in_function:
                    methodName = scanner.context_name

                return MethodCall(values, scanner, methodName)
            elif values[0] == TokenName.T_BINARYOP:
                return  BinaryOp(values, scanner)
            
            elif values[0] == TokenName.T_ISSET:
                return IsSet(values, scanner)
            else:
                
                return UnknowNode(scanner)
                
        else:
            return Literal(values)

class VulnTree:
    def __init__(self, file_name):
        self.vulns = []
        self.file_name = file_name
    
    def addVuln(self, vulnTreeNode):
        if vulnTreeNode:

            for vuln in self.vulns:
                if vuln.md5Hash == vulnTreeNode.md5Hash:
                    return

            vulnTreeNode.file_name = self.file_name
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
        try:
            #loop through all params 
            if len(sinkInfo[0]) >0 and sinkInfo[0][0] == 0:
                values = self.values
            else:
                value_ind_list = sinkInfo[0]
                values = []
                for value_ind in value_ind_list:
                    values.append(self.values[value_ind-1])
        except IndexError:
            return

        for value in values:

            if hasattr(value, 'secure_from'):
                if self.name.lower() in value.secure_from:
                    return None
                elif value.userinput:
                    if not self.vulnTreeNode:
                        self.vulnTreeNode = VulnTreeNode('A sink function is called with unsanitized parameter. This causes potential %s' % ( vulnName.upper()), self.lnr, self.__str__())
                    
                    self.vulnTreeNode.addChildren( value.vulnTreeNode)
                    self.vulnTreeNode.addPatch( sinkInfo[1] )



    #sink_info : the sink information containing the vulnerable parameters and the securing function for the sink
    #vuln : The name of the vulnerability associated with the sink 
    def getVulnerability(self):

        sink_info, vuln = self.scanner.getSink(self.name)
        return sink_info, vuln
    
    def __str__(self):
        params = ','.join([value.__str__() for value in self.values])
        return '%s(%s)' % (self.name.lower(), params)

class VulnTreeNode:

    def __init__(self, title, line, snippet=None, file_name=None, is_rootable=True):
        self.title = title 
        self.line = line
        self.snippet = snippet
        self.children = []
        self.patch_methods = set()
        self.file_name = file_name
        self.is_rootable = is_rootable
        self.md5Hash = self.__getHash()

        #Sink is with unsanitized input is called. Thus, vulnerability  
        self.sink_vuln = False


    def __getHash(self):
        import hashlib
        from hashlib import md5
        m = hashlib.md5()
        m.update( self.title + ' ' + str(self.line) + ' ' + str(self.file_name) )
        return m.hexdigest()
        
         

    def addChildren(self, vulnTreeNode):

        #check the hash if the vuln tree node is added as a child already. 
        for child in self.children:
            if child.md5Hash == vulnTreeNode.md5Hash:
                return
        if vulnTreeNode:
            self.file_name = vulnTreeNode.file_name
            self.children.append( vulnTreeNode )

    def addChildrenFromTree(self, vulnTree):
        for vuln in  vulnTree.vulns:
            self.addChildren( vuln )

    def length(self):
        return len(self.children )
    
    def vulnerable(self):
        return self.length() > 0
    
    def display(self, width=2):

        for child in self.children:
            print '%*s [*] %2s' % (width, ' ', str(child))
            child.display(width+2)
    
    def getFileName(self):
        if self.file_name:
            return '/'.join(self.file_name.split('/')[1:])
        
        return ''
    def __str__(self):
        if self.snippet and self.file_name:
            return "(%s) %s at line %s : '%s'" % (self.getFileName(), self.title, self.line, str(self.snippet))
        elif self.snippet:
            return "%s at line %s : '%s'" % (self.title, self.line, str(self.snippet))
        elif self.file_name:
            return "(%s) at line %s : '%s'" % (str(self.getFileName()),  self.line, self.title)

        return "%s at line %s " % (self.title, self.line)
    
    def addPatch(self, methodNames):
        methodNames = set(methodNames)
        self.patch_methods = self.patch_methods.union( methodNames)

class Silence:
    def __init__(self,raw_data, scanner):
        self.raw_data = raw_data
        self.scanner = scanner
        self.userinput = False 
        self.name = 'Silence'
        self.secure_from = set()
        self.scannerVulnTreeNode = None
        self.value = Utility.getTokenObject(self.raw_data[1]['expr'], self.scanner)
        self.vulnTreeNode = self.getVulnNode()
        self.lnr = self.raw_data[1]['lineno']
    
    def __str__(self):
        return "@%s" % self.value

    def isuserinput(self):
        return self.value and self.value.userinput

    def getVulnNode(self):
        if hasattr(self.value, 'secure_from') and self.value.secure_from:
            self.secure_from = self.secure_from.union( self.value.secure_from)
        if self.value.vulnTreeNode and self.value.vulnTreeNode.sink_vuln:
            self.scannerVulnTreeNode = self.value.vulnTreeNode

        return self.value.vulnTreeNode

class Node:
    def __init__(self, raw_data='', scanner=None):
        self.raw_data = raw_data
        self.scanner = scanner
        self.vulnTreeNode = None
        self.userinput = False 
        self.name = ''
        self.value = ''
        self.lnr = 0

class Include:
    def __init__(self, raw_data, scanner):
        self.scanner = scanner
        self.raw_data = raw_data
        self.file_path = self.__getFilePath()
        self.lnr = self.raw_data[1]['lineno']

    def __getFilePath(self):
        exprObject = Utility.getTokenObject(self.raw_data[1]['expr'], self.scanner)
        
        if hasattr(exprObject, 'computed_value'):
            return exprObject.computed_value
        return None

    def fileExists(self):
        import os
        return self.file_path and os.path.exists(self.file_path)


    def getPHPFile(self):
        from analyze.ProjectHandler import ProjectHandler
        from analyze.PHPFile import PHPFile

        if self.fileExists():
            #check if the file is already scanned
            if ProjectHandler.fileHandler.getFile(self.file_path):
                return ProjectHandler.fileHandler.getFile(self.file_path)

            else:
                from analyze.scanner import Scanner
                return PHPFile(self.file_path)
        else:
            return None

    
class ForEachKey:
    def __init__(self, name,lnr, value, scanner):
        self.name = name 
        self.scanner = scanner
        self.lnr = lnr 
        self.value = value 
        self.userinput = self.isuserinput()
    
    def isuserinput(self):
        return self.value.userinput
class ForEachValue:
    def __init__(self, raw_data, value, scanner):
        self.scanner = scanner
        self.raw_data = raw_data
        self.lnr = raw_data[1]['name'][1]['lineno']
        self.name = raw_data[1]['name'][1]['name']
        self.value = value
        self.userinput = self.isuserinput()

    def isuserinput(self):
        return self.value.userinput

class ForEach:
    def __init__(self, raw_data, scanner):
        from analyze.scanner import Scanner
        
        self.scanner = scanner
        self.raw_data = raw_data
        #without and with curly brace 
        nodes = self.raw_data[1]['node'][1].get('nodes', [self.raw_data[1]['node']])
        self.loopScanner = Scanner(nodes, scanner, file_name=scanner.file_name)

        self.value = self.__getExpr(self.raw_data[1]['expr'])
        self.lnr = self.raw_data[1]['lineno']

        self.keyVar = self.getKeyAssignment(self.raw_data[1]['keyvar'])
        self.forEachValue = self.getValueAssignment(self.raw_data[1]['valvar'])
        self.vulnTreeNode = None

        self.loopScan()
        

    def getKeyAssignment(self, keyVar):
        if not keyVar:
            return
        forEachKey = VarDeclared(ForEachKey(keyVar[1]['name'], keyVar[1]['lineno'], self.value, self.scanner))
        self.loopScanner.variables[forEachKey.name] = VarDeclared(forEachKey)
        return forEachKey
    
    def getValueAssignment(self, value):
        forEachValue = VarDeclared(ForEachValue(value, self.value, self.scanner))
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
        nodes = raw_data[1]['node'][1].get('nodes', [raw_data[1]['node']])
        self.loopScanner = Scanner(nodes, file_name=scanner.file_name)

        self.lnr = raw_data[1]['lineno']
        self.start = self.__getAssignments( raw_data[1]['start'])
        self.count = self.__getAssignments( raw_data[1]['count'])
        self.vulnTreeNode = None

        self.loopScan()

    def __getAssignments(self,  data ):
        if not data:
            return
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
        self.ifScanner = Scanner(self.getNodes(), scanner, file_name=scanner.file_name)
        self.lnr = raw_data[1]['lineno']
        self.vulnTreeNode = None
        self.getExpr()
        self.ifScan()
        self.getExtraParams()

    def getExpr(self):
        if self.raw_data[1].get('expr'):
            self.expr = Utility.getTokenObject( self.raw_data[1]['expr'], self.scanner)

    def getNodes(self):
        if self.raw_data[1]['node'][1].get('nodes'):
            return self.raw_data[1]['node'][1].get('nodes')
        
        return [self.raw_data[1]['node']]


    def getExtraParams(self):
        return None
    
    def ifScan(self):
        scannedVulnTreeNode = self.ifScanner.scan()

        if scannedVulnTreeNode.length():
            self.vulnTreeNode = VulnTreeNode( 'Requires %s' %( self.__str__()), self.lnr, '' )
            self.vulnTreeNode.addChildrenFromTree( scannedVulnTreeNode)

        if hasattr(self, 'expr') and self.expr:
            if self.expr.vulnTreeNode:
                self.scanner.vulnTree.addVuln(self.expr.vulnTreeNode)

        self.scanner.mergeScannerData(self.ifScanner)
    
    def getStr(self):
        if  hasattr(self, 'expr') and self.expr:
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

        return self.raw_data[1]['node'][1]['nodes'] if self.raw_data[1]['node'][1].get('nodes') else [self.raw_data[1]['node']]

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
        
        return self.element.userinput
    
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
            if element.userinput:
                
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
        self.scannerVulnTreeNode = None

        self.secure_from = set()
        self.right = self.__getOperand(raw_data[1]['right'])
        
        self.left = self.__getOperand(raw_data[1]['left'])
        self.lnr = raw_data[1]['lineno']
        self.op = raw_data[1]['op']
        self.scanVuln()
        self.userinput = self.isuserinput()
        self.computed_value = self.__computeValue()

    def isOr(self):
        return self.op == TokenName.T_OROP

    def isConcat(self):
        return self.op == TokenName.T_VULNBINARYOP

    def __computeValue(self):
        if self.isConcat() and hasattr(self.right, 'computed_value') and hasattr(self.left, 'computed_value'):
            if self.right.computed_value and self.left.computed_value:
                return str(self.left.computed_value) + str(self.right.computed_value)
        
        return None

    def getVulnTreeNode(self):
        if not self.vulnTreeNode:
            self.vulnTreeNode = VulnTreeNode('Unsanitized input is used inside the binary operation ', self.lnr, self.__str__(), is_rootable=False)

    def scanVuln(self):
        if self.isConcat() or self.isOr():
            if hasattr(self.right, 'secure_from') and hasattr(self.left, 'secure_from'):
                self.secure_from = self.left.secure_from.intersection( self.right.secure_from)
            
            elif hasattr(self.left, 'secure_from') :
                self.secure_from = self.secure_from.union( self.left.secure_from)
    
            elif hasattr(self.right, 'secure_from') :
                self.secure_from = self.secure_from.union( self.right.secure_from)

            if self.right and self.right.vulnTreeNode:
                #self.getVulnTreeNode()
                self.vulnTreeNode = self.right.vulnTreeNode
                
                if self.right.vulnTreeNode.sink_vuln:
                    self.scannerVulnTreeNode = self.right.vulnTreeNode
            
            if self.left and self.left.vulnTreeNode:
                #self.getVulnTreeNode()
                self.vulnTreeNode = self.left.vulnTreeNode
                if self.left.vulnTreeNode.sink_vuln:
                    self.scannerVulnTreeNode = self.left.vulnTreeNode

            return self.right.userinput or self.left.userinput     
        return False
            
    def isuserinput(self):
        if self.isConcat() or self.isOr():
            return self.right.userinput or self.left.userinput
        
        return False

    def __getOperand(self, expr):
        
        return Utility.getTokenObject(expr, self.scanner)
    
    def __str__(self):

        return "%s %s %s" % (self.left.__str__(), self.op, self.right.__str__())

class ArrayOffset():
    def __init__(self, raw_data,scanner):

        self.scanner = scanner
        self.vulnTreeNode = None

        self.name = self.__setName(raw_data[1]['node'])
        self.nameObject = self.getNameObject(raw_data[1]['node'])
        self.lnr = raw_data[1]['node'][1]['lineno']
        self.key = raw_data[1]['expr']
        self.scanVuln()

        self.userinput = self.isuserinput() 
        self.secure_from = set()


    def __str__(self):
        return "%s[%s]" % (self.name , self.key)

    def getNameObject(self, name_node):
        return Utility.getTokenObject(name_node, self.scanner )

    def __setName(self, name_node):
        if name_node[0] == TokenName.T_VARIABLE:
            return name_node[1]['name']
        elif name_node[0] == TokenName.T_ARRAYOFFSET:
            return str(ArrayOffset(name_node, self.scanner))

    def scanVuln(self):
        if self.nameObject.userinput:
            self.vulnTreeNode = self.nameObject.vulnTreeNode

        elif self.name in self.scanner.sources and not self.vulnTreeNode:
            self.vulnTreeNode = VulnTreeNode( "Sensitive sink used", self.lnr, self.__str__())
         
    def isuserinput(self):
        if self.vulnTreeNode:
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
        self.className = self.instance = self.getClassName(raw_data[1]['name'])
        self.lnr = raw_data[1]['lineno']
        self.vulnTreeNode = None
        self.userinput = self.isuserinput()

    def getClassName(self, nameData):
        classNameObj = Utility.getTokenObject(nameData,self.scanner)
        if isinstance(classNameObj, Literal):
            return classNameObj.value
        
        if isinstance(classNameObj, VarAccess):
            varDeclared = self.scanner.variables.get(classNameObj.name)
            if varDeclared and varDeclared.computed_value:
                return classNameObj.computed_value
            
        
        return None


    def isuserinput(self):
        if not self.className:
            return False

        pClass = self.scanner.classes.get(self.className, None)
        if pClass:
            constructor = pClass.scanner.functions.get(TokenName.T_CONSTRUCT)
            if constructor:
                self.raw_data[1]['name'] = TokenName.T_CONSTRUCT
                methodCall = MethodCall(self.raw_data, self.scanner)
                if methodCall.vulnTreeNode and methodCall.vulnTreeNode.vulnerable():
                    self.vulnTreeNode = VulnTreeNode('The constructor of the class %s is insecure. ' % self.className, self.lnr, self.__str__())
                    self.vulnTreeNode.addChildren(methodCall.vulnTreeNode)

                return methodCall.userinput
        
        return False

    
    def __str__(self):
        return 'new %s()' %self.className
    

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
        self.computed_value = self.__computeValue()

    def __computeValue(self):
        if self.var and hasattr(self.var, 'computed_value'):
            return self.var.computed_value 
        
        return None 

    def isuserinput(self):
        return self.userinput;

    def getVulnTeeNode(self):
        if hasattr(self.var, 'vulnTreeNode'):
            return self.var.vulnTreeNode
        
        return None

    def getUserInput(self):
        return self.var.userinput if self.var else False
    
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
        return self.name

class IsSet(Node):
    def __init__(self, raw_data, scanner):
        self.name = "isset"
        self.scanner = scanner
        self.raw_data = raw_data
        self.userinput = self.isuserinput() 
        self.vulnTreeNode = None
        self.lnr = raw_data[1]['lineno']
        self.nodes = [ str(Utility.getTokenObject(node, scanner) ) for node in self.raw_data[1]['nodes']]
    
    def isuserinput(self):
        return False
    
    def __str__(self):
        return "%s(%s)" % ('isset', ', '.join(self.nodes) )
class Define:
    def __init__(self, functionCall):
        self.function_call = functionCall
        self.scanner = self.function_call.scanner
        self.vulnTreeNode = None
        self.secure_from = set()
        self.executeFunc()
        
    def executeFunc(self):
        params = self.function_call.getFuncCallParms()

        if len(params) < 2:
            return
        if isinstance(params[0].value, Literal):
            
            self.name = params[0].value.value
            self.lnr = params[0].lnr
            self.value = params[1].value
            self.getVulnTreeNode()

            self.userinput = params[1].userinput
            self.scanner.variables[self.name] = VarDeclared(self)
   
    def getVulnTreeNode(self):
        
        if hasattr(self.value, 'vulnTreeNode') and self.value.vulnTreeNode:
            self.vulnTreeNode = VulnTreeNode('Unsanitized value is assigned to the constant', self.lnr, self.__str__(), is_rootable=False)
            self.vulnTreeNode.addChildren(self.value.vulnTreeNode)

        if hasattr(self.value, 'secure_from'):
            self.secure_from = self.secure_from.union(self.value.secure_from)


    def __str__(self):
        return "%s %s" % (self.name , self.value )


class FunctionCall:
    def __init__(self, raw_data,scanner):
        self.scanner = scanner
        self.name = raw_data[1]['name']
        self.lnr = raw_data[1]['lineno']
        self.param_raw_data = raw_data[1]['params']
        self.params = self.getFuncCallParms()
        self.vulnTreeNode = None
        self.secure_from = set()
        self.userinput = self.scanVuln()
    
    def isuserinput(self):
        return self.userinput

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


    def scanVuln(self):
        from analyze.scanner import Scanner

        if self.name == TokenName.T_DEFINE:
            define = Define(self)

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
                    if param_ind-1 < len(self.params):
                        params.append(self.params[param_ind-1])

            not_secure = False 
            for param in params:
                if hasattr(param, 'secure_from'):
                    if self.name.lower() in param.secure_from:
                        continue
                    elif param.vulnTreeNode:
                        if not self.vulnTreeNode:
                            self.vulnTreeNode = VulnTreeNode('A sink function is called with unsanitized parameter. This causes potential %s' % ( vulnName.upper()), self.lnr, self.__str__())                
                            self.vulnTreeNode.addPatch(sinkInfo[1] )
                            self.vulnTreeNode.sink_vuln = True

                        if param.vulnTreeNode:
                            self.vulnTreeNode.addChildren( param.vulnTreeNode)
                            self.vulnTreeNode.sink_vuln = True
                        
                        not_secure = True

            return not_secure 
        elif self.name in self.scanner.sources:
            return True

        elif self.scanner.securingFor( self.name ):
            self.secure_from = self.secure_from.union( self.scanner.securingFor( self.name ))    
            for param in self.params:
                if param.userinput:
                    return True

        elif self.scanner.in_class:
            return False
        else:
            for param in self.params:
                if hasattr(param, 'secure_from'):
                    if self.name.lower() in param.secure_from:
                        continue
                    elif param.vulnTreeNode:
                        self.vulnTreeNode = param.vulnTreeNode
                        return True
            return False

    def getFunction(self, scanner=None):
        if not scanner:
            scanner = self.scanner

        return scanner.functions.get(self.name)

    def taintScanFunction(self, scanner=None):
        function = self.getFunction(scanner)
        if not function:
            return True

        param_names = []
        #loops through the function parameters
        for function_param in function.params:
            param_names.append( function_param.name )

        function_params = self.getParams(param_names )
        to_taint_params_index = []
        for index, function_param in enumerate(function_params):
            if function_param.userinput:
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
            if index >= len(self.param_raw_data):
                continue

            assignment = Assignment(self.scanner, object_data=FunctionCallArgument(param_name, self.lnr, self.param_raw_data[index]) )
            params.append( VarDeclared(assignment))
        
        return params


class Literal():
    def __init__(self, data):
        self.name = 'literal'
        self.value = data
        self.vulnTreeNode = None
        self.computed_value = self.__computeValue()
        self.userinput = self.isuserinput()
    def __computeValue(self):
        return self.value

    def isuserinput(self):
        return False

    def __str__(self):
        return str(self.value)

class MagicConstant:
    def __init__(self, scanner, raw_data):
        self.lnr = raw_data[1]['lineno']
        self.scanner = scanner
        self.raw_data = raw_data
        self.vulnTreeNode = None
        self.value = self.computed_value = self.__getValue()
        self.name = raw_data[1]['name']
        self.userinput = self.isuserinput()
        self.secure_from = {}

    def isuserinput(self):
        return False

    def __getValue(self):
        self.value = self.raw_data[1]['name']
        if self.value == TokenName.T__FILE__:
            return self.scanner.file_name
        return self.value
    
    def __str__(self):
        return "%s" %(self.value)

class Constant:
    def __init__(self,scanner, data):
        self.scanner = scanner
        self.name = data[1]['name']
        self.lnr = data[1]['lineno']
        self.value = self.getValue()
        self.secure_from = self.__getSecureFrom()
        self.userinput = self.isuserinput()
        self.computed_value = self.__computeValue()
        self.vulnTreeNode = self.getVulnTreeNode()

    def getValue(self):
        return self.scanner.variables.get(self.name)

    def isuserinput(self):
        return self.value and self.value.userinput

    def __computeValue(self):
        if self.value and hasattr(self.value, 'computed_value'):
            return self.value.computed_value
        
        return None
    
    def getVulnTreeNode(self):
        return self.value and self.value.vulnTreeNode
    
    def __getSecureFrom(self):
        if self.value and hasattr(self.value, 'secure_from'):
            return self.value.secure_from
        else:
            return set()

    def __str__(self):
        return self.name

class Assignment():
    def __init__(self,scanner,raw_data=None, object_data=None):
        self.scanner = scanner
        self.scannerVulnTreeNode = None
        if raw_data:
            self.name = self.__setName(raw_data[1]['node'])
            self.lnr = raw_data[1]['node'][1]['lineno']
            self.value = self.__setValue(raw_data[1]['expr'])
            
        elif object_data:
            self.name = object_data.name 
            self.lnr = object_data.lnr 
            self.value = self.__setValue( object_data.expr )
        self.is_safe = True 

    def __setName(self, name_node):
        if name_node[0] == TokenName.T_VARIABLE:
            return name_node[1]['name']
        elif name_node[0] == TokenName.T_ARRAYOFFSET:
            return str(ArrayOffset(name_node, self.scanner))

    def __setValue(self, values):
        return Utility.getTokenObject(values, self.scanner)
    
    def __str__(self):
        return '%s = %s' % (self.name , str(self.value) )


class VarDeclared():
    def __init__(self, assignment):
        self.scanner = assignment.scanner
        self.name = assignment.name
        self.value = assignment.value
        self.lnr = assignment.lnr
        self.vulnTreeNode = None
        self.scannerVulnTreeNode = None

        self.instance = self.getInstance()
        self.computed_value = self.__computeValue()
        # list of security vulns 
        self.secure_from = set()
        self.getVulnTreeNode()
        self.userinput = self.isuserinput()
        self.declareVariable(assignment)

    def __computeValue(self):
        if self.value and hasattr(self.value, 'computed_value'):
            return self.value.computed_value
        
        return None

    def isuserinput(self):
        if self.value:
            return self.value.userinput
    
    def getInstance(self):
        if hasattr(self.value, 'instance'):
            return self.value.instance
        
        return None

    def getVulnTreeNode(self):
        
        if hasattr(self.value, 'vulnTreeNode') and self.value.vulnTreeNode :
            self.vulnTreeNode = VulnTreeNode('', self.lnr, self.__str__(),is_rootable=False)

            if self.value.vulnTreeNode.sink_vuln:
                self.scannerVulnTreeNode = self.vulnTreeNode = self.value.vulnTreeNode

        if hasattr(self.value, 'secure_from'):
            self.secure_from = self.secure_from.union(self.value.secure_from)

    def __str__(self):
        return "%s = %s" % ( self.name, str(self.value))

    def declareVariable(self, assignment):
        
        assignment.scanner.variables[self.name] = self
        

class FunctionParam:
    def __init__(self, parameterData, scanner):
        self.node = parameterData[1]['node']
        self.value = Utility.getTokenObject(self.node, scanner)
        self.lnr = parameterData[1]['lineno']
        self.secure_from = set()
        self.vulnTreeNode = None
        self.__setParams()
        self.userinput = self.isuserinput()

    def isuserinput(self):
        return self.value.userinput

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
        self.userinput = self.isuserinput()

    def isuserinput(self):
        return self.value.userinput

    def __scanVuln(self):
        if self.value.userinput:
            self.vulnTreeNode = VulnTreeNode('%s returns usanitized data' % (self.function.name), self.lnr, self.__str__(), is_rootable=False)
            
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
        self.scanner = Scanner(self.nodes, scanner, file_name=scanner.file_name)
        self.name = self.raw_data['name']
        self.lnr = self.raw_data['lineno']
        self.params = self.set_params()
        self.taintable_params = self.set_params()
        self.userinput = False 
        self.secure = True

        #control if the tainted version of variables is being used
        self.tainted = False 
        self.vulnTreeNode = None
        self.getVulns()

    def isuserinput(self):
        return self.userinput

    def getVulns(self):
        vulnTree = self.scanVuln()
        if vulnTree.length() > 0:
            self.vulnTreeNode = VulnTreeNode('The function %s is suscetible to potential security vulnerability' %(self.name), self.lnr)
            self.vulnTreeNode.addChildrenFromTree( vulnTree )
        
    def __unicode__(self):
        return self.name

    def isSecure(self):
        return self.secure

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

        # check if the function parameters are passed. Or if it just Function defintion. 
        #if function call, the function has to be redefined with the provided parameter values 
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
        #check if the method has been visisted already 
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

class ClassVariable(Node):
    
    def __init__(self, raw_data, scanner):
        self.raw_data = raw_data
        self.scanner =scanner
        self.value = self.getInitial()
        self.name = self.raw_data[1]['name']
        self.lnr = self.raw_data[1]['lineno']
        self.userinput = self.isuserinput()

    def getInitial(self):
        return Utility.getTokenObject(self.raw_data[1]['initial'], self.scanner)

    def isuserinput(self):
        return self.value.userinput

class ClassVariables(Node):
    def __init__(self, raw_data, scanner):
        self.raw_data = raw_data
        self.scanner =scanner
        self.lnr = self.raw_data[1]['lineno']
        self.classVariables = [ VarDeclared(ClassVariable(node, scanner)) for node in self.raw_data[1]['nodes'] ]

    def setClassVariables(self):
        for classVariable in self.classVariables:
            self.scanner.variables[classVariable.name] = classVariable;

class ObjectProperty:
    this = '$this'
    def __init__(self, raw_data, scanner):
        #$obj->attr
        self.scanner = scanner
        self.raw_data = raw_data
        self.vulnTreeNode = None
        self.name =  raw_data[1]['name']  #attr
        self.lnr =  raw_data[1]['lineno']
        self.node = raw_data[1].get('node', None)
        self.objct_name = self.getObjectName() #$obj
        self.userinput = self.isuserinput()

    def getObjectName(self):
        if not self.node:
            return None
        elif self.node[0] == TokenName.T_VARIABLE:
            variableName = self.node[1]['name']
            return variableName
        
        return None
    
    
    def getClass(self, className):
        return self.scanner.classes.get(className)

    def isuserinput(self):

        if self.objct_name == ObjectProperty.this:
            if self.scanner.parentScanner and self.scanner.parentScanner.variables.get(self.name):
                classVariable = self.scanner.parentScanner.variables.get(self.name)
                
                if classVariable.vulnTreeNode:
                    self.vulnTreeNode = classVariable.vulnTreeNode

                return classVariable.userinput
            else:
                return False
        else:
            objVar =  self.scanner.variables.get(self.objct_name)
            if hasattr(objVar, 'instance') and objVar.instance:
                pClass =  self.getClass(objVar.instance)
                if pClass:
                    classVariable = pClass.scanner.variables.get(self.name)
                    if classVariable.vulnTreeNode:
                        self.vulnTreeNode = classVariable.vulnTreeNode

                    return classVariable.userinput

        return False
        
    def __str__(self):
        if self.name:
            return '%s->%s' %( self.objct_name, self.name )
     

class PClass:
    def __init__(self, raw_data, parentScanner):
        self.parentScanner = parentScanner

        self.raw_data = raw_data
        self.name = raw_data[1]['name']
        self.lnr = raw_data[1]['lineno']
        self.extends = self.__extends(raw_data[1]['extends'])
        from analyze.scanner import Scanner

        self.nodes = self.raw_data[1]['nodes']
        self.scanner = Scanner(self.nodes, parentScanner, file_name=parentScanner.file_name)

        self.methods = self.__getMethods()
        self.vulnTreeNode = None
        self.scanVuln()

    def __extends(self, parentClass):
        if parentClass:
            parentClass = self.parentScanner.classes.get(parentClass, None)
            if parentClass:
                self.scanner.mergeScannerData( parentScanner ) 
        
        return Node

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