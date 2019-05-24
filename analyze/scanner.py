from analyze.sink_points import * 
from analyze.source_points import * 
from analyze.securing_functions import *
from analyze.classes import *

class Scanner:
    
    
    def __init__(self, tokens, parentScanner=None):
        self.parentScanner = parentScanner
        if parentScanner:
            self.importScanParamsFromParent()
        else:
            self.setScanParams()

        self.in_function = False
        self.context_object = self
        self.in_class = False 
        self.context_name = TokenName.GLOBAL_SCOPE
        self.getSources()
        self.tokens = tokens 
        self.vulnTree = VulnTree()

    def getSources(self):
        self.sources = Sources.V_USERINPUT +  Sources.V_SERVER_PARAMS + Sources.F_FILE_INPUT + Sources.F_DATABASE_INPUT + Sources.F_OTHER_INPUT
    
    def getSinks(self):

        sinks = {
                        NAME_XSS : F_XSS,
                        NAME_HTTP_HEADER : F_DATABASE,
                        NAME_CODE : F_CODE
        }

        return sinks

    def securingFor(self, funcName):
        securingFuncs = set()
        funcName = funcName.lower()
        for sinkKey in self.sinks:
            vulnSinks = self.sinks[sinkKey]
            for vulnSink in vulnSinks:
                if funcName in vulnSinks[vulnSink][1]:
                    securingFuncs.add( vulnSink)

        
        return securingFuncs
    
    def getSink(self, funcName):
        funcName = funcName.lower()
        for sinkKey in self.sinks:
            vulnSinks = self.sinks[sinkKey]

            if vulnSinks.get( funcName):
                return vulnSinks.get(funcName), sinkKey
        
        return None

    def mergeScannerData(self, otherScanner):
        self.variables.update(otherScanner.variables) 
        self.functions.update(otherScanner.functions) 
        self.vulnTree.merge( otherScanner.vulnTree )

    def importScanParamsFromParent(self):

        self.sinks = self.parentScanner.getSinks()
        self.sources = self.parentScanner.sources
        self.securingFuncs = self.parentScanner.securingFuncs
        self.variables = self.parentScanner.variables
        self.functions = self.parentScanner.functions
        self.classes = self.parentScanner.classes
        self.yet_to_scan_functions = self.parentScanner.yet_to_scan_functions

    def setScanParams(self):
        self.sinks = self.getSinks()
        self.sources = Sources.V_USERINPUT
        self.securingFuncs = F_SECURING_XSS
        self.variables = {}
        self.classes = {}
        self.functions = {}
        self.yet_to_scan_functions = {} 


    def scan(self):
        for token in self.tokens:
            #Variable Assignment 
            if token[0] == TokenName.T_ASSIGNMENT:

                assignment = Assignment(self, raw_data=token)
                varDeclared = VarDeclared(assignment)
                self.variables[varDeclared.name] = varDeclared
                
                if varDeclared.vulnTreeNode:
                    self.vulnTree.addVuln(varDeclared.vulnTreeNode)


            #Function defintion 
            elif token[0] == TokenName.T_FUNCTION or token[0] == TokenName.T_METHOD:

                function = Function(token, self)
                self.functions[function.name] = function

                if function.vulnTreeNode:
                    self.vulnTree.addVuln(function.vulnTreeNode)

                yet_to_scan_function = self.yet_to_scan_functions.pop(function.name, None)

                if yet_to_scan_function:
                    funcVulnTree = self.functions[yet_to_scan_function].scanVuln()
                    if funcVulnTree:
                        self.vulnTree.merge( funcVulnTree )

            elif token[0] == TokenName.T_FUNCTIONCALL:
                functionCall = FunctionCall(token, self)
                if functionCall.vulnTreeNode:
                    self.vulnTree.addVuln(functionCall.vulnTreeNode)

            #class 
            elif token[0] == TokenName.T_CLASS:
                pClass = PClass(token, self)
                self.classes[pClass.name] = pClass

                if pClass.vulnTreeNode:
                    self.vulnTree.addVuln( pClass.vulnTreeNode )

            #method call 
            elif token[0] == TokenName.T_METHODCALL:
                methodName = None 

                if self.in_function:
                    methodName = self.context_name

                methodCall = MethodCall(token, self, methodName)
                if methodCall.vulnTreeNode:
                    self.vulnTree.addVuln(methodCall.vulnTreeNode)
    
            elif token[0] == TokenName.T_NEW:
                classInst = NewClass(token, self)
                self.vulnTree.addVuln(classInst.vulnTreeNode)
            
            elif token[0] == TokenName.T_ARRAY:
                array = Array(token, self)
                self.vulnTree.addVuln(array.vulnTreeNode)
            
            elif token[0] == TokenName.T_BINARYOP:
                binaryOp = BinaryOp(token, self)
                self.vulnTree.addVuln(binaryOp.vulnTreeNode)

            elif token[0] == TokenName.T_FOREACH:
                foreach = ForEach(token, self)
            
            elif token[0] == TokenName.T_FOR:
                forloop = ForLoop(token, self)
            
            elif token[0] == TokenName.T_IF:
                ifblock = IfMain(token, self)
                self.vulnTree.addVuln(ifblock.vulnTreeNode)

            elif token[0] == TokenName.T_RETURN:
                if self.in_function:
                    returnstatement = Return(token, self.context_object, self)
                    self.vulnTree.addVuln(returnstatement.vulnTreeNode)
                        
            #Found Sink 
            elif self.getSink(token[0].lower()):
                    sink = Sink(token, self)
                    if sink.isVulnerable():
                        self.vulnTree.addVuln( sink.vulnTreeNode)
                    
        return self.vulnTree

                        

    #check if the variable is tainted 
    def scanParameter(self, name):

        newFind = None
        for global_variable in self.variables:
            if global_variable == name:
                newFind = self.variables[global_variable]
        
        if newFind:
            if not newFind.isuserinput():
                for dependency in newFind.dependencies:
                    if dependency.isuserinput():
                        return True
            else:
                return True
        
            
        

