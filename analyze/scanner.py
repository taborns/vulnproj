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
        self.in_class = False 
        self.context_name = TokenName.GLOBAL_SCOPE

        self.tokens = tokens 
        self.vulnTree = VulnTree()

    def mergeScannerData(self, otherScanner):
        self.variables.update(otherScanner.variables) 
        self.functions.update(otherScanner.functions) 
        self.vulnTree.merge( otherScanner.vulnTree )

    def importScanParamsFromParent(self):

        self.sinks = self.parentScanner.sinks
        self.sources = self.parentScanner.sources
        self.securingFuncs = self.parentScanner.securingFuncs
        self.variables = self.parentScanner.variables
        self.functions = self.parentScanner.functions
        self.classes = self.parentScanner.classes
        self.yet_to_scan_functions = self.parentScanner.yet_to_scan_functions

    def setScanParams(self):
        self.sinks = F_XSS
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
                print "T_ASSIGNMENT"

                assignment = Assignment(self, raw_data=token)
                varDeclared = VarDeclared(assignment)
                self.variables[varDeclared.name] = varDeclared
                
                if varDeclared.vulnTreeNode:
                    self.vulnTree.addVuln(varDeclared.vulnTreeNode)


            #Function defintion 
            elif token[0] == TokenName.T_FUNCTION or token[0] == TokenName.T_METHOD:
                print "T_FUNC, T_METHOD"

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
                print "T_FUNCALL"
                functionCall = FunctionCall(token, self)
                self.vulnTreeNode.append(functionCall.vulnTreeNode)

            #class 
            elif token[0] == TokenName.T_CLASS:
                print "T_CLASS"
                pClass = PClass(token, self)
                self.classes[pClass.name] = pClass
                self.vulnTreeNode.append( pClass.vulnTreeNode )

            #method call 
            elif token[0] == TokenName.T_METHODCALL:
                print "T_METHODCALL"
                methodName = None 

                if self.in_function:
                    methodName = self.context_name

                methodCall = MethodCall(token, self, methodName)
                self.vulnTreeNode.append(methodCall.vulnTreeNode)
    
            elif token[0] == TokenName.T_NEW:
                print "T_NEW"
                classInst = NewClass(token, self)
                self.vulnTreeNode.append(classInst.vulnTreeNode)
            
            elif token[0] == TokenName.T_ARRAY:
                print "T_ARRAY"
                array = Array(token, self)
                self.vulnTreeNode.append(array.vulnTreeNode)
            
            elif token[0] == TokenName.T_BINARYOP:
                print "T_BINARYOP"
                binaryOp = BinaryOp(token, self)
                self.vulnTreeNode.append(binaryOp.vulnTreeNode)

            elif token[0] == TokenName.T_FOREACH:
                print "FOREACH"
                foreach = ForEach(token, self)
            
            elif token[0] == TokenName.T_FOR:
                print "For loop"
                forloop = ForLoop(token, self)
            
            elif token[0] == TokenName.T_IF:
                print "If Loop"
                ifblock = IfMain(token, self)
                self.vulnTree.addVuln(ifblock.vulnTreeNode)
                
            #Found Sink 
            elif token[0].lower() in self.sinks:

                sink_infos = self.sinks[token[0].lower()]
                nodes = []
                if len(sink_infos[0])> 0:
                    if sink_infos[0][0] == 0:
                        nodes = token[1]['nodes']

                for token_node in nodes:
                    if token_node[0] == TokenName.T_VARIABLE:
                        varAcess = VarAccess(self, token_node)
                        
                        if varAcess.isuserinput():
                            if self.context_name == TokenName.GLOBAL_SCOPE:
                                vulnTreeNode = VulnTreeNode('Userinput reaches sensitive sink', varAcess.lnr, "%s %s" % (token[0].lower(), str(varAcess) ))
                                vulnTreeNode.addChildren( varAcess.vulnTreeNode)
                            
                            elif self.in_function:
                                vulnTreeNode = VulnTreeNode('Userinput reaches sensitive sink when function %s() is called' %( token[0].lower()), varAcess.lnr, str(varAcess.__str__()) )

                            self.vulnTree.addVuln(vulnTreeNode)
                    
                    elif token_node[0] == TokenName.T_FUNCTIONCALL:

                        functionCall = FunctionCall(token_node, self)
                        
                        if functionCall.isuserinput():
                            vulnBlock = VulnBlock('Call triggers vulnerability in function %s' %(functionCall.name))
                            self.vulnTreeNode.addVuln(vulnBlock)
                            self.vulnTreeNode.append(functionCall.vulnTreeNode)
                    elif token_node[0] == TokenName.T_ARRAYOFFSET:

                        arrayOffset = ArrayOffset(token_node, self)
                        if arrayOffset.isuserinput():
                                vulnTree = VulnTreeNode('Userinput reaches sensitive sink', arrayOffset.lnr, arrayOffset.__str__() )
                                self.vulnTree.addVuln(vulnTree)
                    
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
        
            
        

