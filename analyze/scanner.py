from analyze.sink_points import * 
from analyze.source_points import * 
from analyze.classes import *

class Scanner:
    sinks = F_XSS
    sources = Sources.V_USERINPUT
    functions = {}
    
    def __init__(self, tokens):
        self.in_function = False
        self.in_class = False 
        self.context_name = TokenName.GLOBAL_SCOPE
        self.variables = {}
        self.functions = {}
        self.tokens = tokens 
        self.vulnTreeNode = VulnTreeNode()

    def scan(self):
        for token in self.tokens:

            #Variable Assignment 
            if token[0] == TokenName.T_ASSIGNMENT:
                assignment = Assignment(token)
                varDeclared = VarDeclared(assignment)
                varDeclared.userinput =  assignment.value.name in Scanner.sources
                self.variables[varDeclared.name] = varDeclared
            
            #Function defintion 
            elif token[0] == TokenName.T_FUNCTION:
                function = Function(token)
                Scanner.functions[function.name] = function
                self.vulnTreeNode.append(function.vulnTreeNode)

            #Found Sink 
            elif token[0].lower() in Scanner.sinks:
                sink_infos = Scanner.sinks[token[0].lower()]
                
                for sink_info in sink_infos[0]:
                    token_node = token[1]['nodes'][sink_info]

                    if token_node[0] == TokenName.T_VARIABLE:
                        unsafeUserInput = self.scanParameter( token_node[1]['name'] )

                        if unsafeUserInput:
                            if self.context_name == TokenName.GLOBAL_SCOPE:
                                vulnBlock = VulnBlock('Userinput reaches sensitive sink.')
                            
                            elif self.in_function:
                                vulnBlock = VulnBlock('Userinput reaches sensitive sink when function %s() is called.' %(self.context_name))

                            self.vulnTreeNode.addVuln(vulnBlock)
                    
                    elif token_node[0] == TokenName.T_FUNCTIONCALL:

                        functionCall = FunctionCall(token_node)
                        functionObject = Scanner.functions.get(functionCall.name)

                        if functionObject.isSecure():
                            vulnBlock = VulnBlock('Call triggers vulnerability in function %s' %(functionObject.name))
                            self.vulnTreeNode.addVuln(vulnBlock)
                        
        return self.vulnTreeNode
                        

    #check if the variable is tainted 
    def scanParameter(self, name):

        newFind = None
        for global_variable in self.variables:
            if global_variable == name:
                newFind = self.variables[global_variable]
        
        if newFind:
            if not newFind.isUserInput():
                for dependency in newFind.dependencies:
                    if dependency.isUserInput():
                        return True
            else:
                return True
        
            
        

