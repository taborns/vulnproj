class Printer:
    def __init__(self, vulnTree):
        self.vulnTree = vulnTree
        self.display()

    def display(self):
        for vuln in self.vulnTree.vulns:
            print "[*] %s" % vuln
            for vuln_ in vuln.children:
                print"     [*] %s" % vuln_
                print "has children", len(vuln_.children)
            
            print "---" * 20