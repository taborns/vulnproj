class Printer:
    def __init__(self, vulnTree):
        self.vulnTree = vulnTree
        self.display()

    def display(self):
        for vuln in self.vulnTree.vulns:
            if not vuln.is_rootable:
                continue

            print '=> %2s' % ( str(vuln))
    
            vuln.display()
            
            if vuln.patch_methods:
                print "%2s [=>]Patches : %s " %( '', ', '.join(vuln.patch_methods))
                            
            print "---" * 20