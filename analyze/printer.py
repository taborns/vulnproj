class Printer:
    def __init__(self, vulnTree):
        self.vulnTree = vulnTree
        self.display()

    def display(self):
        for vuln in self.vulnTree.vulns:
            print "[*] %s" % vuln
            vulnChildren = vuln.children
            
            for vuln_ in vuln.children:
                print"%2s [*] %s" % ('', vuln_)
                if vuln_.children:
                    for vuln_2 in vuln_.children:
                        print"%4s [*] %s" % ('', vuln_2)
                        if vuln_2.children:
                            for vuln_3 in vuln_2.children:
                                print"%6s [*] %s" % ('', vuln_3)
                                if vuln_3.children:
                                    for vuln_4 in vuln_3.children:
                                        print"%8s [*] %s" % ('', vuln_4)
                                        if vuln_4.children:
                                            for vuln_5 in vuln_4.children:
                                                print"%10s [*] %s" % ('', vuln_5)
                                                if vuln_5.children:
                                                    for vuln_6 in vuln_5.children:
                                                        print"%10s [*] %s" % ('', vuln_6)

            
            if vuln.patch_methods:
                print "%2s [=>]Pathes : %s " %( '', ', '.join(vuln.patch_methods))
                            
            print "---" * 20