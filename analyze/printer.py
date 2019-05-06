class Printer:
    def __init__(self, vulns):
        self.vulns = vulns
    
    def display(self):
        for vulnBlock in self.vulns:
            print vulnBlock.title