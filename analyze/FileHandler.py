class FileHandler:
    def __init__(self):
        self.files = {}
    
    def addFile(self, phpFile):
        self.files[phpFile.file_name] = phpFile
    
    def getFile(self, file_name):
        return self.files.get(file_name, None)