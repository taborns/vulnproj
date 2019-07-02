from phplex import lexer
from phpparse import make_parser
from analyze.scanner import Scanner
from analyze.printer import Printer
from analyze.FileHandler import FileHandler
from analyze.PHPFile import PHPFile
import os,os.path,sys,shutil,simplejson,random,hashlib
import zipfile
class ProjectHandler:
    fileHandler = FileHandler()
    parser = make_parser()
    FILETYPES = [						# filetypes to scan
		'.php', 
		'.inc', 
		'.phps', 
		'.php4', 
		'.php5', 
		'.html', 
		'.htm', 
		'.txt',
		'.phtml', 
		'.tpl',  
		'.cgi',
		'.test',
		'.module',
		'.plugin'
	]

    @staticmethod
    def unzipFolder(zipName):
        output_directory_arr = []
        for i in range(100):
            output_directory_arr.append(str(random.randint(1000,1000000000)))

        output_directory = ''.join(output_directory_arr)
        from hashlib import md5
        m = hashlib.md5()
        m.update( output_directory )
        output_directory =  m.hexdigest()
        zip_file = zipfile.ZipFile(zipName, "r")
        zip_file.extractall(output_directory)
        zip_file.close()

        return output_directory        
    @staticmethod
    def getFiles(dir_path):
        file_paths = []
        dirs = [dir_path]
        counter = 0
        while True:
            if counter == len(dirs):
                break
            cur_dir = dirs[counter]
            files = os.listdir(cur_dir)

            for name in files:
                full_path = os.path.join(cur_dir, name)
                if os.path.isdir(full_path):
                    dirs.append(full_path)
                else:
                    filename, file_extension = os.path.splitext(full_path)
                    if file_extension in ProjectHandler.FILETYPES:
                        file_paths.append( full_path )
            counter +=1
        
        return file_paths
                    
        

    @staticmethod
    def handle(zipName):
        output_directory = ProjectHandler.unzipFolder(zipName)
        #os.remove(zipName)
        file_paths = ProjectHandler.getFiles(output_directory)

        for file_path in file_paths:
            phpFile = PHPFile(file_path)
            ProjectHandler.fileHandler.addFile(phpFile)
            phpFile.handle()

        shutil.rmtree(output_directory)
        # simplejson.dump(tokens,output, indent=2)
        # output.write('\n')
