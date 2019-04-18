import zipfile

file_name = "test_zip.zip"
output_directory = "test_zip"
zip_file = zipfile.Zipfile(file_name, "r")
zip_file.extractall(output_directory)
zip_file.close()


