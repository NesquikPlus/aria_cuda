import os



os.chdir("FourThreadsPerBlockSBConst256")
os.system("rm output.txt")
os.chdir("..")

os.chdir("FourThreadsPerBlockSBConst512")
os.system("rm output.txt")
os.chdir("..")

os.chdir("FourThreadsPerBlockSBShared256")
os.system("rm output.txt")
os.chdir("..")

os.chdir("FourThreadsPerBlockSBShared512")
os.system("rm output.txt")
os.chdir("..")

os.chdir("OneThreadPerBlockSBConst256")
os.system("rm output.txt")
os.chdir("..")

os.chdir("OneThreadPerBlockSBConst512")
os.system("rm output.txt")
os.chdir("..")

os.chdir("OneThreadPerBlockSBShared256")
os.system("rm output.txt")
os.chdir("..")

os.chdir("OneThreadPerBlockSBShared512")
os.system("rm output.txt")
os.chdir("..")

os.chdir("Host")
os.system("rm output.txt")
os.chdir("..")