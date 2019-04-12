import os



os.chdir("FourThreadsPerBlockSBConst256")
os.system("nvcc kernel.cu -o kernel -std=c++11")
os.chdir("..")

os.chdir("FourThreadsPerBlockSBConst512")
os.system("nvcc kernel.cu -o kernel -std=c++11")
os.chdir("..")

os.chdir("FourThreadsPerBlockSBShared256")
os.system("nvcc kernel.cu -o kernel -std=c++11")
os.chdir("..")

os.chdir("FourThreadsPerBlockSBShared512")
os.system("nvcc kernel.cu -o kernel -std=c++11")
os.chdir("..")

os.chdir("OneThreadPerBlockSBConst256")
os.system("nvcc kernel.cu -o kernel -std=c++11")
os.chdir("..")

os.chdir("OneThreadPerBlockSBConst512")
os.system("nvcc kernel.cu -o kernel -std=c++11")
os.chdir("..")

os.chdir("OneThreadPerBlockSBShared256")
os.system("nvcc kernel.cu -o kernel -std=c++11")
os.chdir("..")

os.chdir("OneThreadPerBlockSBShared512")
os.system("nvcc kernel.cu -o kernel -std=c++11")
os.chdir("..")

os.chdir("Host")
os.system("g++ host.cpp -o host -std=c++11")
os.chdir("..")