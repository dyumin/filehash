
cd /tmp
git clone https://github.com/dyumin/filehash.git
cd filehash
mkdir build && cd build
cmake ..
cmake --build . --target filehash
./filehash --help


Output file is in binary, to view individual hashes run (in bash):
od -t 'u4' out_file