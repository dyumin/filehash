#include "mapped_chunk.h"
#include "fdhandle.h"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/crc.hpp>

#include <iostream>
#include <filesystem>
#include <thread>
#include <algorithm>
#include <atomic>
#include <fstream>
#include <condition_variable>
#include <iterator>

#include <fcntl.h> // open
#include <sys/mman.h> // mmap
#include <unistd.h> // sysconf
#include <sys/types.h>

int main(int argc, char* argv[])
{
    try
    {
        using namespace boost::program_options;
        auto desc = boost::program_options::options_description(
            std::string("filehash") + "\nOptions"
        );
        std::string inputFile;
        std::string outputFile;
        uintmax_t blockSize = 1024;
        desc.add_options()
            ("help", "produce help message")
            ("input-file", boost::program_options::value(&inputFile)->required(), "Path to input file to hash, must be readable")
            ("output-file", boost::program_options::value(&outputFile)->required(), "Path to output file to store hash result to, must be writable")
            ("block-size", boost::program_options::value(&blockSize), "Block size to hash, bytes");

        variables_map vm;
        store(parse_command_line(argc, argv, desc), vm);

        if (vm.count("help"))
        {
            std::cout << desc << std::endl;
            return 1;
        }

        notify(vm);

        std::ifstream file(inputFile, std::ios::binary);
        std::vector<uint8_t> data;
        std::vector<boost::crc_32_type::value_type> hashes;
        int i = 0;
        for(auto it = std::istreambuf_iterator<char>{file}; it != std::istreambuf_iterator<char>();)
        {
            data.push_back(*it++);
            if (data.size() == blockSize || (it == std::istreambuf_iterator<char>()))
            {
                if (it == std::istreambuf_iterator<char>())
                {
                    std::cout << "file end reached" << std::endl;
                }
                boost::crc_32_type crc32;
                crc32.process_bytes(data.data(), data.size());
                hashes.push_back(crc32.checksum());
                data.clear();
            }
        }

        std::ofstream hash(outputFile, std::ios::binary | std::ios::trunc);
        hash.write(reinterpret_cast<const char*>(hashes.data()), hashes.size() * 4);
        hash.flush();
    }
    catch (const std::exception& ex)
    {
        std::cout << "Error: " << ex.what();
        return -1;
    }

    return 0;
}
