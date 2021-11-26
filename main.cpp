#include "fdhandle.h"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>

#include <iostream>
#include <filesystem>
#include <fcntl.h>

using helpers::FDHandle;

class FileHash final
{
public:
    FileHash(const std::filesystem::path& inputFile, std::filesystem::path outputFile, const size_t blockSize) : m_outputFile(std::move(outputFile)), m_blockSize(blockSize)
    {
        m_inputFileHandle = FDHandle(open(inputFile.c_str(), O_RDONLY)); // TODO: O_LARGEFILE, open64?
        if (!m_inputFileHandle)
        {
            const auto errnoCopy = errno;
            throw std::runtime_error(std::string("Failed to open inputFile ") + inputFile.string() + ", errno = " + std::to_string(errnoCopy));
        }

        std::error_code ec;
        m_fileSize = std::filesystem::file_size(inputFile, ec); // ignore error
        if (m_fileSize == 0)
        {
            throw std::runtime_error(std::string("inputFile ") + m_outputFile.string() + " size is zero, no hash to calculate");
        }

        std::filesystem::remove(m_outputFile, ec); // ignore error
        m_outputFileHandle = FDHandle(open(m_outputFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC)); // TODO: O_LARGEFILE, open64?
        if (!m_outputFileHandle)
        {
            const auto errnoCopy = errno;
            throw std::runtime_error(std::string("Failed to open outputFile ") + m_outputFile.string() + ", errno = " + std::to_string(errnoCopy));
        }
    }

    ~FileHash()
    {
        if (!m_success)
        {
            std::error_code ec;
            std::filesystem::remove(m_outputFile, ec); // ignore error
        }
    }

private:
    const std::filesystem::path m_outputFile;
    const size_t m_blockSize;

    FDHandle m_inputFileHandle;
    FDHandle m_outputFileHandle;

    size_t m_fileSize = 0;
    bool m_success = false;
};

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

        FileHash fileHash(inputFile, outputFile, blockSize);
    }
    catch (const std::exception& ex)
    {
        std::cout << "Error: " << ex.what();
        return -1;
    }

    return 0;
}
