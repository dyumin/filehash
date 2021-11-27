#include "fdhandle.h"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/crc.hpp>

#include <iostream>
#include <filesystem>
#include <thread>
#include <algorithm>

#include <fcntl.h>
#include <sys/mman.h>

using helpers::FDHandle;



class FileHash final
{
public:
    FileHash(const std::filesystem::path& inputFile, std::filesystem::path outputFile, const uintmax_t blockSize) : m_outputFile(std::move(outputFile)), m_blockSize(blockSize)
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

    void Run()
    {
        /* const */ auto hardwareThreadsCount = std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() : 1;

//        m_fileSize = 139;
//        m_blockSize = 2;
//        hardwareThreadsCount = 8;

        unsigned long threadsCount = hardwareThreadsCount;
        const auto chunks = m_fileSize / m_blockSize;

        // Since thread creation is kinda an expensive operation thread will be created only if file size exceeds this threshold
        // Threshold may be determined dynamically, e.g. it won't help to create a lot of threads on some old broken hdd either
        // A good starting point to define what a small file is may be the fact that mmap-ed memory does lazy loading with the size of page
        const auto threadDispatchThreshold = sysconf(_SC_PAGE_SIZE);
        const auto maxNumberOfThreadForFile = m_fileSize / threadDispatchThreshold;
        if (maxNumberOfThreadForFile == 0)
        {
            threadsCount = 1;
        }

        if (chunks == 0 || (chunks == 1 && (m_fileSize % m_blockSize) == 0) || threadsCount == 1)
        {
            // single thread
            std::cout << "single thread" << std::endl;
        }
        else
        {
            if (chunks < hardwareThreadsCount)
            {
                threadsCount = chunks;
            }

            threadsCount = std::min(threadsCount, maxNumberOfThreadForFile);

            const auto fullChunksPerThread = chunks / threadsCount;
            const uintmax_t threadViewSize = fullChunksPerThread * m_blockSize; // aligned by m_blockSize, except for tail

            // add tail processing thread if tail is at least the size of threadDispatchThreshold
            if (threadsCount < hardwareThreadsCount && ((m_fileSize % m_blockSize) > threadDispatchThreshold)) //TODO: check
            {
                threadsCount++;
            }

            // dispatch fully loaded threads
            uintmax_t offset = 0;
            for (int i = 0; i < threadsCount - 1; ++i)
            {
                std::cout << offset << " to " << offset + threadViewSize << std::endl;
                offset = threadViewSize * (i + 1);
            }

            // dispatch tail processing thread
            auto tail = m_fileSize - offset;
            std::cout << offset << " to " << offset + tail << std::endl;

            int i = 0;

//            for (; offset < m_fileSize - threadViewSize; offset += threadViewSize) // full threads
//            {
//                std::cout << offset << " to " << offset + threadViewSize << std::endl;
//            }
//
//            auto tail = m_fileSize - offset;
//            std::cout << offset << " to " << offset + tail << std::endl;
        }

        // MAP_POPULATE
//        auto* const dataRaw = mmap(nullptr, m_fileSize, PROT_READ, MAP_PRIVATE, m_inputFileHandle.Get(), 0);
//        const auto* const data = static_cast<const uint8_t*>(dataRaw);
//        const uint8_t* const dataEnd = data + m_fileSize;
//
//        // PAGE_SIZE
//
//        // MAP_POPULATE
//        auto* const dataRaw2 = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, m_inputFileHandle.Get(), 4096);
//        const auto* const data2 = static_cast<const uint8_t*>(dataRaw2);
//        const uint8_t* const dataEnd2 = data2 + 4096;

//        auto* const dataRaw = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, m_inputFileHandle.Get(), 4096);
//        auto* const dataRaw2 = mmap(nullptr, 8192, PROT_READ, MAP_PRIVATE, m_inputFileHandle.Get(), 0);
//         auto* const data = static_cast< uint8_t*>(dataRaw);
//         auto* const data2 = static_cast< uint8_t*>(dataRaw2);
//        auto distance = std::distance(data2, data);
//
//        data2[1] = '9';
//        auto resulttt = data2[4095];

//        auto butesToProcess = m_fileSize >
//        for (auto dataChunk = data; dataChunk != dataEnd; dataChunk+=m_blockSize)
//        {
//            boost::crc_32_type crc32;
//            crc32.process_bytes(dataChunk, m_blockSize);
//            auto result = crc32.checksum();
//            std::cout << result << std::endl;
//        }
//
//        for (auto dataChunk = data2; dataChunk != dataEnd2; dataChunk+=m_blockSize)
//        {
//            boost::crc_32_type crc32;
//            crc32.process_bytes(dataChunk, m_blockSize);
//            auto result = crc32.checksum();
//            std::cout << result << std::endl;
//        }


//        std::string lol = "111";
//        boost::crc_32_type crc32;
//        crc32.process_bytes(lol.data(), lol.size());
//        auto result = crc32.checksum();
//        std::cout << result << std::endl;

//        auto error = errno;
//        auto result = munmap(dataRaw, m_fileSize);
//        error = errno;
//        auto result2 = munmap(dataRaw2, 8192);
//        error = errno;
//        auto result3 = munmap(dataRaw2, m_fileSize);
//        error = errno;
//        auto result4 = munmap(dataRaw2, m_fileSize);
//        error = errno;

//        std::cout << 1 << std::endl;
    }

private:
    const std::filesystem::path m_outputFile;
    /* const */ uintmax_t m_blockSize;

    FDHandle m_inputFileHandle;
    FDHandle m_outputFileHandle;

    uintmax_t m_fileSize = 0;
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
        fileHash.Run();
    }
    catch (const std::exception& ex)
    {
        std::cout << "Error: " << ex.what();
        return -1;
    }

    return 0;
}
