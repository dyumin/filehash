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
#include <condition_variable>

#include <fcntl.h> // open
#include <sys/mman.h> // mmap
#include <unistd.h> // sysconf
#include <sys/types.h>

using helpers::FDHandle;
using helpers::MappedChunk;

// todo: mmap64

struct Task final
{
    std::shared_ptr<FDHandle> inputFileHandle;
    const uintmax_t fileSize;
    const uintmax_t blockSize;
    const long int pageSize;

    const uintmax_t startOffset; // from file start // aligned by blockSize
    const uintmax_t stopOffset; // from file start // aligned by blockSize except for the tail

    uintmax_t currentOffset; // from file start // aligned by blockSize except for the tail

    uintmax_t currentMappingOffset; // from file start // aligned by pageSize
    MappedChunk currentMapping;

    std::vector<boost::crc_32_type::value_type> blocksHashes;

    // precondition: offset may only be incremented for successive calls
    std::pair<void*, size_t> GetPointerToOffset(const uintmax_t offset)
    {
//        if () //TODO: throw maybe?
        const auto mappingOffsetEnd = currentMappingOffset + currentMapping.Size();
        if (offset < mappingOffsetEnd) // TODO: check boundaries
        {
            const size_t pointerOffset = offset - currentMappingOffset;
            const size_t size = mappingOffsetEnd - (currentMappingOffset + pointerOffset);

            auto* pointer = static_cast<uint8_t*>(currentMapping.Data());
            pointer += pointerOffset;

            return std::make_pair(pointer, size);
        }
        else // remap
        {
            const uintmax_t oldMappingSize = currentMapping.Size(); // will be multiple of page size except for the tail
            currentMapping.Reset();

            currentMappingOffset += oldMappingSize;

            const uintmax_t remainingFileSize = fileSize - currentMappingOffset; // TODO: if zero?
            size_t mappingSize = 0;
            if (oldMappingSize > remainingFileSize)
            {
                mappingSize = remainingFileSize;
            }
            else
            {
                mappingSize = oldMappingSize;
            }
//            const size_t mappingSize = std::min(oldMappingSize, remainingFileSize);
            auto* const data = mmap64(nullptr, mappingSize, PROT_READ, MAP_PRIVATE, inputFileHandle->Get(), currentMappingOffset); // initial mapping
            if (data == MAP_FAILED)
            {
                //TODO: handle errors
                throw std::runtime_error("mmap64 failed " + std::to_string(errno));
            }
            const auto adviseResult = madvise(data, mappingSize, MADV_SEQUENTIAL);
            if (adviseResult == -1)
            {
                // TODO: fail
                throw std::runtime_error("madvise failed " + std::to_string(errno));
            }

            currentMapping = helpers::MappedChunk(data, mappingSize);

            const auto mappingOffsetEnd = currentMappingOffset + currentMapping.Size();
            if (offset < mappingOffsetEnd) // TODO: check boundaries
            {
                const size_t pointerOffset = offset - currentMappingOffset;
                const size_t size = mappingOffsetEnd - (currentMappingOffset + pointerOffset);

                auto* pointer = static_cast<uint8_t*>(currentMapping.Data());
                pointer += pointerOffset;

                return std::make_pair(pointer, size);
            }
            else
            {
                // TODO: handle
                throw std::runtime_error("offset < mappingOffsetEnd");
            }
        }
    }
};

constexpr auto ElementSize = sizeof(decltype(static_cast<Task*>(nullptr)->blocksHashes)::value_type);

class FileHash final
{
public:
    FileHash(const std::filesystem::path& inputFile, std::filesystem::path outputFile, const uintmax_t blockSize) : m_outputFile(std::move(outputFile)), m_blockSize(blockSize)
    {
        m_inputFileHandle = std::make_shared<FDHandle>(open(inputFile.c_str(), O_RDONLY)); // TODO: O_LARGEFILE, open64?
        if (!m_inputFileHandle->operator bool())
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

        m_outputFileHandle = FDHandle(open(m_outputFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)); // TODO: O_LARGEFILE, open64?
        if (!m_outputFileHandle)
        {
            const auto errnoCopy = errno;
            throw std::runtime_error(std::string("Failed to open outputFile ") + m_outputFile.string() + ", errno = " + std::to_string(errnoCopy));
        }
    }

    ~FileHash()
    {
//        m_stop.store(true, std::memory_order_release);
        for (auto& worker: m_workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }

        if (!m_success)
        {
            std::error_code ec;
            std::filesystem::remove(m_outputFile, ec); // ignore error
        }
    }

    void Run()
    {
        const auto chunksNumber = (m_fileSize / m_blockSize) + !!(m_fileSize % m_blockSize);

        const auto fileSize = chunksNumber * ElementSize;

        const auto result = ftruncate64(m_outputFileHandle.Get(), fileSize);
        if (result == -1)
        {
            throw std::runtime_error("ftruncate64 failed " + std::to_string(errno));
        }

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

        // TODO: determine dynamically
        constexpr auto BytesToReserve = (size_t) 1024 * 1024 * 10; // MiB, https://wiki.ubuntu.com/UnitsPolicy
        if (chunks == 0 || (chunks == 1 && (m_fileSize % m_blockSize) == 0) || threadsCount == 1)
        {
            // single thread
            std::cout << "single thread" << std::endl;
            // Todo: single thread should not wait for the writer thread
            m_tasksToProcess.emplace_back(new Task{
                .inputFileHandle = m_inputFileHandle,
                .fileSize = m_fileSize,
                .blockSize = m_blockSize,
                .pageSize = threadDispatchThreshold,
                .startOffset = 0,
                .stopOffset = m_fileSize,
                .currentOffset = 0,
                .currentMappingOffset = 0});
            m_tasksToProcess.back()->blocksHashes.reserve(BytesToReserve / ElementSize);
        }
        else
        {
            if (chunks < hardwareThreadsCount)
            {
                threadsCount = chunks;
            }

            threadsCount = std::min(threadsCount, maxNumberOfThreadForFile);

            const auto fullChunksPerThread = chunks / threadsCount;
            const uintmax_t threadViewSize = fullChunksPerThread * m_blockSize; // aligned by m_blockSize, except for the tail

            // add tail processing thread if tail is at least the size of threadDispatchThreshold
            if (threadsCount < hardwareThreadsCount && ((m_fileSize % m_blockSize) > threadDispatchThreshold)) //TODO: check
            {
                threadsCount++;
            }

            // dispatch fully loaded threads
            uintmax_t offset = 0;
            for (int i = 1; i < threadsCount; ++i)
            {
                std::cout << offset << " to " << offset + threadViewSize << std::endl;
                m_tasksToProcess.emplace_back(new Task{
                    .inputFileHandle = m_inputFileHandle,
                    .fileSize = m_fileSize,
                    .blockSize = m_blockSize,
                    .pageSize = threadDispatchThreshold,
                    .startOffset = offset,
                    .stopOffset = offset + threadViewSize,
                    .currentOffset = offset,
                    .currentMappingOffset = 0});
                m_tasksToProcess.back()->blocksHashes.reserve(BytesToReserve / ElementSize);

                offset = threadViewSize * i;
            }

            // TODO: what if there will be dead tasks?
            // dispatch tail processing thread
            const auto tail = m_fileSize - offset;
            std::cout << offset << " to " << offset + tail << std::endl;
            m_tasksToProcess.emplace_back(new Task{
                .inputFileHandle = m_inputFileHandle,
                .fileSize = m_fileSize,
                .blockSize = m_blockSize,
                .pageSize = threadDispatchThreshold,
                .startOffset = offset,
                .stopOffset = offset + tail,
                .currentOffset = offset,
                .currentMappingOffset = 0});
            m_tasksToProcess.back()->blocksHashes.reserve(BytesToReserve / ElementSize);

        }

        std::unique_lock lock(m_workingQueuesLock);
        m_remainingTasks = m_tasksToProcess.size();

        m_workers.reserve(m_tasksToProcess.size());
        {
            for (auto i = 0; i < m_tasksToProcess.size(); i++)
            {
                m_workers.emplace_back(std::thread([&]()
                                                   {
                                                       HashThreadBody();
                                                   }));
            }

            const auto writersCount = m_workers.size() / 2 + !!(m_workers.size() % 2);
            for (auto i = 0; i < writersCount; i++)
            {
                m_workers.emplace_back(std::thread([&]()
                                                   {
                                                       WritingThreadBody();
                                                   }));
            }
        }

        m_hashersCond.notify_all();
        m_controlThreadCond.wait(lock, [&]()
        {
            return m_remainingTasks == 0; // TODO: m_stop
        });

        std::cout << "will exit" << std::endl;

        m_exit = true;
        m_workingQueuesLock.unlock();
        m_hashersCond.notify_all();
        m_writersCond.notify_all();

        for (auto& worker : m_workers) // TODO
        {
            worker.join();
        }
    }

    void WritingThreadBody()
    {
        std::unique_ptr<Task> readyTask;
        std::unique_ptr<Task> taskToHash;
        while (true)
        {
            {
                std::unique_lock lock(m_workingQueuesLock);
                if (taskToHash)
                {
                    m_tasksToProcess.emplace_back(std::move(taskToHash));
                    /**
                     * The notifying thread does not need to hold the lock on the same mutex as the one held by the waiting thread(s);
                     * in fact doing so is a pessimization, since the notified thread would immediately block again,
                     * waiting for the notifying thread to release the lock.
                     * However, some implementations (in particular many implementations of pthreads) recognize this situation
                     * and avoid this "hurry up and wait" scenario by transferring the waiting thread from the condition variable's queue
                     * directly to the queue of the mutex within the notify call, without waking it up.
                     */
                    m_hashersCond.notify_one();
                }
                if (m_exit)
                {
                    return;
                }
                if (m_readyTasks.empty())
                {
                    m_writersCond.wait(lock, [&]()
                    {
                        return m_exit || !m_readyTasks.empty();
                    });
                    if (m_exit)
                    {
                        return;
                    }
                }

                readyTask = std::move(m_readyTasks.back());
                m_readyTasks.pop_back();
            }

            auto& task = *readyTask;

            const auto nextHashIndex = task.currentOffset / task.blockSize + !!(task.currentOffset % task.blockSize);
            const auto hashFileOffset = (nextHashIndex - task.blocksHashes.size()) * ElementSize;
            const auto numWritten = pwrite64(m_outputFileHandle.Get(), task.blocksHashes.data(), task.blocksHashes.size() * ElementSize, hashFileOffset);

//            const auto syncResult = fdatasync(m_outputFileHandle.Get());
            if (numWritten == -1)
            {
                throw std::runtime_error("pwrite64 failed" + std::to_string(errno));
            }
            task.blocksHashes.clear();

            if (task.currentOffset != task.stopOffset)
            {
                taskToHash = std::move(readyTask);
            }
            else
            {
                {
                    std::unique_lock lock(m_workingQueuesLock);
                    if (--m_remainingTasks == 0)
                    {
                        m_success = true;
                        m_controlThreadCond.notify_one();
                    }
                }

                std::cout << "done " << task.startOffset << " to " << task.stopOffset << std::endl;
            }
        }
    }

    void HashThreadBody()
    {
        std::unique_ptr<Task> taskPtr;
        while (true)
        {
            {
                std::unique_lock lock(m_workingQueuesLock);
                if (m_exit)
                {
                    return;
                }
                if (m_tasksToProcess.empty())
                {
                    m_hashersCond.wait(lock, [&]()
                    {
                        return m_exit || !m_tasksToProcess.empty();
                    });
                    if (m_exit)
                    {
                        return;
                    }
                }

                taskPtr = std::move(m_tasksToProcess.back());
                m_tasksToProcess.pop_back();
            }

            auto& task = *taskPtr;

            // all arithmetic normalized to zero
            if (!task.currentMapping)
            {
                const auto MMapMaxSize = task.stopOffset + (task.stopOffset % task.pageSize); // TODO: find the right value
//                        const auto MMapMaxSize = 4096; // TODO: find the right value

                const auto initialMappingOffset = task.startOffset - (task.startOffset % task.pageSize);
                auto* const data = mmap64(nullptr, MMapMaxSize, PROT_READ, MAP_PRIVATE, task.inputFileHandle->Get(), initialMappingOffset); // initial mapping
                if (data == MAP_FAILED)
                {
                    // TODO: fail
                    throw std::runtime_error("mmap64 failed " + std::to_string(errno));
                }
                const auto adviseResult = madvise(data, MMapMaxSize, MADV_SEQUENTIAL);
                if (adviseResult == -1)
                {
                    // TODO: fail
                    throw std::runtime_error("madvise failed " + std::to_string(errno));
                }
                task.currentMapping = MappedChunk(data, MMapMaxSize);
                task.currentMappingOffset = initialMappingOffset;
            }

            for (; task.currentOffset < task.stopOffset;)
            {
//                if (m_stop.load(std::memory_order_acquire))
//                {
//                    // m_exit must be set prior to m_stop
//                    // todo: move to internal loop
//                    break;
//                }

                boost::crc_32_type crc32;

                const auto currentOffsetEnd = std::min(task.currentOffset + task.blockSize, task.fileSize);
                auto i = task.currentOffset;
                for (; i < currentOffsetEnd;)
                {
                    const auto[data, size] = task.GetPointerToOffset(i); // NOTE: this will be inefficient for small task.blockSize values
                    const auto bytesToProcess = std::min(currentOffsetEnd - i, size); // in case of very big task.blockSize, each step will process task.currentMapping.Size() bytes (which also may be big enough)
                    i += bytesToProcess;
                    task.currentOffset += bytesToProcess;
                    crc32.process_bytes(data, bytesToProcess);
                }

                task.blocksHashes.push_back(crc32.checksum());
                if (task.blocksHashes.size() == task.blocksHashes.capacity())
                {
                    break;
                }
            }

            {
                std::unique_lock lock(m_workingQueuesLock);
                m_readyTasks.emplace_back(std::move(taskPtr));
            }
            m_writersCond.notify_one();
        }
    }

private:
    const std::filesystem::path m_outputFile;
    /* const */ uintmax_t m_blockSize;

    std::shared_ptr<FDHandle> m_inputFileHandle;
    FDHandle m_outputFileHandle;

    uintmax_t m_fileSize = 0;

//    std::atomic<bool> m_stop = {false}; // TODO: later
    std::vector<std::thread> m_workers;

    std::condition_variable m_hashersCond;
    std::condition_variable m_writersCond;
    std::condition_variable m_controlThreadCond;
    std::mutex m_workingQueuesLock;
    bool m_exit = false;
    bool m_success = false;
    size_t m_remainingTasks = 0;
    std::vector<std::unique_ptr<Task>> m_tasksToProcess;
    std::vector<std::unique_ptr<Task>> m_readyTasks;
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
