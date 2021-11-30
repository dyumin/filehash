#include "mapped_chunk.h"
#include "fdhandle.h"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/crc.hpp>

#include <optional>
#include <chrono>
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

// Overall:
// Simple pread() or std::ifstream might have done the job, but I wanted to try mmap for a long time now, so here we are

// defines and global variables are bad, but let's make these since stream synchronisation is not the main purpose of this task
// std::osyncstream is available in std 20
// also this way of unique_lock management is absolutely cursed but valid
std::mutex LogLock;
#define log for(auto lock57567333 = std::unique_lock(LogLock); lock57567333.owns_lock(); std::unique_lock(std::move(lock57567333)) /*NOLINT(bugprone-use-after-move)*/) \
            std::cout

struct Task final
{
    std::optional<std::chrono::time_point<std::chrono::steady_clock>> hashStartTimepoint;
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

    friend class FileHash;

private:
    // precondition: on successive calls offset must be equal or greater than previous offset value, but not greater than oldMappingSize (of filesize)
    void InitializeMapping()
    {
        const auto& alignToNearestUpperValue = [&](const auto value)
        {
            const auto rem = value % pageSize;
            return rem == 0 ? value : (value - rem + pageSize);
        };

        constexpr auto UnalignedMappingSize = 1024 * 1024 * 10; // MiB, https://wiki.ubuntu.com/UnitsPolicy
        const size_t maxMMapSize = alignToNearestUpperValue(UnalignedMappingSize);

        const uintmax_t remainingFileSize = fileSize - startOffset;
        const uintmax_t alignedRemainingFileSize = alignToNearestUpperValue(remainingFileSize);

        const size_t mmapSize = alignedRemainingFileSize > maxMMapSize ? maxMMapSize : alignedRemainingFileSize;

        const uintmax_t initialMappingOffset = startOffset - (startOffset % pageSize);
        auto* const data = mmap64(nullptr, mmapSize, PROT_READ, MAP_PRIVATE, inputFileHandle->Get(), initialMappingOffset);
        if (data == MAP_FAILED)
        {
            const auto errnoCopy = errno;
            throw std::runtime_error("mmap64 failed; offset: " + std::to_string(currentMappingOffset) + "; len: " + std::to_string(mmapSize) + "; errno: " + std::to_string(errnoCopy));
        }
        madvise(data, mmapSize, MADV_SEQUENTIAL); // ignore error

        currentMapping = MappedChunk(data, mmapSize);
        currentMappingOffset = initialMappingOffset;
    }

    // precondition: on successive calls offset must be equal or greater than previous offset value, but not greater than oldMappingSize (of filesize)
    std::pair<void*, size_t> GetPointerToOffset(const uintmax_t offset)
    {
        auto mappingOffsetEnd = currentMappingOffset + currentMapping.Size();
        const auto& getPointerToMappedOffset = [&]()
        {
            const size_t pointerOffset = offset - currentMappingOffset;
            const size_t size = mappingOffsetEnd - (currentMappingOffset + pointerOffset);

            auto* pointer = static_cast<uint8_t*>(currentMapping.Data());
            pointer += pointerOffset;

            return std::make_pair(pointer, size);
        };

        if (offset < mappingOffsetEnd)
        {
            return getPointerToMappedOffset();
        }
        else // remap
        {
            const uintmax_t oldMappingSize = currentMapping.Size(); // aligned by page size except for the tail
            currentMapping.Reset();

            currentMappingOffset += oldMappingSize;

            const uintmax_t remainingFileSize = fileSize - currentMappingOffset;
            const size_t mappingSize = std::min(oldMappingSize, remainingFileSize);
            auto* const data = mmap64(nullptr, mappingSize, PROT_READ, MAP_PRIVATE, inputFileHandle->Get(), currentMappingOffset); // initial mapping
            if (data == MAP_FAILED)
            {
                const auto errnoCopy = errno;
                throw std::runtime_error("mmap64 failed; offset: " + std::to_string(currentMappingOffset) + "; len: " + std::to_string(mappingSize) + "; errno: " + std::to_string(errnoCopy));
            }
            madvise(data, mappingSize, MADV_SEQUENTIAL); // ignore error

            currentMapping = helpers::MappedChunk(data, mappingSize);

            mappingOffsetEnd = currentMappingOffset + currentMapping.Size();
            if (offset < mappingOffsetEnd)
            {
                return getPointerToMappedOffset();
            }
            else
            {
                throw std::runtime_error("offset " + std::to_string(offset) + " is greater than remapped mappingOffsetEnd " + std::to_string(mappingOffsetEnd));
            }
        }
    }
};

constexpr auto ElementSize = sizeof(decltype(static_cast<Task*>(nullptr)->blocksHashes)::value_type);

class FileHash final
{
public:
    FileHash(const std::filesystem::path& inputFile, const std::filesystem::path& outputFile, const uintmax_t blockSize) : m_outputFile(outputFile), m_blockSize(blockSize)
    {
        m_inputFileHandle = std::make_shared<FDHandle>(open64(inputFile.c_str(), O_RDONLY)); // TODO: O_LARGEFILE, open64?
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

        m_outputFileHandle = FDHandle(open64(m_outputFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)); // TODO: O_LARGEFILE, open64?
        if (!m_outputFileHandle)
        {
            const auto errnoCopy = errno;
            throw std::runtime_error(std::string("Failed to open outputFile ") + m_outputFile.string() + ", errno = " + std::to_string(errnoCopy));
        }
    }

    ~FileHash()
    {
        {
            std::unique_lock lock(m_workingQueuesLock);
            m_exit = true;
        }

        m_hashersCond.notify_all();
        m_writersCond.notify_all();

        for (auto& worker: m_workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }

        if (!m_success || m_errorDescription) // actually output file should be fine in case m_success is set even if m_errorDescription is also set, but let's remove it anyway
        {
            std::error_code ec;
            std::filesystem::remove(m_outputFile, ec); // ignore error
        }
        else
        {
            // duration includes time spend writing to output and all the shutdown sequence
            const auto duration = std::chrono::duration<double>(std::chrono::steady_clock::now() - m_hashStartTimepoint); // seconds with double rep
            log << "File processed in " << duration.count() << " seconds; "
                << (double) m_fileSize / 1024 / 1024 / duration.count() << " MiB/s" << std::endl; // zero div exception may fire, although very unlikely

            fdatasync(m_outputFileHandle.Get()); // ignore error
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
            // Todo: single thread should not wait for the writer thread
            m_tasksToProcess.emplace_back(new Task{
                .hashStartTimepoint = {},
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
                m_tasksToProcess.emplace_back(new Task{
                    .hashStartTimepoint = {},
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
            m_tasksToProcess.emplace_back(new Task{
                .hashStartTimepoint = {},
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
            return m_remainingTasks == 0 || m_errorDescription; // TODO: m_stop
        });

        if (m_errorDescription)
        {
            log << "Worker error: " << m_errorDescription.value();
            m_exit = true; // stop running threads // NOTE: workers might override initial error on exit, lets ignore that
        }
    }

    void WritingThreadBody()
    {
        try
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
                    if (task.currentOffset == task.stopOffset)
                    {
                        const auto duration = std::chrono::duration<double>(std::chrono::steady_clock::now() - task.hashStartTimepoint.value()); // seconds with double rep

                        // duration includes time spend writing to output
                        log << "Chunk from " << task.startOffset << " to " << task.stopOffset
                            << " took " << duration.count() << " seconds; "
                            << (double) (task.stopOffset - task.startOffset) / 1024 / 1024 / duration.count() << " MiB/s" << std::endl; // zero div exception may fire, although very unlikely
                    }
                    {
                        std::unique_lock lock(m_workingQueuesLock);
                        if (--m_remainingTasks == 0)
                        {
                            m_success = true;
                            m_controlThreadCond.notify_one();
                        }
                    }
                }

            }
        }
        catch (const std::bad_alloc&)
        {
            {
                std::unique_lock lock(m_workingQueuesLock);
                m_errorDescription = std::string("wr bad_alloc");  // std::string uses SSO for up to 15 (including) symbols
            }
            m_controlThreadCond.notify_one();
        }
        catch (const std::exception& ex)
        {
            {
                std::unique_lock lock(m_workingQueuesLock);
                m_errorDescription = ex.what();
            }
            m_controlThreadCond.notify_one();
        }
    }

    void HashThreadBody()
    {
        try
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

                if (!task.hashStartTimepoint)
                {
                    task.hashStartTimepoint = std::chrono::steady_clock::now();
                }

                // all arithmetic normalized to zero
                if (!task.currentMapping)
                {
                    task.InitializeMapping();
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
        catch (const std::bad_alloc&)
        {
            {
                std::unique_lock lock(m_workingQueuesLock);
                m_errorDescription = std::string("h bad_alloc");  // std::string uses SSO for up to 15 (including) symbols
            }
            m_controlThreadCond.notify_one();
        }
        catch (const std::exception& ex)
        {
            {
                std::unique_lock lock(m_workingQueuesLock);
                m_errorDescription = ex.what();
            }
            m_controlThreadCond.notify_one();
        }
    }

private:
    const std::chrono::time_point<std::chrono::steady_clock> m_hashStartTimepoint = std::chrono::steady_clock::now(); // default-initialized for simplicity
    const std::filesystem::path m_outputFile;
    const uintmax_t m_blockSize;

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
    std::optional<std::string> m_errorDescription;
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
