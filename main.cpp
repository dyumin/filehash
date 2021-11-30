#include "mapped_chunk.h"
#include "fdhandle.h"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/crc.hpp>

#include <utility>
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

using helpers::FDHandle;
using helpers::MappedChunk;

template<class LHS, class RHS>
constexpr auto min(const LHS& a, const RHS& b) -> typename std::common_type<LHS, RHS>::type
{
    return b < a ? b : a;
}

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
    const size_t pageSize;

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

        constexpr size_t UnalignedMappingSize = {1024 * 1024 * 10}; // MiB, https://wiki.ubuntu.com/UnitsPolicy
        const size_t maxMMapSize = alignToNearestUpperValue(UnalignedMappingSize);

        const uintmax_t remainingFileSize = fileSize - startOffset;
        const uintmax_t alignedRemainingFileSize = alignToNearestUpperValue(remainingFileSize);

        const auto mmapSize = static_cast<size_t>(min(maxMMapSize, alignedRemainingFileSize));

        const uintmax_t initialMappingOffset = startOffset - (startOffset % pageSize);
        auto* const data = mmap64(nullptr, mmapSize, PROT_READ, MAP_PRIVATE, inputFileHandle->Get(), static_cast<off64_t>(initialMappingOffset));
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
            const auto pointerOffset = static_cast<size_t>(offset - currentMappingOffset);
            const auto size = static_cast<size_t>(mappingOffsetEnd - (currentMappingOffset + pointerOffset));

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
            const auto mappingSize = static_cast<size_t>(std::min(oldMappingSize, remainingFileSize));
            auto* const data = mmap64(nullptr, mappingSize, PROT_READ, MAP_PRIVATE, inputFileHandle->Get(), static_cast<off64_t>(currentMappingOffset)); // initial mapping
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

constexpr auto HashSize = sizeof(decltype(static_cast<Task*>(nullptr)->blocksHashes)::value_type);

class FileHash final
{
public:
    FileHash(const std::filesystem::path& inputFile, std::filesystem::path outputFile, const uintmax_t blockSize) : m_outputFile(std::move(outputFile))
    {
        m_inputFileHandle = std::make_shared<FDHandle>(open64(inputFile.c_str(), O_RDONLY));
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
        m_blockSize = blockSize == 0 ? m_fileSize : blockSize;

        m_outputFileHandle = FDHandle(open64(m_outputFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH));
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
            std::cout << "File processed in " << duration.count() << " seconds; "
                      << (double) m_fileSize / 1024 / 1024 / duration.count() << " MiB/s" << std::endl; // zero div exception may fire, although very unlikely

            fdatasync(m_outputFileHandle.Get()); // ignore error
        }
    }

    void Run()
    {
        const auto chunksCount = (m_fileSize / m_blockSize) + !!(m_fileSize % m_blockSize);
        const auto outputFileSizeBytes = chunksCount * HashSize;

        const auto result = ftruncate64(m_outputFileHandle.Get(), static_cast<off64_t>(outputFileSizeBytes));
        if (result == -1)
        {
            const auto errnoCopy = errno;
            throw std::runtime_error("ftruncate64 failed, errno = " + std::to_string(errnoCopy));
        }

        const auto hardwareThreadsCount = std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() : 1;

        // Since thread creation is kinda an expensive operation thread will be created only if file size exceeds page size
        // Threshold may be determined dynamically, e.g. it won't help to create a lot of threads on some old broken hdd either
        constexpr auto ThreadCreationThreshold = (uintmax_t) 1024 * 1024; // 1 MiB
        const uintmax_t maxNumberOfThreadsForFile = m_fileSize / ThreadCreationThreshold + !!(m_fileSize % ThreadCreationThreshold);

        auto threadsCount = min(hardwareThreadsCount, maxNumberOfThreadsForFile);

        const auto pageSize = static_cast<size_t>(sysconf(_SC_PAGE_SIZE));
        constexpr size_t HashBufferSizeBytes = {1024 * 1024 * 10}; // 10 MiB
        if ((chunksCount == 1 && (m_fileSize % m_blockSize) == 0) || threadsCount == 1)
        {
            // Todo: single thread should not wait for the writer thread if chunksCount >> 1
            m_tasksToProcess.emplace_back(new Task{
                .hashStartTimepoint = {},
                .inputFileHandle = m_inputFileHandle,
                .fileSize = m_fileSize,
                .blockSize = m_blockSize,
                .pageSize = pageSize,
                .startOffset = 0,
                .stopOffset = m_fileSize,
                .currentOffset = 0,
                .currentMappingOffset = 0});
            m_tasksToProcess.back()->blocksHashes.reserve(HashBufferSizeBytes / HashSize);
        }
        else
        {
            threadsCount = std::min(chunksCount, threadsCount);

            const auto fullChunksPerThread = chunksCount / threadsCount; // at least one
            const uintmax_t threadViewSize = fullChunksPerThread * m_blockSize; // aligned by m_blockSize, except for the tail

            for (uintmax_t offset = 0; offset < m_fileSize; offset += threadViewSize)
            {
                m_tasksToProcess.emplace_back(new Task{
                    .hashStartTimepoint = {},
                    .inputFileHandle = m_inputFileHandle,
                    .fileSize = m_fileSize,
                    .blockSize = m_blockSize,
                    .pageSize = pageSize,
                    .startOffset = offset,
                    .stopOffset = std::min(offset + threadViewSize, m_fileSize),
                    .currentOffset = offset,
                    .currentMappingOffset = 0});
                m_tasksToProcess.back()->blocksHashes.reserve(HashBufferSizeBytes / HashSize);
            }
        }

        std::unique_lock lock(m_workingQueuesLock);
        m_remainingTasks = m_tasksToProcess.size();

        m_workers.reserve(m_tasksToProcess.size());
        for (size_t i = 0; i < m_tasksToProcess.size(); i++) // Note m_tasksToProcess.size() may be greater than threadsCount by one
        {
            m_workers.emplace_back(std::thread([&]()
                                               {
                                                   HashThreadBody();
                                               }));
        }

        const auto writersCount = m_workers.size() / 2 + !!(m_workers.size() % 2);
        for (size_t i = 0; i < writersCount; i++)
        {
            m_workers.emplace_back(std::thread([&]()
                                               {
                                                   WritingThreadBody();
                                               }));
        }

        m_hashersCond.notify_all();
        m_controlThreadCond.wait(lock, [&]()
        {
            return m_remainingTasks == 0 || m_errorDescription;
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
                const auto hashFileOffset = (nextHashIndex - task.blocksHashes.size()) * HashSize;
                const auto numWritten = pwrite64(m_outputFileHandle.Get(), task.blocksHashes.data(), task.blocksHashes.size() * HashSize, static_cast<off64_t>(hashFileOffset));

                if (numWritten == -1)
                {
                    const auto errnoCopy = errno;
                    throw std::runtime_error("pwrite64 failed, errno = " + std::to_string(errnoCopy));
                }
                task.blocksHashes.clear();

                if (task.currentOffset != task.stopOffset)
                {
                    taskToHash = std::move(readyTask);
                }
                else
                {
                    const auto duration = std::chrono::duration<double>(std::chrono::steady_clock::now() - task.hashStartTimepoint.value()); // seconds with double rep

                    // duration includes time spend writing to output
                    log << "Chunk from " << task.startOffset << " to " << task.stopOffset
                        << " took " << duration.count() << " seconds; "
                        << (double) (task.stopOffset - task.startOffset) / 1024 / 1024 / duration.count() << " MiB/s" << std::endl; // zero div exception may fire, although very unlikely

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

                if (!task.currentMapping)
                {
                    task.InitializeMapping();
                }

                for (; task.currentOffset < task.stopOffset;)
                {
                    boost::crc_32_type crc32;
                    const auto currentOffsetEnd = std::min(task.currentOffset + task.blockSize, task.stopOffset);
                    for (; task.currentOffset < currentOffsetEnd;)
                    {
                        const auto[data, size] = task.GetPointerToOffset(task.currentOffset); // NOTE: this will be inefficient for small task.blockSize values
                        const size_t bytesToProcess = static_cast<size_t>(min(currentOffsetEnd - task.currentOffset, size)); // in case of very big task.blockSize, each step will process task.currentMapping.Size() bytes (which also may be big enough)
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
    uintmax_t m_blockSize;

    std::shared_ptr<FDHandle> m_inputFileHandle;
    FDHandle m_outputFileHandle;

    uintmax_t m_fileSize = 0;

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
            ("block-size", boost::program_options::value(&blockSize), "Block size to hash, bytes. Pass 0 to hash file in one block");

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
