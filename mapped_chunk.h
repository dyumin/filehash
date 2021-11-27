#ifndef FILEHASH_MAPPED_CHUNK_H
#define FILEHASH_MAPPED_CHUNK_H

#include <boost/noncopyable.hpp>
#include <sys/mman.h>
#include <tuple>

namespace helpers {
class MappedChunk final : boost::noncopyable
{
public:
    MappedChunk(void* const data, const size_t size) noexcept: m_data(data), m_size(size)
    {}

    ~MappedChunk() noexcept
    {
        Reset();
    }

    MappedChunk& operator=(MappedChunk&& other) noexcept
    {
        auto[data, size] = other.Release();
        Reset(data, size);
        return *this;
    }

    MappedChunk(MappedChunk&& other) noexcept
    {
        std::tie(m_data, m_size) = other.Release();
    }

    void Reset(void* const data = nullptr, const size_t size = 0) noexcept
    {
        if (m_data && m_size) // todo: zero size?
        {
            munmap(m_data, m_size); // ignore error
        }

        m_data = data;
        m_size = size;
    }

    std::pair<void*, size_t> Release() noexcept
    {
        auto tmp = std::make_pair(m_data, m_size);
        m_data = nullptr;
        m_size = 0;
        return tmp;
    }

    explicit operator bool() const noexcept
    {
        return m_data && m_size;
    }

    [[nodiscard]] void* Data() const noexcept
    {
        return m_data;
    }

    [[nodiscard]] size_t Size() const noexcept
    {
        return m_size;
    }

private:
    void* m_data;
    size_t m_size;
};
}

#endif //FILEHASH_MAPPED_CHUNK_H
