#ifndef FILEHASH_FDHANDLE_H
#define FILEHASH_FDHANDLE_H

#include <boost/noncopyable.hpp>
#include <unistd.h>

namespace helpers {

class FDHandle final : boost::noncopyable
{
public:
    explicit FDHandle(const int fd = -1) noexcept: m_fd(fd)
    {
    }

    ~FDHandle() noexcept
    {
        Reset();
    }

    FDHandle& operator=(FDHandle&& other) noexcept
    {
        Reset(other.Release());
        return *this;
    }

    FDHandle(FDHandle&& other) noexcept
    {
        m_fd = other.Release();
    }

    [[nodiscard]] int Get() const noexcept
    {
        return m_fd;
    }

    explicit operator bool() const noexcept
    {
        return m_fd != -1;
    }

    void Reset(const int fd = -1) noexcept
    {
        if (m_fd != -1)
        {
            close(m_fd); // ignore error
        }
        m_fd = fd;
    }

    int Release() noexcept
    {
        const auto tmp = m_fd;
        m_fd = -1;
        return tmp;
    }

private:
    int m_fd;
};
}

#endif //FILEHASH_FDHANDLE_H
