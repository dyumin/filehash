#ifndef FILEHASH_HELPERS_H
#define FILEHASH_HELPERS_H

#include <type_traits>

namespace helpers {

template<class LHS, class RHS>
constexpr auto min(const LHS& a, const RHS& b) -> typename std::common_type<LHS, RHS>::type
{
    return b < a ? b : a; // integral promotion should do the trick
}

}

#endif //FILEHASH_HELPERS_H
