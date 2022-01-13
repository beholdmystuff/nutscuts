#ifndef COMMON_H
#define COMMON_H

#include <string>

namespace Utils
{
	static uint32_t joaat(const std::string& str)
	{
		uint32_t hash = 0;
		for (const char c : str)
		{
			hash += c;
			hash += (hash << 10);
			hash ^= (hash >> 6);
		}
		hash += (hash << 3);
		hash ^= (hash >> 11);
		hash += (hash << 15);
		return hash;
	};
}

#endif //COMMON_H
