#include "explorer.h"
#include <bitset>
using namespace std;
constexpr std::size_t BITS_PER_BYTE = std::numeric_limits<byte>::digits;

std::string read_bits(const std::string& file_name)
{
    using bits = std::bitset<BITS_PER_BYTE>;

    if (std::ifstream file{ file_name, ios::in | std::ios::binary })
    {
        std::string result;

        file >> std::noskipws;

        byte b;
        while (file >> b) 
            result += bits(b).to_string(); 
        return result;
    }
    return {};
}

std::string is_packed(std::string file_name) {
	std::string UPX = "010101010101000001011000";
    std::string out = read_bits(file_name);

    size_t pos = out.find(UPX);
    if (pos != std::string::npos)
        return "Packed";
    else
        return "Unpacked";

    cout << out;
}