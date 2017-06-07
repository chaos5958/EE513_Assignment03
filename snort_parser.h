#include <iostream>
#include <string>
#include <regex>
#include <vector>
#include <map>

class snort_parser
{
    static const int headers_num = 7; 
    std::vector<std::string> headers;
    std::vector<std::string> options;
    std::map <std::string, std::string> options_map;

    public:
        void Parse(std::string);
        void clean();
        std::string getAction();
        std::string getHeaderRule();
        std::map<std::string, std::string> getOptionRule();
        bool isHttp();
};
