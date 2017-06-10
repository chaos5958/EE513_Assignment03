/* Parse snort rules
 *   'alert tcp 192.168.1.0/24 any -> 192.168.1.0/24 22 (content:"/bin/sh"; msg:"Remote shell execution message! ")'
 *   'alert tcp any any -> 143.248.5.153 80 (msg:"A packet destined to www.kaist.ac.kr")'
 *   'alert udp any any -> 192.168.1.0/24 1:1024 (msg:"udp traffic from any port and destination ports ranging   from  1 to 1024")'
 *   'alert http any any -> any 80 (http_request:"GET"; content:"naver"; msg:"NAVER detected!")'
 *           */

/* g++ version should be higher than 4.9 */

#include <iostream>
#include <string>
#include <regex>
#include <vector>
#include <map>
#include "snort_parser.h"

// trim from start
static inline std::string &ltrim(std::string &s); 

// trim from end
static inline std::string &rtrim(std::string &s); 

// trim from both ends
static inline std::string &trim(std::string &s); 

// alert http any any -> any 80 (http_request:"GET"; content:"naver"; msg:"NAVER detected!")
void snort_parser::Parse(std::string fname)
{
    //std::cout << "Parse start handle :" << fname << std::endl;

    // Extraction of several sub-matches
    //std::string fnames[] = {"alert http any any -> any 80 (http_request:\"GET\"; content:\"naver\"; msg:\"NAVER detected!\")"};
    //std::string fnames[] = {"alert tcp any any -> 143.248.5.153 80 (msg:\"A packet destined to www.kaist.ac.kr\")"};
    //std::string fnames[] = {"alert udp any any -> 192.168.1.0/24 1:1024 (msg:\"udp traffic from any port and destination ports ranging from 1 to 1024\")"};
    //std::string fnames[] = {"alert http any any -> any 80 (http_request:\"GET\"; content:\"naver\"; msg:\"NAVER detected!\")"};


    std::regex pieces_regex("^(.+)\\((.+)\\)$", std::regex_constants::extended);
    std::smatch pieces_match;
    std::string header;
    std::string option;

    if (std::regex_match(fname, pieces_match, pieces_regex)) {
        //std::cout << fname << '\n';

        header = pieces_match[1].str();
        option = pieces_match[2].str();

        header = ltrim(header);
        header = rtrim(header);
        option = ltrim(option);
        option = rtrim(option);

        //std::cout << "header: " << header << std::endl << "option: " << option << std::endl;


        //parse header
        size_t pos = 0;
        std::string delimiter = " ";
        while ((pos = header.find(delimiter)) != std::string::npos) {
            //std::cout << header.substr(0, pos) << std::endl;
            headers.push_back(header.substr(0, pos));
            header.erase(0, pos + delimiter.length());
        }
        //std::cout << header << std::endl;
        headers.push_back(header);

        //parse option
        delimiter = "; ";
        while ((pos = option.find(delimiter)) != std::string::npos) {
            //std::cout << option.substr(0, pos) << std::endl;
            options.push_back(option.substr(0, pos));
            option.erase(0, pos + delimiter.length());
        }
        //std::cout << option << std::endl;
        options.push_back(option);
    }   
    else
    {
        std::cerr << "wrong snort rule" << std::endl;
    }
    if(headers.size() != snort_parser::headers_num)
    {
        std::cerr << "Parse: invalid snort rule" << std::endl;
    }

    //std::cout << "Parse end" << std::endl;
}

std::string snort_parser::getAction()
{
    if(headers.size() != snort_parser::headers_num)
    {
        std::cerr << "getHeaderRule: no valie snort rule is saved" << std::endl;
        return std::string();
    }

    return headers.at(0);
}

bool snort_parser::isHttp()
{
    if(headers.size() != snort_parser::headers_num)
    {
        return false;
    }

    if(headers.at(1).compare("http") == 0)
    {
        return true;    
    }

    return false;
    
}

std::string snort_parser::getHeaderRule()
{
    if(headers.size() != snort_parser::headers_num)
    {
        std::cerr << "getHeaderRule: no valie snort rule is saved" << " length: " << headers.size() << std::endl;
        return std::string();
    }
    
    std::string headerRule;
    size_t pos = 0;

    //protocol 
    if(headers.at(1).compare("http") == 0)
    {
        headerRule += "tcp";    
    }
    else
        headerRule += headers.at(1);
    //parse ip
    std::string ipdelimiter = "/";
    std::string src_ip = headers.at(2);
    std::string dst_ip = headers.at(5);
    if(src_ip.compare("any") != 0)
    {
        if((pos = src_ip.find(ipdelimiter)) != std::string::npos) {
            //std::cout << src_ip.substr(0, pos) << std::endl;
            headerRule  += " and src net " + src_ip.substr(0, pos);
            src_ip.erase(0, pos + ipdelimiter.length());
            //std::cout << src_ip << std::endl;
            headerRule += "/" + src_ip; 
        }
        else
            headerRule += " and src host " + src_ip;
    }

    if(dst_ip.compare("any") != 0)
    {
        if((pos = dst_ip.find(ipdelimiter)) != std::string::npos) {
            //std::cout << dst_ip.substr(0, pos) << std::endl;
            headerRule  += " and dst net " + dst_ip.substr(0, pos);
            dst_ip.erase(0, pos + ipdelimiter.length());
            //std::cout << dst_ip << std::endl;
            headerRule += "/" + dst_ip; 
        }
        else
            headerRule += " and dst host " + dst_ip;
    }

    //parse port 
    std::string portdelimiter_range = ":";
    std::string portdelimiter_or = ",";
    std::string src_port = headers.at(3);
    std::string dst_port = headers.at(6);
    if(src_port.compare("any") != 0)
    {
        if((pos = src_port.find(portdelimiter_range)) != std::string::npos) {
            //std::cout << src_port.substr(0, pos) << std::endl;
            if(src_port.substr(0, pos).empty())
                headerRule += " and portrange 1";
            else
                headerRule  += " and portrange " + src_port.substr(0, pos);
            src_port.erase(0, pos + portdelimiter_range.length());
            //std::cout << src_port << std::endl;
            
            if(src_port.empty())
            {
                headerRule += "-";
                headerRule += "65535";
            }
            else
                headerRule += "-" + src_port; 
        }
        else if((pos = src_port.find(portdelimiter_or)) != std::string::npos)
        {
            headerRule += std::string(" and (");
            bool isFirst = true;
            while ((pos = src_port.find(portdelimiter_or)) != std::string::npos) {
                //std::cout << src_port.substr(0, pos) << std::endl;
                if(isFirst)
                {
                    headerRule += " src port " + src_port.substr(0, pos);
                    isFirst = false;
                }
                else
                    headerRule += " or src port " + src_port.substr(0, pos);

                src_port.erase(0, pos + portdelimiter_or.length());
            }
            headerRule += " or src port " + src_port; 
            headerRule += std::string(" )");
            std::cout << "parse result " << headerRule << std::endl;
        }
        else
            headerRule += " and src port " + src_port;
    }

    if(dst_port.compare("any") != 0)
    {
        if((pos = dst_port.find(portdelimiter_range)) != std::string::npos) {
            //std::cout << dst_port.substr(0, pos) << std::endl;
            if(dst_port.substr(0, pos).empty())
                headerRule += " and portrange 1";
            else
                headerRule  += " and portrange " + dst_port.substr(0, pos);
            dst_port.erase(0, pos + portdelimiter_range.length());
            //std::cout << dst_port << std::endl;

            if(dst_port.empty())
            {
                headerRule += "-";
                headerRule += "65535";
            }
            else
                headerRule += "-" + dst_port; 
        }
        else if((pos = dst_port.find(portdelimiter_or)) != std::string::npos)
        {
            headerRule += std::string(" and (");
            bool isFirst = true;
            while ((pos = dst_port.find(portdelimiter_or)) != std::string::npos) {
                //std::cout << dst_port.substr(0, pos) << std::endl;
                //
                if(isFirst)
                {
                    headerRule += " dst port " + dst_port.substr(0, pos);
                    isFirst = false;
                }
                else
                    headerRule += " or dst port " + dst_port.substr(0, pos);

                dst_port.erase(0, pos + portdelimiter_or.length());
            }
            headerRule += " or dst port " + dst_port; 
            headerRule += std::string(" )");
            std::cout << "parse result " << headerRule << std::endl;
        }
        else
            headerRule += " and dst port " + dst_port;
    }

    //std::cout << "final rule: " << headerRule << std::endl;
    return headerRule;
}

std::map<std::string, std::string> snort_parser::getOptionRule()
{
    std::regex option_regex("^(.+):(.+)$", std::regex_constants::extended);
    std::regex msg_regex("^\"(.+)\"$", std::regex_constants::extended);
    std::smatch pieces_match;
    std::string key, value;

    for(std::vector<std::string>::iterator iter = options.begin() ; iter != options.end(); ++iter)
    {
        if (std::regex_match(*iter, pieces_match, option_regex)) {
            key = pieces_match[1].str();
            value = pieces_match[2].str();

            key = ltrim(key);
            key = rtrim(key);
            value = ltrim(value);
            value = rtrim(value);

            if (std::regex_match(value, pieces_match, msg_regex)) 
                value = pieces_match[1].str();

            //std::cout << "key: " << key << std::endl << "value: " << value << std::endl;

            options_map.insert(std::map<std::string, std::string>::value_type(key, value));
        }
        else
        {
            std::cerr << "getOptionRule: invalid option " << *iter << std::endl;
        }
    }    

    return options_map;
}

void snort_parser::clean()
{
    headers.clear();
    options.clear();
    options_map.clear();
}


/*
int main()
{
    snort_parser a = snort_parser();
    a.Parse();
    a.getHeaderRule();
    a.getOptionRule();

    return 0;
}
*/

// trim from start
static inline std::string &ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// trim from end
static inline std::string &rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
                std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

// trim from both ends
static inline std::string &trim(std::string &s) {
    return ltrim(rtrim(s));
}
