// 32 bit Light weight vscode file
// struct is kinda like classes in OOP programming, or in normal words; a way to organize data

/* Stolen from _ip_types.h (WSA header file)
struct sockaddr {
	u_short	sa_family;
	char	sa_data[14];
};
*/

// I am reusing old code from other projects, so that is why it can get a little messy. But I will try my best to document it.
// I am gonna try to explain it as you have never coded in C++
// This took a long time to document, I have never writen that many comments irl. Sit back, grab some popcorn and relax.
// For ease of everything I added everything in a single file and called it a day (definitively not lazy)
// Fun fact, this code is unironically a billion times more readable than my previous yandere spaghetti code. That is why rewrites are good.

#include <iostream> // 4 debugging, winsock/ws2 = windows socket api or WSA
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream> // File stream, handles files
#include <sstream> // String stream, more flexible string
#include <algorithm> // Legacy code thing, I could make my own algorithm, but I guess I was lazy back then.
#include <vector>
#include <iomanip>
#include <gmp.h> // I stumbled upon a problem, that I am doing arithmetic operations on very big numbers. 
//Therefore I found this nice library that uses the system's memory instead of the registers in the CPU.
#include <gmpxx.h> // C++ wrapper for gmp.h, makes it C++ compatable
#include "json.hpp"

#include "PRIVATE_PEM.hpp" // Contains the private key, bytes are stored in a vector

// Global variables
SOCKET Accepted;
SOCKET Socket;
sockaddr_in Address;
int Size;

// Database file paths
std::string DATABASE = "./DB";
std::string POSTDATA = DATABASE + "/posts.json";

struct DER 
{
    std::vector<unsigned char> n;
    std::vector<unsigned char> e;
    std::vector<unsigned char> d;
    std::vector<unsigned char> p;
    std::vector<unsigned char> q;
};

DER theoneandsingularDER;

// c^d(mod n) = decryption formula! Very simple.
mpz_class modExp(const mpz_class &base, const mpz_class &exp, const mpz_class &mod) {
    mpz_class result = 1;
    mpz_class base_copy = base % mod;  // 

    mpz_class exponent = exp;

    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base_copy) % mod;
        }
        base_copy = (base_copy * base_copy) % mod;
        exponent = exponent / 2;
    }

    return result;
}

std::vector<unsigned char> base64_decode(const std::string &input) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> decoded_data;
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (base64_chars.find(c) == std::string::npos) break; // Skip non-Base64 characters
        val = (val << 6) + base64_chars.find(c);
        valb += 6;
        if (valb >= 0) {
            decoded_data.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return decoded_data;
}
std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    for (auto byte : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return oss.str();
}

// Function to parse the ASN.1 DER INTEGER, Abstract Syntax Notasion One which is a standard on how to store data including YYYY-MM-DD. I would rather eat vomit than ever have to see this section.
std::vector<unsigned char> parse_integer(const std::vector<unsigned char>& data, size_t& index) {
    ++index;  // move past the tag byte
    size_t len = data[index];  // get the length of the integer
    ++index;  // move past the length byte

    std::vector<unsigned char> value(data.begin() + index, data.begin() + index + len);
    index += len;  // Move past the value

    return value;
}
void parse_rsa_private_key(const std::vector<unsigned char>& data) {
    size_t index = 0;
    // the first byte tells what version of PEM you're using. We don't care, ours were 0x30 aka "0"

    ++index;  // Move past the version byte
    size_t sequence_len = data[index];  // second byte = the length of the sequence
    ++index;  // Move past the length byte

    // Parse the RSA private key thingies 5 of them in this specific order
    theoneandsingularDER.n = parse_integer(data, index);  // Modulus n
    theoneandsingularDER.e = parse_integer(data, index);  // Public exponent e
    theoneandsingularDER.d = parse_integer(data, index);  // Private exponent d
    theoneandsingularDER.p = parse_integer(data, index);  // Prime factor p
    theoneandsingularDER.q = parse_integer(data, index);  // Prime factor q

    // Output the parsed values (n, e, d, p, q)
    std::cout << "n (Modulus): " << bytes_to_hex(theoneandsingularDER.n) << std::endl;
    std::cout << "e (Public Exponent): " << bytes_to_hex(theoneandsingularDER.e) << std::endl;
    std::cout << "d (Private Exponent): " << bytes_to_hex(theoneandsingularDER.d) << std::endl;
    std::cout << "p (Prime): " << bytes_to_hex(theoneandsingularDER.p) << std::endl;
    std::cout << "q (Prime): " << bytes_to_hex(theoneandsingularDER.q) << std::endl;
}

int startserver()
{
    int returncode = 0; // having a return on every if statement looks ugly.

    // Initialization of the wsa // win sock api
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 0), &wsadata) != 0) { returncode = 1; } // Run WSA
    
    Socket = socket(AF_INET, SOCK_STREAM, 0); // Create socket
    if (Socket == INVALID_SOCKET) { WSACleanup(); returncode = 1; } // Check socket, no errors

    // Fill in the IP address and port for the socket to use
    Address.sin_family = AF_INET; // Either use TCP or UDP, chose TCP 4 obvious reasons (reliablity)
    Address.sin_port = htons(80); /* what port to use, 80 ofc (HTTP port) which is funny since this website is more secure than ol'
                                    reliable SSL (it makes HTTP go HTTPS) cause script kiddies don't know how to handle something unique like this ;) (they only know mitmproxy)*/
    Address.sin_addr.s_addr = INADDR_ANY; // Default IP address, which is the same as h80085.ddns.net since I own it.
    
    Size = sizeof(Address); // If you know C++; this just returns the data type, so int = 4 bytes, char 1 byte etc... (Very important)
    
    // This part binds and listens for incoming connection requests aka "SYN" (sync)
    // Check and bind socket w/ "converted aka" casted generic struct (see line 1, the struct)
    if (bind(Socket, reinterpret_cast<struct sockaddr*>(&Address), Size) == SOCKET_ERROR) { closesocket(Socket); WSACleanup(); returncode = 1; } 
    
    // Same thing, but it listens for incoming requests ( SYN, SYN ACK, ACK ) its too long to explain. (sync, sync-acknowledge, acknowledge)
    if (listen(Socket, 1) == SOCKET_ERROR) { closesocket(Socket); WSACleanup(); returncode = 1; }
    
    return returncode;
}

void readRecv(std::string &request) { // request gets filled in w/ data this "&" is a reference, basically "Use the same memory address!", difficult to explain
    char buffer[65535]; // Creates a 16 bit long character array
    int bytesReceived;
    while ((bytesReceived = recv(Accepted, buffer, sizeof(buffer), 0)) > 0) { // While loop, it reads each char aka byte od data
        request.append(buffer, bytesReceived); // Handy c++ funtion that appen
        if (request.find("\r\n\r\n") != std::string::npos) // Infamous CRLF (carriage return line feed), it marks the end of the http packet
            break; // If CRLF found, break the torturous cycle.
    }
}

// Extracts the HTTP method like GET POST etc... from the request.
std::string get_method(const char* request) {
    if (request == nullptr) return ""; // No request? then return nothing! (null pointers... They are cursed and I hate them and so does C++)
    std::istringstream iss(request); // Basically allows me to treat it as a stream whjich in turn I am able to extract specific values(C++ shenanigans)
    std::string method;
    iss >> method; // << As demonstrated here
    return method;
}

// Extracts the path from the HTTP request so for like GET /index.html or GET /cats.jpg
std::string get_path(const char* request) {
    if (request == nullptr) return "";
    std::istringstream iss(request); // same thing
    std::string method, path, version;
    iss >> method >> path >> version; // From the method, path get version from requets.
    return path; // return it
}

// the 

std::string extract_body(const std::string &request) {
    const std::string delimiter = "\r\n\r\n"; // What the hell is that for word? "delimiter", basically CRLF
    size_t pos = request.find(delimiter);
    if (pos != std::string::npos) {
        return request.substr(pos + delimiter.length());
    }
    return "";
}

// Returns the mime type based on the file extension. multipurpose internet mail extension "png becomes >> image/png"
std::string get_mime_type(const std::string &path) {
    size_t dot = path.find_last_of('.'); // As it says, finds the last presence of . so for example in as..das.rteds.png; dot would equal to the "." inbetween rteds >.< png
    if (dot == std::string::npos)
        return "application/octet-stream"; // I forgot what this line did. It looks scary, but I will keep it for legacy code (90% of my coding)
    
    // Steals the file extension
    std::string ext = path.substr(dot + 1); // what comes after the dot in woof.ogg? "O" ofcourse. ext = O
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower); /* what if the extension looked like oGg, will lower letter. It also sorts from first character to 
    the last character. This is why I love the std::string so much (they are dynamic aka the string size can change and works with almost anything), 
    but I hate converting them to C arrays and back, cause */

    // I could optimize or atleast prettify it, but who got time for that ¯\_(ツ)_/¯
    if (ext == "html" || ext == "htm") return "text/html";
    if (ext == "css")  return "text/css";
    if (ext == "js")   return "application/javascript";
    if (ext == "png")  return "image/png";
    if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
    if (ext == "gif")  return "image/gif";
    if (ext == "ico")  return "image/x-icon";
    return "application/octet-stream";
}

// HMM... I wonder what it does?
std::string read_file(const std::string &path) {
    std::string full_path = std::string("./root") + path; /* The root path of the web server. Its all for legacy code since I dont want to break this. 
    The reason why I do want to remove it is because I don't need to show you the http contents in this server. This just works as a database not HTML website*/
    std::ifstream file(full_path, std::ios::in | std::ios::binary); // Read it in raw binary and not ascii.
    if (!file.is_open()) { // File not open?, return nothing
        std::cerr << "Failed to open file: " << full_path << std::endl;
        return "";
    }
    std::stringstream buffer; // Store in buffer
    buffer << file.rdbuf();
    return buffer.str(); // Turn stream into string cause stream is flexible but not a string
}

// Who got time to build a http header? The only purpose of this function
std::string build_header(const std::string &status, const std::string &contentType, size_t contentLength) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << "\r\n"
        << "Content-Type: " << contentType << "\r\n"
        << "Content-Length: " << contentLength << "\r\n"
        << "Connection: close\r\n\r\n";
    return oss.str();
}

// Please understand this
void append_post_to_db(const std::string &postBody) {
    // Create a simple JSON object.
    std::string newPost = postBody;
    std::string jsonData;
    {
        std::ifstream inFile(POSTDATA); // POSTDATA is where the database is located at
        if (inFile.good()) {
            std::stringstream ss;
            ss << inFile.rdbuf();
            jsonData = ss.str();
        }
        inFile.close();
    }
    
    // If the file is empty or doesn't contain an array, start a new one.
    if (jsonData.empty()) {
        jsonData = "[]";
    }
    
    // remove whitespace
    jsonData.erase(jsonData.find_last_not_of(" \n\r\t") + 1);
    
    // json magic, encodes newPost in json
    if (jsonData == "[]") {
        jsonData = "[" + newPost + "]";
    } else {
        if (jsonData.back() == ']') {
            jsonData.pop_back();
            jsonData += "," + newPost + "]";
        } else {
            jsonData = "[" + newPost + "]";
        }
    }

    std::ofstream outFile(POSTDATA);
    if (outFile.good()) {
        outFile << jsonData;
    }
    outFile.close();
}
std::string vector_to_string(const std::vector<unsigned char>& vec) {
    return std::string(vec.begin(), vec.end());
}
// I was to lazy to change the name of the function to MethodIfStatements since C doesn't support character arrays to be used in switch case statements
void MethodSwitchStatements(const std::string &method, const std::string &path, const std::string &request, std::string &response)
{
    std::string body;

    if (method == "GET")
    {
        if (path == "/get-posts") // Just straight up copied from my other server. It appends the JSON file to its database
        {
            std::ifstream file(POSTDATA);
            if (!file.is_open()) {
                response = build_header("500 Internal Server Error", "text/plain", 0);
            } else {
                std::stringstream buffer;
                buffer << file.rdbuf();
                file.close();
                std::string postsJson = buffer.str();
                response = build_header("200 OK", "application/json", postsJson.size()) + postsJson;
            }
            return;
        }

        std::string actualPath = path.empty() || path == "/" ? "/index.html" : path; // So you don't need to write /index.html everytime you enter the website
        body = read_file(actualPath);

        if (body.empty())
        {
            // Fallback to index.html if file not found
            body = read_file("/index.html");
            if (body.empty())
            {
                response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            }
            else
            {
                std::string mime = get_mime_type("/index.html");
                response = build_header("200 OK", mime, body.size()) + body; // see build_header for more detail
            }
        }
        else
        {
            std::string mime = get_mime_type(actualPath);
            response = build_header("200 OK", mime, body.size()) + body;
        }
    }
    else if (method == "POST")
    {
        std::string postBody = extract_body(request);
        
        try {
            // Parse the JSON string into a JSON object
            nlohmann::json jsonObject = nlohmann::json::parse(postBody);

            // 
            std::vector<unsigned char> json_body = base64_decode(jsonObject["body"]);
            std::vector<unsigned char> json_iv = base64_decode(jsonObject["iv"]);
            std::vector<unsigned char> encryptedAESKey = base64_decode(jsonObject["encryptedAESKey"]);
            std::vector<unsigned char> json_tag = base64_decode(jsonObject["tag"]);

            // c^d(mod n)

            // modExp(json_body, theoneandsingularDER.d, theoneandsingularDER.n) Along the Line         //// TODO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

            std::cout << jsonObject["encryptedAESKey"];

        } catch (const nlohmann::json::exception& e) {
            // Handle error if JSON parsing fails
            std::cerr << "Error parsing JSON: " << e.what() << std::endl;
        }

        append_post_to_db(postBody);

        std::string responseBody = "<html><body><h1>POST Received</h1><p>Your post was saved.</p></body></html>";
        response = build_header("201 Created", "text/html", responseBody.size()) + responseBody;
    }
    else if (method == "PUT")
    {
        std::string putBody = extract_body(request);
        std::string responseBody = "<html><body><h1>PUT Received</h1><p>" + putBody + "</p></body></html>";
        response = build_header("200 OK", "text/html", responseBody.size()) + responseBody;
    }
    else if (method == "DELETE")
    {
        std::string responseBody = "<html><body><h1>DELETE Received</h1></body></html>";
        response = build_header("200 OK", "text/html", responseBody.size()) + responseBody;
    }
    else
    {
        std::string responseBody = "<html><body><h1>405 Method Not Allowed</h1></body></html>";
        response = build_header("405 Method Not Allowed", "text/html", responseBody.size()) + responseBody;
    }
}

// The main function, like keeping it clean.
int main()
{
    std::vector<unsigned char> data = base64_decode(PRIVATE_KEY); // Since PEM is encoded in base64, we have to decode it.
    parse_rsa_private_key(data); // Now we have to parse the RAW data and fill it in our DER struct for later use

    // Main loop, each nanosecond code executes for indefintily.
    int result = startserver();
    while (result == 0) // 0 = no fail;
    {
        Accepted = accept(Socket, reinterpret_cast<struct sockaddr*>(&Address), &Size); // Almost like listen but used for communication.

        std::string request; // A string with the life goal of holding future packet data
        readRecv(request); // Fills request with data

        // Determine the method and path.
        std::string method = get_method(request.c_str());
        std::string path = get_path(request.c_str());
        std::string response;
        std::string body;

        // I forgot the word for populate, thats why I wrote "filled in" for every single sentence. But this basically populates the response.
        MethodSwitchStatements(method, path, request, response);
        int bytesSent = send(Accepted, response.c_str(), static_cast<int>(response.size()), 0); // Send it to the client

        closesocket(Accepted);
    }
    // Clean up, don't want memory leaks, cause we're in C++ (C is even worse since it got no garbage collector, doesn t make it bad)
    closesocket(Socket);
    WSACleanup();

    return 0;
}

// please give me A Mr. McKenzie.
// If you don't understand something mail me.