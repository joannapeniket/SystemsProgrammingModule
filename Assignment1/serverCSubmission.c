#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <ctype.h>

extern char *processRequest(char *request);

// Query struct records single IP + port pair 
typedef struct {
    uint32_t ip;  //uint32_t is the unsigned 32-bit integer type defined in <stdint.h>
    int port;
} Query;

// Rule struct stores valid IP and port ranges and fields for a dynamic array to track which connections have satisfied the rule
typedef struct {
    uint32_t ip_start, ip_end;
    int port_start, port_end;
    Query *queries;  //pointer to what will be the first dynamically allocated array of query structs 
    size_t query_count;  
    size_t query_cap;
    //size_t is the unsigned integer type defined in <stddef.h>: it is platform sized (e.g., 64-bit on 64-bit system)
} Rule;

static Rule *rules;  //pointer to the dynamic array of Rule structs
static size_t rule_count, rule_cap;  
static char **requests;  //pointer to a dynamically allocated array of char* pointers, each pointing to a request string
static size_t req_count, req_cap;
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER; //thread-safety mechanism

static int parse_ip(const char *s, uint32_t *out) {  //takes the input string to parse and a pointer to where the the result (a 32-bit integer) should be stored

    int a, b, c, d;
    int consumed = 0;  //tracks number of characters read by sscanf

    if (sscanf(s, "%d.%d.%d.%d%n", &a, &b, &c, &d, &consumed) != 4)  
        return 0;  //triggered if anything other than 4 matches are made

    if (s[consumed] != '\0')  //checks for junk (anything other than \0) at the end of s
            return 0;

    if (a < 0 || a > 255 || b < 0 || b > 255 ||
        c < 0 || c > 255 || d < 0 || d > 255)  //checks each part of ip address is within valid range 
        return 0;

    *out = ((uint32_t)a << 24 | (uint32_t)b << 16 |
            (uint32_t)c << 8 | (uint32_t)d);  //casts each section of the ip address to an unsigned integer and shifts chunk left to the correct position in the 32-bit integer
            //the 32-bit integer is written through the *out pointer into the caller's variable

    return 1;  //represents success
}

static int parse_port(const char *s, int *out) {
    if (!isdigit((unsigned char) s[0])) return 0;  //rejects inputs with leading signs of whitespace which sscanf with %d would accept

    int port;
    int consumed = 0;

    if (sscanf(s, "%d%n", &port, &consumed) != 1)
        return 0;  //triggered if anything other than 1 match is made


    if (s[consumed] != '\0')  //checks for junk (anything other than \0) at the end of s
        return 0;

    if (port < 0 || port > 65535)  //checks that port is within valid integer range 
        return 0;

    *out = port;  //port is written through the *out pointer into the caller's variable

    return 1;  //represents success
}

static int parse_rule(const char *s, Rule *out) {  //takes const char *s - the input string to parse and Rule *out 

    char ip_part[64], port_part[32];  //fixed size arrays to store the ip and port after split

    //searches for space that would split ip and port in a valid input 
    const char *sp = strchr(s, ' ');  //scans through string and returns pointer to first occurence of a ' ' or NULL if not found
    if (!sp) return 0;  
    if (sp != strrchr(s, ' ')) return 0;  //checks that pointer to first occurence of ' ' is the same as last occurence of ' ' (i.e., there is only one space in the input)
    if (strpbrk(s, "\t\r\n")) return 0;  //rejects any stings containing tabs, carriage returns or newlines

    if (sscanf(s, "%63s %31s", ip_part, port_part) != 2)
    //%63s reads up to 63 characters into ip_part, %31s reads up to 31 characters into port_part.
    //note that ip_part is the raw input string - it is packed into a 32-bit integer only when parse_ip is called on it  
        return 0;  //triggered if anything other than 2 matches are made (i.e., a valid ip address and a vallid port)

    //searches for '-' that would indicate a valid ip range rather than a single valid ip address
    char *ip_dash = strchr(ip_part, '-'); //scans through string and returns pointer to first occurence of a '-' or NULL if not found
    if (ip_dash) {
        *ip_dash = '\0';  //write '\0' in place of dash - separates range into two separate strings
        if (!parse_ip(ip_part, &out -> ip_start)) return 0;  //parse first ip address
        if (!parse_ip(ip_dash + 1, &out -> ip_end)) return 0;  //parse second ip address
        if (out -> ip_start >= out -> ip_end) return 0;  //checks that second address greater than the first - indicating valid range  
    } else {
        //handles single valid ip address rather than valid ip range 
        if (!parse_ip(ip_part, &out -> ip_start)) return 0;
        out -> ip_end = out -> ip_start; //sets ip_start and ip_end to the same value (rule allows single valid ip)
    }

    //searches for '-' that would indicate a valid port range rather than a single valid port number
    //note that this function follows the same logical flow as ip_dash
    char *port_dash = strchr(port_part, '-');
    if (port_dash) {
        *port_dash = '\0';
        if (!parse_port(port_part, &out -> port_start)) return 0;
        if (!parse_port(port_dash + 1, &out -> port_end)) return 0;
        if (out -> port_start >= out -> port_end) return 0;
    } else {
        if (!parse_port(port_part, &out -> port_start)) return 0;
        out -> port_end = out -> port_start;
    }

    return 1;  //represents success
}

static int ip_in_range(uint32_t ip, const Rule *r) {
    return ip >= r -> ip_start && ip <= r -> ip_end;  //returns 1 if ip falls within valid range
}

static int port_in_range(int port, const Rule *r) {
    return port >= r -> port_start && port <= r -> port_end;  //returns 1 if port falls within valid range 
}

static char *make_response(const char *s) {  //called inside handler functions whenever they have to return a response string 
    char *r = strdup(s);  //allocates enough heap memory to fit the input string, copies it in, and returns a pointer to it - that pointer gets stored in r and returned
    if (!r) { perror("strdup"); exit(1); }  //error handling for strdup - kills program immediately if strdup can't allocate memory for a response string 
    return r;
}

static void ip_to_str(uint32_t ip, char *buf) {
    sprintf(buf, "%u.%u.%u.%u", 
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8)  & 0xFF,
            ip         & 0xFF); //sprintf takes a pointer to where to write the output, the format string telling it how to write the output and 4 integers to write
            //shifting the 32-bit string then & 0xFF has the effect of isolating each 8 bit chunk
}

//keeps a record of every request that comes into the server in the order they arrived 
static void log_request(const char *request) {
    //if the capacity of the requests array is met, increase capacity 
    if (req_count == req_cap) {
        size_t new_cap;
        if(req_cap == 0) {
            new_cap = 8;
        } else {
            new_cap = req_cap * 2;
        }
        char **tmp = realloc (requests, new_cap * sizeof(char *));  //resize requests array to hold new_cap pointers, and store the result in tmp
        if (!tmp) { perror("realloc"); exit(1); }  //error handling for realloc - kills program immediately if tmp is NULL
        requests = tmp;  
        req_cap = new_cap;  //update capacity of requests array
    }
    requests[req_count] = strdup(request);  //allocates memory on the heap, stores a copy of the new request there and returns a pointer to that request which is stored in the next empty slot in the requests array
    if (!requests[req_count]) { perror("strdup"); exit(1); }  //error handling for strdup - kills program immediately if empty slot is NULL
    req_count++;
}

//concatenate every request thats ever been logged
static char *handle_R(void) {
    if (req_count == 0)
        return make_response("");

    size_t total = 0; //total created to store number of bytes required to store all request strings 
    for (size_t i = 0; i < req_count; i++)
        total += strlen(requests[i]) + 1;  //+1 to each string for '\n'

    char *response = malloc(total + 1); //allocated enough memory for total + 1 ('\0' at the end) and returns a pointer to it called response
    if (!response) { perror("malloc"); exit(1); }

    char *p = response;  //creates new pointer to same place in memory as response called p
    for (size_t i = 0; i < req_count; i++) {
        size_t len = strlen(requests[i]);
        memcpy(p, requests[i], len); //copies len bytes from requests[i] to p
        p += len; //moves p beyond newly written string
        *p++ = '\n';  //writes '\n' then moves past it to start writing the next string 
    }
       *p = '\0'; //properly ends the string of all requests with '\0'

    return response; //return string of all requests
}

//create rule
static char *handle_A(const char *request) {
    const char *rule_str = request + 2;  //rule_str is a pointer to the first element of the ip address part of the input string 

    Rule r = {0};  //creates new Rule struct and initializes all fields to 0 (or pointers to NULL)
    if (!parse_rule(rule_str, &r))  //calls parse rule on the rule_str string (starting at the element it points to - the start of the ip address)
        return make_response("Invalid rule");

    //allocate a new larger block of memory to hold more Rule structs, and store the result in tmp
    if (rule_count == rule_cap) {
        size_t new_cap;
        if(rule_cap == 0) {
            new_cap = 8;
        } else {
            new_cap = rule_cap * 2;
        }
        Rule *tmp = realloc(rules, new_cap * sizeof(Rule));  
        if (!tmp) { perror("realloc"); exit(1); }  //error handling for realloc - kills program immediately if tmp is NULL
        rules = tmp;  
        rule_cap = new_cap;
    }

    rules[rule_count++] = r;  //adds new Rule struct r to the first empty slot in the allocated memory 
    return make_response("Rule added");
}

//C is used to check whether an ip address/port pair are both valid/well formed AND allowed according to the rules
static char *handle_C(const char *request) {
    const char *rest = request + 2;

    if(strpbrk(rest, "\t\r\n")) //rejects input strings with tabs, carriage returns of new line characters
        return make_response("Illegal IP address or port specified");

    const char *sp = strchr(rest, ' ');  //sp is a pointer to the first blank space in the input string (in rest not request!)
    if(!sp || sp != strrchr(rest, ' '))  //rejects strings with anything but exactly one blank space
        return make_response("Illegal IP address or port specified");

    char ip_str[64], port_str[32];
    if(sscanf(rest, "%63s %31s", ip_str, port_str) != 2)  //same job as sscanf in parse_rule - splits the input string into ip_str (ip address part) and port_str (port part)
        return make_response("Illegal IP address or port specified");

    uint32_t ip;
    int port;
    if (!parse_ip(ip_str, &ip) || !parse_port(port_str, &port))
        return make_response("Illegal IP address or port specified");

    for (size_t i = 0; i < rule_count; i++) { //loop through Rule structs
        if (ip_in_range(ip, &rules[i]) && port_in_range(port, &rules[i])) { 
            Rule *r = &rules[i];
            //resize queries array to hold more Query structs, and store the result in tmp
            if (r -> query_count == r -> query_cap) {
                size_t new_cap;
                    if (r -> query_cap == 0) {
                        new_cap = 8;
                    } else {
                        new_cap = r -> query_cap * 2;
                    }
                Query *tmp = realloc(r -> queries, new_cap * sizeof(Query));  //resize requests array to hold new_cap pointers, and store the result in tmp
                if (!tmp) { perror("realloc"); exit(1); }  //error handling for realloc - kills program immediately if tmp is NULL
                r -> queries = tmp;  
                r -> query_cap = new_cap;  
            }
            //writes the new Query struct into the empty slot in the queries array
            r -> queries [r -> query_count].ip = ip;
            r -> queries [r -> query_count].port = port;
            r -> query_count++;

            return make_response("Connection accepted");
        }
    }

    return make_response("Connection rejected");
}

//frees all heap-allocated memory and resests the program back to a clean state
static char *handle_F(void) {
    for (size_t i = 0; i < rule_count; i++) //loop through Rule structs
        free(rules[i].queries); //free queries array inside each Rule struct

    free(rules); //free memory the rules pointer points to
    rules = NULL; //rules is now a dangling pointer - set to NULL
    rule_count = 0;
    rule_cap = 0;

    for (size_t i = 0; i < req_count; i++) //loop through all requests 
        free(requests[i]); //free each request string
    free(requests); //free memory the requests pointer points to 
    requests = NULL;  //requests is now a dangling pointer - set to NULL
    req_count = 0;
    req_cap = 0;

    return make_response("All rules deleted");
}

//delete rule
static char *handle_D(const char *request) {
    const char *rule_str = request + 2;

    Rule r = {0};  //creates a temporary Rule struct on the stack called r and initializes all fields to 0
    if (!parse_rule(rule_str, &r)) //parses rule_str and writes result at &r
        return make_response("Invalid rule");

    //searches through Rule structs for exact match with the temporary rule just created
    for (size_t i = 0; i < rule_count; i++) {
        if (rules[i].ip_start == r.ip_start &&
            rules[i].ip_end == r.ip_end &&
            rules[i].port_start == r.port_start &&
            rules[i].port_end == r.port_end) {

            //if found, frees that rule's queries
            free(rules[i].queries);

            //shifts remaining rules 
            memmove(&rules[i], &rules[i+1], (rule_count - i - 1) *sizeof(Rule));
            //memmove copies a block of memory from one location to another - It takes the destination, source and size (how many bytes to copy)
            rule_count--;

            return make_response("Rule deleted");
            }
    }  

    return make_response("Rule not found");
}  //temporary rule on stack deleted when the function returns

//builds and returns a string that stores every rule, and under each rule, every query that matched it 
static char *handle_L(void) {
    if (rule_count == 0)
        return make_response("");

    //first pass: calculates number of bytes required to store string
    size_t total = 0; //total tracks necessary number of bytes to store string
    for(size_t i = 0; i < rule_count; i++) {
        Rule *r = &rules[i];

        char ip1[16], ip2[16]; 
        ip_to_str(r -> ip_start, ip1); //converts 32-bit int for each rule to formatted ip string and writes to ip1 (ip_start is the first ip in allowed range)
        ip_to_str(r -> ip_end, ip2); //converts 32-bit int for each rule to formatted ip string and writes to ip2 (ip_end is the second ip in allowed range OR the same as ip_start if there is only one allowed ip in rule)

        if (r -> ip_start == r -> ip_end) //if the rule allows a single valid ip (ip_start and ip_end hold the same value)
            total += strlen("Rule: ") + strlen(ip1);
        else //if the rule allows a range of valid ips
            total += strlen("Rule: ") + strlen(ip1) + 1 + strlen(ip2);

        if (r -> port_start == r -> port_end) //if the rule allows a single valid port
            total += 1 + 5; //(space between ip and port + port)
        else //if the rule allows a range of valid ports
            total += 1 + 5 + 1 + 5; //(space between ip and port + port + '-' + port)

        total += 1; //total + '\n'

        for (size_t j = 0; j < r -> query_count; j++) {
            char qip[16]; //declares 16 byte buffer to store each query's formatted ip which has been accepted by each rule
            ip_to_str(r -> queries[j].ip, qip); //writes formatted ip for each query to qip
            total += strlen("Query: ") + strlen(qip) + 1 + 5 + 1; //calculates bytes needed to store each Query 
        }
    }

    char *response = malloc(total + 1); //allocates enough memory on the heap to store total + '\0' and returns pointer to it called response
    if (!response) { perror("malloc");  exit(1); }

    char *p = response; //creates pointer to the same location as response for the second pass
    //second pass: writes string 
    for (size_t i = 0; i < rule_count; i++) {
        Rule *r = &rules[i];

        char ip1[16], ip2[16];
        ip_to_str(r -> ip_start, ip1);
        ip_to_str(r -> ip_end, ip2);

        if (r -> ip_start == r -> ip_end)
            p += sprintf(p, "Rule: %s", ip1); //calls sprintf on parameters (returns length of output) and moves p pointer along by that number of characters to the next empty slot
        else
            p += sprintf(p, "Rule: %s-%s", ip1, ip2);

        if (r -> port_start == r -> port_end)
            p += sprintf(p, "%d\n", r -> port_start);
        else
            p += sprintf(p, "%d-%d\n", r -> port_start, r -> port_end);

        for (size_t j = 0; j < r -> query_count; j++) {
            char qip[16];
            ip_to_str(r -> queries[j].ip, qip);
            p += sprintf(p, "Query: %s %d\n", qip, r -> queries[j].port);
        }
    }
    *p = '\0';

    return response;
    }
    
    char *processRequest(char *request) { 

        //trim trailing whitespace characters
        size_t len = strlen(request);
        while(len < 0 && isspace((unsigned char)request[len - 1])) //while request is non-empty and last character is whitespace/trailing character - keep going
        //isspace returns true for any whitespace character: space ' ', tab '\t', newline '\n', carriage return '\r', vertical tab '\v', and form feed '\f'
            request[len--] = '\0'; //overwrite any whitespace characters at the end of request string with '\0'

        pthread_mutex_lock(&global_lock);  //ensures that if two threads call processRequest at the same time, only one can be inside the critical section at a time
        log_request(request);
            
        char *response;

        if (strcmp(request, "R" ) == 0)  //R takes no arguments - if statement returns 1/true if strings match (0 == 0)
            response = handle_R();
        else if (strncmp(request, "A ", 2) == 0) //if statement returns true if first 2 characters of strings match (0 == 0)
        /* strncmp(string1, string2, n): n = how many characters to check, starting from the beginning */
            response = handle_A(request);
        else if (strncmp(request, "C ", 2) == 0) //if statement returns true if first 2 characters of strings match (0 == 0)
            response = handle_C(request);
        else if (strcmp(request, "F" ) == 0)  //F takes no arguments  - if statement returns 1/true if strings match (0 == 0)
            response = handle_F();
        else if (strncmp(request, "D ", 2) == 0) //if statement returns true if first 2 characters of strings match (0 == 0)
            response = handle_D(request);
        else if (strcmp(request, "L" ) == 0)  //L takes no arguments  - if statement returns 1/true if strings match (0 == 0)
            response = handle_L();

        pthread_mutex_unlock(&global_lock);
        return response;
    }


        
    
    
        

    

