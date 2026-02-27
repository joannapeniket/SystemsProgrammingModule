#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <ctype.h>

/* A client says "I want to connect from IP 147.188.192.43 on port 22" — the firewall checks its list of rules, and either waves it through or blocks it. 
This program is the firewall rule engine. It's a software simulation of firewall rule management — it stores rules and evaluates connections against them, but it doesn't actually block any network traffic. It's essentially the logic layer that a real firewall would use. */


/* Query Struct */
//important - queries is an array of these. queries is an array of Query structs which are just ip 32-bit integer and port integer pairs
typedef struct {  // without typedef you would always have to write struct Query rather than just Query
    uint32_t ip;  //data chunk 1: uint32_t is a type built in to <stdint.h> - it is specifically a fixed-size unsigned integer type that is exactly 32 bits wide. (Other similar types in <stdint.h> include int8_t (8-bit signed) and int32_t(32-bit signed))
    int port;  //data chunk 2
} Query;  // Query is the name of the struct

/* This is the simplest thing in the whole file. It just records *one* IP+port pair that was checked and accepted. Think of it as a log entry: "someone from 147.188.192.43 on port 22 connected." 

The struct syntax follows standard C struct definition pattern 
typedef struct {
    // fields
} Name;

The new type name here is Query, and the type is struct { uint32_t ip; int port; } — an anonymous struct containing those two fields.
In C, struct is a composite type — it's a type that groups other types together. Just like int or char are types, struct { ... } is a type too.
A struct allows us to treat related data as one unit and mix types */

typedef struct {
    uint32_t ip_start, ip_end;  //declares 2 variables with type uint32_t (unsigned 32-bit integer)
    int port_start, port_end;  //declares 2 int variables
    Query  *queries;  //pointer to a query struct
    size_t  query_count;  //size_t is an unsigned integer type for representing sizes and counts — defined in <stddef.h>
    // size_t is an unsigned integer, so no negatives. The difference is it's platform-sized (64-bit on a 64-bit system), whereas int is typically fixed at 32-bit regardless of platform.
    size_t  query_cap;
} Rule;  //Rule is the name of the struct

/* 
A Rule represents one firewall allow-rule. It includes:

ip_start, ip_end — the IP range that's allowed (single IP = both are equal)
port_start, port_end — the port range that's allowed (single port = both are equal)
queries, query_count, query_cap: will be a dynamic array tracking which connections have actually matched this rule - Note that at this point (declaration) it's just three fields — no memory has been allocated yet. The actual array comes into existence later when realloc/malloc is called.

Rule contains a pointer to the first element of a dynamically allocated array of Query structs because each rule must remember which connections matched it (according to the spec). When you run the L command, it needs to print not just the rule but every IP+port that was accepted by that rule. So the rule has to carry that history with it.
A pointer to a dynamic array is the right choice because you don't know in advance how many connections will match — it could be 0 or thousands.

Both ip and port ranges will have to be simultaneously met for the rule satisfied and the pair to be approved
*/

/* Static declarations: These are the program's global state — everything the server needs to remember across multiple calls to processRequest: */
static Rule   *rules;  //rules is a pointer to the dynamic array of Rule structs
static size_t  rule_count, rule_cap;  //unsigned integer types to track capacity for the dynamic array of Rule structs:count = current size, cap = allocated capacity — doubling when full
static char  **requests;  //pointer to a dynamic array of strings: requests points to an array of char * pointers, each of which points to an individual request string.
static size_t  req_count, req_cap;  //unsigned integer types to track capacity for the dynamic array of request strings: count = current size, cap = allocated capacity — doubling when full
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;  //This is the thread-safety mechanism. Because the assignment requires the server to be thread-safe, any code that reads or writes the shared global state (rules, requests) must lock this mutex first and unlock after. You'll see pthread_mutex_lock / pthread_mutex_unlock wrapping the logic in processRequest

/* Note that a 'request' in this program is any string passed to processRequest — so things like "A 147.188.192.43 22", "C 147.188.192.43 22", "F", etc. Every command received gets logged into the requests array, which is what the R command prints back out. */

/* Note that ** means a pointer to a pointer so:
char * = pointer to a string
char ** = pointer to an array of strings */

static int parse_ip(const char *s, uint32_t *out) {
    //takes const char *s - the input string to parse and uint32_t *out - the pointer to where the result (32-bit integer) should be stored. Instead of returning the IP value directly, the function returns an int success/failure code (1 or 0), so the actual result needs to come back via a pointer parameter.
    //returns int (1=success, 0 = failure)

    int a, b, c, d; //initialises variables a-d each to store store an octet (8 bits)
    int consumed = 0;  //consumed will track how many characters sscanf read

    if (sscanf(s, "%d.%d.%d.%d%n", &a, &b, &c, &d, &consumed) != 4)
    //sscanf is from the C standard library, included via <stdio.h>. It works like scanf (which reads from keyboard input), but instead of reading from stdin (standard input) it reads from a string. You give it a string and a format, and it tries to parse values out of it.
    //s is the string you parse - the first parameter of parse_ip. s is just the name we give the parameter here - it could be anything - only the position and type matter.
    //sscanf takes the string to read from, the format, and pointers to variables where it will write each matched value. Each value read from these %d.%d.%d.%d%n, is written into one of these &a, &b, &c, &d, &consumed
    //%n is a special built-in specifier — it doesn't consume any input and doesn't need a corresponding value to match. Instead it just writes the count of characters consumed so far into the pointer you give it (&consumed). That's why sscanf returns 4 not 5 — %n doesn't count as a matched item.
    //The format string works like a template — literal characters (like the .) must match exactly, and %d means "read an integer here". It returns how many items were successfully matched, which is why the code checks != 4.
        return 0; //If fewer than 4 %d matches are made, sscanf returns that smaller number, the != 4 condition is true, and the function returns 0 (failure).

    if (s[consumed] != '\0')
    //in C, strings are arrays, so s[consumed] is the last position in the string s
    //this checks for any junk at the end of the ip address and returns 0 if anything other than \0 is found
        return 0;

    if (a < 0 || a > 255 || b < 0 || b > 255 ||
        c < 0 || c > 255 || d < 0 || d > 255)
        //checks valid range of each part of the ip address
        return 0;

    *out = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
           ((uint32_t)c << 8)  |  (uint32_t)d;
           // (uint32_t)a is a cast — it tells the compiler "treat a as a uint32_t instead of an int"
           //<< 24 shifts each 8 bit chunk left to its correct position
           //The | (OR) combines them all into one 32-bit integer. Each octet occupies exactly 8 bits and they don't overlap, so ORing them together just slots them into place.
           //Then *out = writes the result through the pointer into the caller's variable.

            /* a=147: 10010011 00000000 00000000 00000000  (shifted 24 bits left)
            b=188: 00000000 10111100 00000000 00000000  (shifted 16 bits left)
            c=192: 00000000 00000000 11000000 00000000  (shifted 8 bits left)
            d=43:  00000000 00000000 00000000 00101011  (not shifted) */

    return 1;  //represents success
}

static int parse_port(const char *s, int *out) { //handles ports
    if (!isdigit((unsigned char)s[0])) return 0;  //Rejects anything starting with +, -, or a space — things sscanf %d would accept but aren't valid ports.
    // s[0] = first character in string
    // (unsigned char)s[0] - cast first character in string to unsigned char because isdigit expects values in the range of unsigned char; without this, negative values (possible with char) could cause undefined behaviour
    // isdigit(...) — standard library function from <ctype.h>, returns nonzero if the character is 0-9, zero otherwise
    // if the first character is not a digit - negate immediately
    int port;
    int consumed = 0;

    if (sscanf(s, "%d%n", &port, &consumed) != 1)
        //reads one integer from string, if it cant - return 0. %n stores character count at &consumed
        //sscanf returns the number of ints read - if this is anything but 1 it isnt a valid port
        return 0;

    if (s[consumed] != '\0')
    //in C, strings are arrays, so s[consumed] is the last position in the string s
    //this checks for any junk at the end of the port and returns 0 if anything other than \0 is found
        return 0;

    if (port < 0 || port > 65535)
    //checks that port is in valid integer range
        return 0;

    *out = port;  //*out = writes the result through the pointer into the caller's variable.

    return 1; //represents success
}

//IMPORTANT - for all of the following we are parsing information about rules and NOT the input string. ranges refer to the range of valid ips and ports given in rules
static int parse_rule(const char *s, Rule *out) {
    //takes const char *s - the input string to parse and Rule* out - a pointer to a Rule struct
    char ip_part[64], port_part[32];  //fixed-size arrays to hold the IP and port strings after splitting the input.
    //ip_part can store up to 63 characters + the null terminator and port_part 31

    //Search for the space between IP and port - a valid rule looks like "147.188.192.43 22" — exactly one space separating the IP part from the port part. So finding that space tells the function where the IP ends and the port begins.
    const char *sp = strchr(s, ' ');  //creates pointer to a character called sp and stores pointer to first occurence of ' ' in s
    //strchr is built in to <string.h> and scans through a string looking a specific character, returning a pointer to the first occurence of it or NULL if not found
    if (!sp) return 0;  //no space found in s - invalid input
    if (sp != strrchr(s, ' ')) return 0;  //sp is a pointer to the first space and strrchr(s, ' ') finds the last space. If the first and last space aren't the same pointer, there's more than one space — invalid input
    //strchr is built in to <string.h> and scans through a string looking a specific character, returning a pointer to the last occurence of it or NULL if not found
    if (strpbrk(s, "\t\r\n")) return 0;  //strpbrk returns a pointer to the first character in s that matches any character in the second string. So this rejects anything containing tabs, carriage returns, or newlines.

    if (sscanf(s, "%63s %31s", ip_part, port_part) != 2)  //sscanf returns the number of successful matches
    //sscanf is from the C standard library, included via <stdio.h>. It works like scanf (which reads from keyboard input), but instead of reading from stdin (standard input) it reads from a string. You give it a string and a format, and it tries to parse values out of it.
    //reads string s - %63s reads up to 63 characters into ip_part, %31s reads up to 31 characters into port_part. The numbers are width limits to prevent buffer overflow
    //ip_part is the raw string like "147.188.192.43" or "147.188.192.43-147.188.194.255". It hasn't been parsed yet. The packing into a 32-bit integer happens later when parse_ip is called on it.
        return 0;  //triggered if theres not exactly 2 matches i.e., a valid IP and a valid port

    //Note -  a RULE like "147.188.192.0-147.188.194.255 22" allows any IP in that range to connect on port 22. We can parse ip ranges as well as individual ip addresses. Thats why we need to handle dashes:
    char *ip_dash = strchr(ip_part, '-');  //finds the first occurence of - in ip_part and returns a pointer to this - called ip_dash
    if (ip_dash) {  //if ip_dash is not NULL
        *ip_dash = '\0';  //writes a null terminator at the position of the dash, effectively separating an ip address RANGE into two separate strings
        //recall that parse_ip takes two parameters: const char *s, uint32_t *out ()
        if (!parse_ip(ip_part, &out->ip_start)) return 0;  //parses first half (before the dash, essentially the first ip address/start of range)
        //out is a pointer to a Rule struct, and ip_start is a field inside that struct. The -> operator is how you access a struct field through a pointer
        //ip_part fills const char *s and &out->ip_start fills uint32_t *out in the parse_ip call
        //&out->ip_start is the address of the ip_start field in the Rule struct, which is where parse_ip will write the packed 32-bit integer.
        if (!parse_ip(ip_dash + 1, &out->ip_end)) return 0; //ip_dash IS a pointer to the dash in the raw input string. ip_dash + 1 is the location after it so its the start of the second address 
        if (out->ip_start >= out->ip_end) return 0;  //it's checking that the range is valid. The start IP must be smaller than the end IP. If start is greater than or equal to end, the range is backwards or pointless, so return 0.
    } else {
        if (!parse_ip(ip_part, &out->ip_start)) return 0;  //if theres no dash in the input string (a single IP rather than a range)
        out->ip_end = out->ip_start;  //instead of parsing 2 IP addresses, it parses 1 and sets ip_start and ip_end to the same value
    }

    char *port_dash = strchr(port_part, '-');  //finds the first occurence of - in port_part and returns a pointer to a this - called port_dash
    if (port_dash) {  //if port_dash is not NULL
        *port_dash = '\0';  //writes a null terminator at the position of the dash, effectively separating a port address RANGE into two separate strings
        if (!parse_port(port_part, &out->port_start))    return 0;  //parses first half (before the dash, essentailly the first port)
        //out is a pointer to a Rule struct, and port_start is a field in that Rule struct
        //&out->port_start is the address of the port_start field in the Rule struct, which is where parse_port will write the port integer.
        if (!parse_port(port_dash + 1, &out->port_end))  return 0;  //port dash is a pointer to the - in the raw port input so port_dash + 1 is the start of the second port number
        if (out->port_start >= out->port_end)             return 0;
    } else {
        if (!parse_port(port_part, &out->port_start)) return 0;  //if theres no dash in the input string (a single port rather than a range)
        out->port_end = out->port_start;  //instead of parsing 2 port numbers, it parses 1 and sets port_start and port_end to the same value
    }

    return 1;  //represents success
}

//all that parsing work in parse_ip, parse_port, and parse_rule exists precisely so that these two simple comparisons can work. Packing IPs into 32-bit integers makes range checking trivial.
static int ip_in_range(uint32_t ip, const Rule *r) {  //function called ip_in_range returns an integer and takes a 32 bit integer called ip and a pointer to a Rule struct
    return ip >= r->ip_start && ip <= r->ip_end;  //returns 1 if ip is in valid range
    //ip_start and ip_end are fields in the rule struct which we access here via the r pointer 
}

static int port_in_range(int port, const Rule *r) {
    return port >= r->port_start && port <= r->port_end; //returns 1 if port is in valid range
}

//DAY 3
//properly allocates memory to responses so that they can be later freed
static char *make_response(const char *s) {  //called inside the handler functions whenever they have to return a response string 
    char *r = strdup(s);
    //strdup does two things in one call - malloc and strcpy. Here, strdup allocates enough heap memory to fit the string, copies it in, and returns a pointer to it. That pointer gets stored in r and returned.
    if (!r) { perror("strdup"); exit(1); }  //error handling for if strdup fails - strdup returns NULL if it couldn't allocate memory
    //!r checks if r is NUL
    //perror("strdup") prints an error message to stderr (the standard error stream as opposed to the standard output)
    //exit(1) kills the program immediately
    //"if we can't even allocate memory for a response string, something is seriously wrong and there's no point continuing."
    return r;  //pointer to to the allocated heap memory storing string s
}

//DAY 5
static void ip_to_str(uint32_t ip, char *buf) {
    sprintf(buf, "%u.%u.%u.%u",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >>  8) & 0xFF,
             ip        & 0xFF);
}

//keeps a record of every request that comes into the server, in order. This is so the R command can later return the full history of all requests that have been made.
//Every time processRequest is called, log_request is called first, storing a copy of the request string into the requests dynamic array before any handler runs.
static void log_request(const char *request) {  //takes pointer to request string 
    if (req_count == req_cap) {  //checks if requests array is full
        size_t new_cap;
        if (req_cap == 0) {
            new_cap = 8;  //arbitrary but conventional - good starting size
        } else {
            new_cap = req_cap * 2;  //double capacity if the capacity is more than 0
        }
        char **tmp = realloc(requests, new_cap * sizeof(char *));  //resize the requests array to hold new_cap pointers, and store the result in tmp rather than directly in requests in case it fails
        //char **tmp declares a temporary pointer to a pointer to char - same type as requests (an array of string pointers)
        //realloc takes two pointers: requests — the existing array to resize and new_cap * sizeof(char *) — the new total size in bytes
        //new_cap is how many slots we want and sizeof(char *) is how many bytes each slot needs (one pointer) - multiplied together gives total bytes needed
        if (!tmp) { perror("realloc"); exit(1); }  //error handling for realloc - kills program immediately if tmp is NULL indicating that realloc failed
        //atp tmp should store a pointer to the first element of the newly resized array/block of memory on the heap that can now hold new_cap string pointers
        requests = tmp;  //resizing of requests (array of string pointers) to hold new_cap string pointers
        req_cap  = new_cap;  //update capacity of requests array
    }
    requests[req_count] = strdup(request);  //update number of pointers in requests array 
    // So malloc inside strdup allocates a separate block of memory big enough to hold all the characters of the string, and then the pointer to that block is what gets stored in the requests array slot.
    if (!requests[req_count]) { perror("strdup"); exit(1); }  
    req_count++; 
    // req_count tracks how many request strings have been logged so far, which is also the index of the next empty slot in the array.
}

//concatenate every request thats ever been logged from the requesrs array
static char *handle_R(void) {
    if (req_count == 0) //no requests yet 
        return make_response(""); //return an empty string 

    size_t total = 0; //total is the number of bytes required to hold all the request strings together 
    for (size_t i = 0; i < req_count; i++) //loop through requests array
        total += strlen(requests[i]) + 1; //requests is an array of char * pointers, so each requests[i] is a pointer to an individual string. strlen follows that pointer and counts characters until it hits the null terminator of that string.
        //strlen(requests[i]) = used to count the number of characters in that string (not counting the null terminator)
        //+1 for the new line that will be appended after each string

    char *response = malloc(total + 1); //malloc allocates enough memory on the heap for entire response string then returns a pointer to that bit of memory which is stored in response
    //+1 adding extra byte just for the null terminator at the very end of the string
    if (!response) { perror("malloc"); exit(1); } //error handling - kill program if malloc fails and response is NULL

    char *p = response; //create new pointer to the same place as response
    //p and response point to the start of the memory allocated to the concatenated request strings - but we need to actually move them there - response stays at the start so we can return the concatenated string and p is used to add the individual request strings
    for (size_t i = 0; i < req_count; i++) { //loop through requests array
        size_t len = strlen(requests[i]); //records length of each string in requests array as len
        memcpy(p, requests[i], len); // copy len bytes from requests[i] into the location pointed to by p. It's essentially stamping the characters of each request string into the response buffer.
        //memcpy(destination, source, number of bytes to copy)
        p += len; //moves p to after the characters of the string we have just added to the master requests string
        *p++ = '\n'; //writes a new line character and moves past it so we can start writing the next string 
    }
    *p = '\0'; //when we have written out all the requests - write a null terminator at p to properly end the master request string

    return response; //return the string of all the requests
}

static char *handle_A(const char *request) {
    const char *rule_str = request + 2;  //rule_str is like rest - its a pointer to the first element in the ip in the input string (remember that this IS the string - there is no separate string type)

    Rule r = {0}; //eclares a new rule struct called r and initializes ALL its fields to 0 (with pointer set to NULL)
    if (!parse_rule(rule_str, &r)) //remember that parse_rule takes an input string and a pointer to where this rule will be stored 
        return make_response("Invalid rule");
    
    // allocate a new larger block of memory to hold more Rule structs
    if (rule_count == rule_cap) {
        size_t new_cap;
        if (rule_cap == 0) {
            new_cap = 8; // first allocation, start at 8
        } else {
            new_cap = rule_cap * 2; // already has capacity, double it
        }
        Rule *tmp = realloc(rules, new_cap * sizeof(Rule));
        if (!tmp) { perror("realloc"); exit(1); }
        rules    = tmp;
        rule_cap = new_cap;
    }

    rules[rule_count++] = r;  //actually adds new rule struct to the next empty slot in the allocated memory
    return make_response("Rule added");
}
//C is used to check whether an ip/port pair is valid/well-formed AND if its allowed (according to the rules). Validity is just the first hurdle. After confirming the input is a real IP and a real port number, it then asks "does this pair fall within any of the rules we've stored?" 
static char *handle_C(const char *request) {  //takes original raw input 
    const char *rest = request + 2;  //rest is a pointer to the first element in the ip address on the input string (request is a pointer to the very first element in the input string so + 2 moves it to the first element in the ip)

    if (strpbrk(rest, "\t\r\n"))  //rejects inputs with tabs, carriage requests and newline characters
        return make_response("Illegal IP address or port specified");        

    const char *sp = strchr(rest, ' ');  //sp is a pointer to the first space in the input after rest
    if (!sp || sp != strrchr(rest, ' '))  //rejects input if there is no space or if there is more than one space (after rest)
        return make_response("Illegal IP address or port specified");

    char ip_str[64], port_str[32];
    if (sscanf(rest, "%63s %31s", ip_str, port_str) != 2)  //same job as sscanf in parse_rule - splits the pair into separate strings (still with the formatting and dots between ip chunks)
        return make_response("Illegal IP address or port specified");

    uint32_t ip;
    int port;
    if (!parse_ip(ip_str, &ip) || !parse_port(port_str, &port)) //calls parse_ip and parse_port on the seperate ip and port strings (ip_str and port_str)
        return make_response("Illegal IP address or port specified");  //triggered if either parse_ip OR parse_port fail

    for (size_t i = 0; i < rule_count; i++) { //loop through rules array (rule_count is the number of rules in the rules array)
        if (ip_in_range(ip, &rules[i]) && port_in_range(port, &rules[i])) { //check the ip and port both fall within the valid range
            //&rules[i] passes a pointer to the current rule so the helper functions can read its fields.
            Rule *r = &rules[i]; //just for convenience - stores &rules[i] as r
            //same dynamic array check as in log request - grows the queries array to fit more Query structs 
            if (r->query_count == r->query_cap) {
                size_t new_cap;
                    if (r->query_cap == 0) {
                        new_cap = 8;        // first time this rule's query array has needed to grow
                    } else {
                        new_cap = r->query_cap * 2;   // already has capacity, double it
                    }
                Query *tmp = realloc(r->queries, new_cap * sizeof(Query));
                if (!tmp) { perror("realloc"); exit(1); }
                r->queries  = tmp;
                r->query_cap = new_cap;
            }
            //writes the new Query into the first empty slot in the queries array
            r->queries[r->query_count].ip   = ip; //we use the . to access a field inside a struct
            r->queries[r->query_count].port = port;
            r->query_count++;

            return make_response("Connection accepted");
        }
    }

    return make_response("Connection rejected");
}

//Its job is to free all heap-allocated memory and reset the program back to a clean state.
static char *handle_F(void) {
    for (size_t i = 0; i < rule_count; i++) //loop through Rule structs
        free(rules[i].queries); //each Rule struct has a queries array inside it - free each queries array by looping through the rules array

    free(rules); //free the memory the rules pointer points to
    rules = NULL; //rules is now a dangling pointer so set to NULL
    rule_count = 0;
    rule_cap   = 0;

    //requests[i] is the string, requests is the array that holds all the pointers to those strings.
    for (size_t i = 0; i < req_count; i++) //loop through the requests
        free(requests[i]); //frees each individual request string on the heap 
    free(requests); //frees the array of pointers itself
    requests  = NULL;  //requests is now a dangling pointer so set to NULL
    req_count = 0;
    req_cap   = 0;

    return make_response("All rules deleted");
}

static char *handle_D(const char *request) {
    const char *rule_str = request + 2; //rest is a pointer to the first element in the ip address on the input string (request is a pointer to the very first element in the input string so + 2 moves it to the first element in the ip)

    Rule r = {0};  //creates a new temporary rule struct on the stack called r and initialises all fields to 0
    if (!parse_rule(rule_str, &r)) //parse the rule we have created (actually want to delete) but dont add it to the rules array
        return make_response("Invalid rule");

    /* find exact match for this rule in the Rule structs */
    for (size_t i = 0; i < rule_count; i++) {
        if (rules[i].ip_start   == r.ip_start  &&
            rules[i].ip_end     == r.ip_end     &&
            rules[i].port_start == r.port_start &&
            rules[i].port_end   == r.port_end) {

            /* free this rule's queries */
            free(rules[i].queries);

            /* shift remaining rules down */
            memmove(&rules[i], &rules[i+1], (rule_count - i - 1) * sizeof(Rule));
            /*memmove copies a block of memory from one location to another. It takes three arguments:
            - destination — `&rules[i]`, where to copy to
            - source — `&rules[i+1]`, where to copy from  
            - size — how many bytes to copy */
            rule_count--;

            return make_response("Rule deleted");
        }
    }

    return make_response("Rule not found");
} //the temporary rule we create in order to find it in the rules array lives on the stack so it is deleted when the function returns

static char *handle_L(void) {
    if (rule_count == 0)
        return make_response("");

    /* first pass: calculate total length needed */
    size_t total = 0;
    for (size_t i = 0; i < rule_count; i++) {
        Rule *r = &rules[i];

        /* "Rule: " + ip_start */
        char ip1[16], ip2[16];
        ip_to_str(r->ip_start, ip1);
        ip_to_str(r->ip_end,   ip2);

        if (r->ip_start == r->ip_end)
            total += strlen("Rule: ") + strlen(ip1);
        else
            total += strlen("Rule: ") + strlen(ip1) + 1 + strlen(ip2); /* +1 for '-' */

        /* " " + port */
        if (r->port_start == r->port_end)
            total += 1 + 5; /* space + up to 5 digit port */
        else
            total += 1 + 5 + 1 + 5; /* space + port-port */

        total += 1; /* newline */

        /* queries */
        for (size_t j = 0; j < r->query_count; j++) {
            char qip[16];
            ip_to_str(r->queries[j].ip, qip);
            total += strlen("Query: ") + strlen(qip) + 1 + 5 + 1; /* ip + space + port + newline */
        }
    }

    char *response = malloc(total + 1);
    if (!response) { perror("malloc"); exit(1); }

    /* second pass: fill the response */
    char *p = response;
    for (size_t i = 0; i < rule_count; i++) {
        Rule *r = &rules[i];

        char ip1[16], ip2[16];
        ip_to_str(r->ip_start, ip1);
        ip_to_str(r->ip_end,   ip2);

        if (r->ip_start == r->ip_end)
            p += sprintf(p, "Rule: %s", ip1);
        else
            p += sprintf(p, "Rule: %s-%s", ip1, ip2);

        if (r->port_start == r->port_end)
            p += sprintf(p, " %d\n", r->port_start);
        else
            p += sprintf(p, " %d-%d\n", r->port_start, r->port_end);

        for (size_t j = 0; j < r->query_count; j++) {
            char qip[16];
            ip_to_str(r->queries[j].ip, qip);
            p += sprintf(p, "Query: %s %d\n", qip, r->queries[j].port);
        }
    }
    *p = '\0';

    return response;
}

extern char *processRequest(char *request);

char *processRequest(char *request) {
    /* trim trailing whitespace in case harness sends "rule\n" */
    size_t len = strlen(request);
    while (len > 0 && isspace((unsigned char)request[len-1]))
        request[--len] = '\0';

    pthread_mutex_lock(&global_lock);
    log_request(request);

    char *response;

    if (strcmp(request, "R") == 0)
        response = handle_R();
    else if (strncmp(request, "A ", 2) == 0)
        response = handle_A(request);
    else if (strncmp(request, "C ", 2) == 0)
        response = handle_C(request);
    else if (strcmp(request, "F") == 0)
        response = handle_F();
    else if (strncmp(request, "D ", 2) == 0)
        response = handle_D(request);
    else if (strcmp(request, "L") == 0)
        response = handle_L();
    else
        response = make_response("Illegal request");

    pthread_mutex_unlock(&global_lock);
    return response;
}
