#define _GNU_SOURCE

#include <limits.h>  // PATH_MAX
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h> //install the required package

#define LOG_FILE_PATH "access_audit.log"
#define HASH_SIZE 64 // SHA-256 is 32 bytes (64 hex characters)

// NOTE: You'll need an absolute path, so resolve 'path' before using it.
// The provided skeleton only uses path as is. For a full implementation, 
// you'd typically use realpath(path, resolved_path) if needed, but for now, 
// we'll stick to the provided 'path' argument.

const char *get_path_from_stream(FILE *stream) {
    if (stream == NULL) {
        return NULL;
    }

    int fd = fileno(stream);
    if (fd == -1) {
        return NULL;
    }

    static char path_buf[PATH_MAX];
    char link_path[64];

    // Build /proc/self/fd/<fd> path
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(link_path, path_buf, sizeof(path_buf) - 1);
    if (len == -1) {
        return NULL;  // could not resolve
    }

    path_buf[len] = '\0'; // null-terminated
    return path_buf;
}

void log_event(const char *path, int operation, int action_denied, const char *file_hash)
{
	FILE *(*original_fopen)(const char*, const char*) = dlsym(RTLD_NEXT, "fopen");
    int (*original_fclose)(FILE*) = dlsym(RTLD_NEXT, "fclose");

    FILE *log_file;
    time_t now; // will take the UNIX timestamp
    struct tm *tm_struct; // time struct
    char date_buf[11]; // YYYY-MM-DD\0
    char time_buf[9];  // HH:MM:SS\0
    
    // 1. Get current time (UTC)
    time(&now); // unix timestamp assigned
    tm_struct = gmtime(&now); // takes the unix timestamp, converts to a time struct (days, months, years, ..)
    
    // format the date n time
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", tm_struct);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_struct);

    //2. open the log file in append mode 
    log_file = (*original_fopen)(LOG_FILE_PATH, "a");
    if (log_file == NULL) {
        return;
    }

    // 3. append the log entry in this very format
    fprintf(log_file, "%d %d %s %s %s %d %d %s\n",
            getuid(), getpid(), path, date_buf, time_buf,
            operation, action_denied, file_hash
    );

    // 4. close the log file using the og fclose()
    (*original_fclose)(log_file);
}

char *sha256_file_hash(const char *path) {
    // Static buffer to return the hex string (64 chars for SHA-256 + '\0')
    static char hex_hash[HASH_SIZE + 1];

    FILE *file = NULL;
    FILE *(*original_fopen)(const char*, const char*);
    int (*original_fclose)(FILE*);

    EVP_MD_CTX *mdctx = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    unsigned int i;

    // in case of failure, it defaults to all zeros
    memset(hex_hash, '0', HASH_SIZE);
    hex_hash[HASH_SIZE] = '\0';

    // get the og fclose/fopen to avoid infinite recursion that breaks the program
    original_fopen  = dlsym(RTLD_NEXT, "fopen");
    original_fclose = dlsym(RTLD_NEXT, "fclose");

    if (!original_fopen || !original_fclose) {
        return hex_hash;
    }

    file = original_fopen(path, "r");
    if (file == NULL) {
        // if file cannot be opened for hashing, return all zeros
        return hex_hash;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        original_fclose(file);
        return hex_hash;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        original_fclose(file);
        return hex_hash;
    }

    char buffer[1024];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(mdctx);
            original_fclose(file);
            return hex_hash;
        }
    }

    if (ferror(file)) {
        EVP_MD_CTX_free(mdctx);
        original_fclose(file);
        return hex_hash;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        original_fclose(file);
        return hex_hash;
    }

    EVP_MD_CTX_free(mdctx);
    original_fclose(file);

    // binary hash conversion to hex string
    for (i = 0; i < hash_len && i * 2 + 1 < sizeof(hex_hash); i++) {
        sprintf(&hex_hash[i * 2], "%02x", hash[i]);
    }
    hex_hash[HASH_SIZE] = '\0';

    return hex_hash;
}


FILE * fopen(const char *path, const char *mode){ // OPERATIONS 0,1 (CREATE, OPEN)

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	struct stat st;

	// stat() returns 0 if file exists, -1 if not
    int existed_before = (stat(path, &st) == 0); // Check if file exists

	// call the og fopen function
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	int operation;
    int action_denied = 0;
    
	// (operation,action_denied) can be 00,01,10,11
    if (original_fopen_ret == NULL && existed_before) {
        action_denied = 1;
        operation =1;
    }
    else if (original_fopen_ret == NULL && !existed_before) {
        action_denied = 1;
        operation = 0; 
    }
    else if (!existed_before){
        operation= 0;
	}
	else {
		operation=1;
	}
    
    // hash the file
    char *hash = sha256_file_hash(path); 

    // log the entry
    log_event(path, operation, action_denied, hash);


	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) // OPERATION 2 (WRITE)
	// fwrite attempts to write a total of size*nmemb bytes
	// nmemb is the number of elements we want to write
	// fwrite returns the number of elements written. if <nmemb, it has written them partially or not at all.
	// considered successful if returned number == nmemb.
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	const char *path = get_path_from_stream(stream);
	if (!path) {
        char zeros[HASH_SIZE + 1];
        memset(zeros, '0', HASH_SIZE);
        zeros[HASH_SIZE] = '\0';

        // mark as denied if fwrite itself failed
		// (as seen in discussions on eclass, a failure is important to be logged, so it goes down to the log as a denial)
        int denied = (original_fwrite_ret != nmemb);
        log_event("UNKNOWN", 2, denied, zeros);
        return original_fwrite_ret;
    }

    char *hash = sha256_file_hash(path);

	int denied = (original_fwrite_ret != nmemb); // if fwrite returns < nmemb, something went wrong => mark as denied for the assignment's purposes
    log_event(path, 2, denied, hash);


	return original_fwrite_ret;
}


int fclose(FILE *stream) // OP 3 (CLOSE)
{
    int (*original_fclose)(FILE*);
    original_fclose = dlsym(RTLD_NEXT, "fclose");

    if (!original_fclose) return EOF; // if dlsym fails, fall back to -1 

    const char *path = get_path_from_stream(stream);  // BEFORE close

    int original_fclose_ret = (*original_fclose)(stream);

    if (!path) {
        // couldn't resolve path? log with placeholder path and hash
        char zeros[HASH_SIZE + 1];
        memset(zeros, '0', HASH_SIZE);
        zeros[HASH_SIZE] = '\0';

		int access_denied = (original_fclose_ret != 0); // if we know that we failed, we know that original_fclose_ret != 0, therefore access_denied = 1
        log_event("UNKNOWN", 3, access_denied, zeros);
        return original_fclose_ret;
    }

    char *hash = sha256_file_hash(path);

    if (original_fclose_ret == 0) { //successful close
        log_event(path, 3, 0, hash);
    } else {
        log_event(path, 3, 1, hash);
    }

    return original_fclose_ret;
}