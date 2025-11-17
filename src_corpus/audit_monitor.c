#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <bits/getopt_core.h>
#include <linux/limits.h>


#define MALICIOUS_THRESHOLD 5  // > 5 distinct files with denied access


struct log_entry {

	int uid; /* user id (positive integer) */
	pid_t pid; /* process id (positive integer) */

	char *file; /* filename (string) */

	time_t date; /* file access date - utc*/
	time_t time; /* file access time - utc*/

	int operation; /* access type values [0-3] */
	int action_denied; /* is action denied values [0-1] */

	char *filehash; /* file hash - sha256 - evp */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};

/* this helper function is used to resolve issues between absolute path and the pure filename, that were creating issues when
calculating the modifications of a file. breaks down the path and extracts the file name at the end.*/
static int filename_matches(const char *logged, const char *query)
{
    // exact match, all good
    if (strcmp(logged, query) == 0) {
        return 1;
    }

    // if logged is a path, extract the file name
    const char *base = strrchr(logged, '/'); // go to the last occurence of '/' 
    if (base) {
        base++;
        if (strcmp(base, query) == 0) { //compare them ahgain
            return 1;
        }
    }

    return 0;
}

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./audit_monitor \n"
		   "Options:\n"
		   "-s, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
    // Make sure we start from the beginning of the log file
    rewind(log);

    // Structures to track per-user denied accesses
    struct user_info {
        int uid;
        int num_files;   // number of distinct files with denied access
        int cap;         // capacity of files array
        char **files;    // dynamic array of filenames, files[0..num_files-1]
    };

	
    struct user_info *users = NULL;
    int users_count = 0; // starting with 0 users in the struct
    int users_cap = 0; // start with 0 allocated capacity

    // biffers to hold the data of each log line
    int uid, operation, action_denied;
    pid_t pid;
    char filename[PATH_MAX];
    char date_buf[11]; // yyyy-mm-dd
    char time_buf[9]; // hh:mm:ss
    char hash_buf[65]; // 64 hex chars with a null termination \0

    // outer while loop, reads the next log line in each iteration
    while (fscanf(log, "%d %d %s %10s %8s %d %d %64s",
                  &uid, &pid, filename, date_buf, time_buf,
                  &operation, &action_denied, hash_buf) == 8) {

        //filtering, we only want denied == 1 lines
        if (action_denied == 0) {
            continue;
        }

        // if the struct already has this uid (there have been other denied accesses), skip this
        int uidx = -1;
        for (int i = 0; i < users_count; i++) {
            if (users[i].uid == uid) {
                uidx = i;
                break;
            }
        }

		//if this is the first denied access for this uid, enter it in the struct
        if (uidx == -1) {
            if (users_count == users_cap) { // if USER CAPACITY has been reached, grow capacity / reallocate
                int new_cap = (users_cap == 0) ? 4 : users_cap * 2; //capacity grows in powers of 2
                struct user_info *tmp = realloc(users, new_cap * sizeof(*users));

                if (!tmp) { // if an error happens, free everything and ragequit (coward)
                    perror("realloc");
                    for (int i = 0; i < users_count; i++) {
                        for (int j = 0; j < users[i].num_files; j++) {
                            free(users[i].files[j]);
                        }
                        free(users[i].files);
                    }
                    free(users);
                    return;
                }
                users = tmp;
                users_cap = new_cap;
            }

			//enter the current (new) user in the struct
            users[users_count].uid = uid;
            users[users_count].num_files = 0;
            users[users_count].cap = 0;
            users[users_count].files = NULL;
            uidx = users_count;
            users_count++;
        }

		//now get the insstance of the current user
        struct user_info *u = &users[uidx];

        // check if this filename already exists in the current user's denied access filenames
        int already_counted = 0;
        for (int j = 0; j < u->num_files; j++) {
            if (strcmp(u->files[j], filename) == 0) {
                already_counted = 1;
                break;
            }
        }

        if (already_counted==0) {
            // add the new distinct filename, and follow same strategy for the FILES CAPACITY as above for the users capacity 
            if (u->num_files == u->cap) {
                int new_cap = (u->cap == 0) ? 4 : u->cap * 2; // again, capacity growth in powers of 2
                char **tmp = realloc(u->files, new_cap * sizeof(char *));


                if (!tmp) {
                    perror("realloc");
                    // same cleanup as before in case of failure
                    for (int i = 0; i < users_count; i++) {
                        for (int j = 0; j < users[i].num_files; j++) {
                            free(users[i].files[j]);
                        }
                        free(users[i].files);
                    }
                    free(users);
                    return;
                }
                u->files = tmp;
                u->cap = new_cap;
            }

            u->files[u->num_files] = strdup(filename);


            if (!u->files[u->num_files]) {
                perror("strdup");
                // cleanup similarly in case strdup() fails when trying to copy the filename
                for (int i = 0; i < users_count; i++) {
                    for (int j = 0; j < users[i].num_files; j++) {
                        free(users[i].files[j]);
                    }
                    free(users[i].files);
                }
                free(users);
                return;
            }
            u->num_files++;
        }
    }

    printf(" ---- (malicious) users with more than %d distinct denied files: --- \n",
           MALICIOUS_THRESHOLD);

    int at_least_one_malicious = 0;
    for (int i = 0; i < users_count; i++) {
        if (users[i].num_files > MALICIOUS_THRESHOLD) {
            printf("%d\n", users[i].uid);
            at_least_one_malicious = 1;
        }
    }

    if (!at_least_one_malicious) {
        printf("no malicious users found.\n");
    }

    // clean up the struct and return 
    for (int i = 0; i < users_count; i++) {
        for (int j = 0; j < users[i].num_files; j++) {
            free(users[i].files[j]);
        }
        free(users[i].files);
    }
    free(users);

    return;
}



void
list_file_modifications(FILE *log, char *file_to_scan)
{

    rewind(log);

    // keeps track of user modification counts
    struct user_mod {
        int uid;
        int mods;   //how many times this user actually modified the file
    };

    struct user_mod *users = NULL;
    int users_count = 0;
    int users_cap   = 0;

    // set of unique hashes for this file
    char **unique_hashes = NULL;
    int unique_count = 0;
    int unique_cap   = 0;

    // last seen hash for this file (across all users), to detect changes
    char last_hash[65];
    int have_last_hash = 0;

    // buffers for parsing each log line
    int uid, operation, action_denied;
    pid_t pid;
    char filename[PATH_MAX];
    char date_buf[11];    // YYYY-MM-DD
    char time_buf[9];     // HH:MM:SS
    char hash_buf[65];    // 64 hex chars + '\0'

    // read the log line by line
    while (fscanf(log, "%d %d %s %10s %8s %d %d %64s",
                  &uid, &pid, filename, date_buf, time_buf,
                  &operation, &action_denied, hash_buf) == 8) {

        // only care about the specific file
        if (!filename_matches(filename, file_to_scan)) {
    		continue;
		}

        // ignore denied actions – they didn't change the file
        if (action_denied != 0) {
            continue;
        }

		/* QUICK DESCRIPTION FOR THIS:
		We define a modification to the file as a DIFFERENT HASH than the PREVIOUS HASH, when we call fclose().
		HOWEVER, this never accounts for the initial modification (fopen() - 0 for create, to fclose() after the first modification).
		So, for each file, we also count the operation 0, so we can count the initial modification from empty to something else. (append, overwrite, whatever)
		*/

        if (operation != 3 && operation !=0) {
            continue;
        }

        // have a set of unique hashes (distinct file states)
        int seen = 0;
        for (int i = 0; i < unique_count; i++) {
            if (strcmp(unique_hashes[i], hash_buf) == 0) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            if (unique_count == unique_cap) {
                int new_cap = (unique_cap == 0) ? 4 : unique_cap * 2;
                char **tmp = realloc(unique_hashes, new_cap * sizeof(char *));
                if (!tmp) {
                    perror("realloc");
                    // same cleanup strategy in case of failure as all the above
                    for (int i = 0; i < unique_count; i++) {
                        free(unique_hashes[i]);
                    }
                    free(unique_hashes);
                    free(users);
                    return;
                }
                unique_hashes = tmp;
                unique_cap = new_cap;
            }
            unique_hashes[unique_count] = strdup(hash_buf);
            if (!unique_hashes[unique_count]) {
                perror("strdup");
                    // i'm sick of commenting on clean up for failure events, so i just won't do it for the next one.
                for (int i = 0; i < unique_count; i++) {
                    free(unique_hashes[i]);
                }
                free(unique_hashes);
                free(users);
                return;
            }

			/* We wanted to count the transition from empty file to anything else, as a modification before.
			However, the initial hash of creation DOES NOT constitute a change.
			It is only used to be able to track the INITIAL modification (empty -> something else).
			*/
			if(operation==3) unique_count++;
        }

        //detect modifications using the last hash
        int is_modification = 0;
        if (!have_last_hash) {
            strcpy(last_hash, hash_buf);
            have_last_hash = 1;
        } else {
            if (strcmp(last_hash, hash_buf) != 0) {
                // if file ended up in a new state -> modification event
                is_modification = 1;
                strcpy(last_hash, hash_buf);
            }
        }

        if (!is_modification) continue;

        //find or create this user in the users[] array
        int uidx = -1;
        for (int i = 0; i < users_count; i++) {
            if (users[i].uid == uid) {
                uidx = i;
                break;
            }
        }
        if (uidx == -1) {
            if (users_count == users_cap) {
                int new_cap = (users_cap == 0) ? 4 : users_cap * 2;
                struct user_mod *tmp = realloc(users, new_cap * sizeof(*users));
                if (!tmp) {
                    perror("realloc");
                    for (int i = 0; i < unique_count; i++) {
                        free(unique_hashes[i]);
                    }
                    free(unique_hashes);
                    free(users);
                    return;
                }
                users = tmp;
                users_cap = new_cap;
            }
            users[users_count].uid  = uid;
            users[users_count].mods = 0;
            uidx = users_count;
            users_count++;
        }

        // count this modification for that user
        users[uidx].mods++;
    }

    // print resulkts
    printf("File: %s\n", file_to_scan);
    printf("User modifications, based on ACTUAL hash changes (counting modification from empty file):\n");

    if (users_count == 0) {
        printf("  (no modifications recorded)\n");
    } else {
        for (int i = 0; i < users_count; i++) {
            printf("  UID %d -> %d modifications\n",
                   users[i].uid, users[i].mods);
        }
    }

    printf("Unique modifications (distinct resulting file states): %d\n",
           unique_count);

    // clean up and GET OUTTT

    for (int i = 0; i < unique_count; i++) {
        free(unique_hashes[i]);
    }
    free(unique_hashes);
    free(users);

    return;
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./access_audit.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./access_audit.log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:s")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 's':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
