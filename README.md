Course instructor : Sotirios Ioannidis
TA : Eva Papadogiannaki

# Assignment 3 - Access Control Logging
##### Gravalos Georgios - Angelos, 2021030001
##### Kerimi Rafaela - Aikaterina, 2021030007

**!! If you do not wish to read the implementation logic, just skip to the final section of the readme file, where we provide information on how we have conducted the test and what you can do to verify the results.**

Our goal for this assignment was to implement an LD_PRELOAD-based function interception. In short, this custom library intercepts the traditional functions ```fopen(), fwrite(), fclose()```, so that every file access by a user or program is logged, including : success (denied/accessed), operation type (create/open/write/close), user and process IDs, and the SHA256 hash of the file (using openssl's EVP) at the time of the operation.
The accompanying monitoring tool analyzes the log file and provides two capabilities:
1) Detection of malicious users (users that have been denied access to more than 5 distinct files)
2) Analyzation of file modification (counting the total modifications of a file, as well as the unique modifications), by monitoring the difference in file hash value (content change) across the log.

In more detail,

### Step 1 - Implemented the audit logger
```(audit_logger.c, audit_logger.so, access_audit.log)```
We implemented the logic of the overriden ``` fopen(), fwrite(), fclose()```, as well as the logging logic, in the .c file.
The original functions are called using ```dlsym(RTLD_NEXT, ...)```, then the type of operation and access/denied are inferred depending on what the original functions themselves return, then finally the event is logged in ```access_audit.log``` in this very sequence:
```(UID, PID, file path, date, time, operation, access_denied, file hash)```.
Where operation can be (0 creation, 1 open, 2 write, 3 close),
and access_denied can be (0 succesfully accesed, 1 denied access).
A few technical details here are:
1) We used ```stat()``` to distinguish between open and create for ```fopen()```
2) The helper function ```get_path_from_stream()``` recovers the filename from FILE* for fwrite/fclose.
It is worth noting here, that for the purpose of this assignment, and taking into consideration a few conversation threads with the TAs on eclass, we have decided to count any other possible failure as access_denied = 1 (denied access). This means that even a failure related to causes other than access control, will lead to the flag access_denied=1.

```audit_logger.so``` is the library generated from the compilation of the .c file.

### Step 2 - Implemented the audit monitor tool
As mentioned above, the tool can be used as follows:
1) ```./audit_monitor -s``` : Shows the malicious users (denied access to more than 5 distinct files).
The monitor tool parses the log file from the beginning, filters to keep only the lines that concern ```access_denied==1```. The struct ```user_info``` is used to keep track of all users who have at least one denied access to a file, and it holds the user id, the number of distinct files with denied access, and the array of file names the user has been denied access to, and the capacity of said array of file names.
When we're done processing the log file and the struct has been filled with users who have been denied access to files, the users who have been denied access to >5 distinct files are printed to the console (their UIDs).
2) ```./audit_monitor -i <file>``` : Shows the modifications and unique modificaitons for file ```<file>```.
To better understand what we define as modification:
For a collection of hash values H1,H2,H3,.. for the content of a file, a modification occurs when H_i != H_i-1, therefore when the hash value isn't the same as the previous one.
A UNIQUE modification occurs when a hash value H_i has never been seen again for a particular file.
For each line in the log file, we filter/keep only those that concern operation==3 or operation==0 (close or create). We mainly focus on close operations, because a close happens right after opening or writing to a file, hinting at possible modifications. However, if we do not include the hash value at the creation of the file, then we will not be able to track the very first modification (from the hash value of the empty file, to the hash value of its first modification), and that's why we also include the creation operation when filtering the log lines.
Finally, the tool prints each uid that modified the file, along with their modification count.

**Sidenote on this** : In ```audit_logger.c```, we call fopen() using the name of the file (e.g. 'textfile'), and that's exactly how it logs the filename. However, ```fwrite/fclose``` only receive a FILE* stream, not the original filename. To recover the file name for these two operations, we have implemented the helper function ```get_path_from_stream()```, which resolves the file descriptor and produces an ABSOLUTE PATH.
This means that ```fopen()``` logs a plain file name, while ```fclose/fwrite``` log an absolute path.
To mitigate this inconsistency, we have also implemented the helper function ```filename_matches()```, which checks if the absolute path is the same as the filename (spoiler alert, it won't be). If it isn't, it breaks the absolute path down to the file name, so that we can make consistent comparisons in the log for all three ```fopen, fwrite, fclose```. 
These two helper functions we just mentioned are crucial to the functionality of the monitor. We do realize that this isn't an ideal solution to the problem, but it is enough for the purpose of the assignment.
### Step 3 - Implemented the test
To test all this, we implemented a test ```test_audit.c```.
WE MUST first run it as the owner, so as to create the 6 text files for the test and set permissions to them. Then, we can run it as any other (malicious or not) user we want.
The test cases are:
1) Creating the test files (if they don't already exist), set the access to 644, and write a random line into them.
This is why the owner user must run the test first, since this block of code will not run afterwards for the other users. The test files are created, and the permissions are set to RW for the owner (6), and R for the rest (4).
2) Open the files with fopen(... , "r"). This is expected to succeed for both the owner and the malicious users, since they all have "read" rights for the files.
3) Open the files with fopen(..., "a"), and append text to them using fwrite(). This is expected to succeed for the owner, and fail for the other users.
This is a key point, since beign allowed write access to these 6 text files WILL flag them as malicious. You can verify this by running ```./audit_monitor -s``` after running the test as a malicious user.
4) Open ONLY 2 of the files with fopen(..., "r"), then try to write something using fwrite().
Of course, this will fail for ALL users, since they will try to write inside a file while having opened it in read-only mode. However, this will not lead to the owner user being flagged as malicious, since this test case happens on only 2 of the files, as we mentioned.

To run the test as a malicious user, you can create a random user in the terminal. We named our user "attacker1".

### Running the test and viewing results.
First of all, run ```make all``` in the terminal.
Then, for your own user, run ```LD_PRELOAD=./audit_logger.so ./test_audit```.
Then, for a malicious user, having created a second account, run ```sudo -u attacker1 bash -c 'cd /home/.../compSec3/src_corpus && LD_PRELOAD=./audit_logger.so ./test_audit'``` and use your own path to src_corpus. We had to manually grant rights to the malicious user, so they can ```cd``` into our directories and execute the test.
When you're done with the test and the log is filled, then you can freely execute ```./audit_logger -s``` or ```./audit_logger -i <filename>``` to see the results.
The way we have made the test, you should be able to confirm that the monitoring tool works as intended, by seeing the secondary user flagged as malicious on the first time that you run the test.

!! **In the delivered files, we have already run the test, once as the owner and once as the malicious user. You can just use the monitoring tool straight away if you want. Otherwise, you can run the test on your own. It is suggested that you clear the log manually first to delete the logs from our attempt.**

