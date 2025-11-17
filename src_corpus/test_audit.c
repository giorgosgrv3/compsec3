#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>   // for access()

int main(void)
{
    const char *files[6] = {
        "protected_0",
        "protected_1",
        "protected_2",
        "protected_3",
        "protected_4",
        "protected_5"
    };

    FILE *f, *f1;
    int i;

	// this loop will ONLY run for the FIRST user who runs it, so we have to make sure we run it as owner first
	// the rest will run for all users
    printf("[1] Ensuring test files exist (created if missing, chmod 644 if possible)\n");

    for (i = 0; i < 6; i++) {
        if (access(files[i], F_OK) != 0) { // if file does not exist, then try to create it
            f = fopen(files[i], "w");
            if (!f) {
                perror("fopen create");
                // continue so later steps still try to open/write
                continue;
            }
            fwrite("initial data\n", 1, strlen("initial data\n"), f);
            fclose(f);
            printf("Created %s\n", files[i]);
        }

        // Try to set mode 0644 (rw-r--r--)
        // we (owner) can write, others can read only.
        if (chmod(files[i], 0644) != 0) {
        }
    }

    printf("\n[2] OPEN test: fopen(..., 'r') on all files. this must fail if executing user has no 'read' rights.\n");

    for (i = 0; i < 6; i++) {
        printf("Opening %s for read...\n", files[i]);
        f = fopen(files[i], "r");
        if (!f) {
            printf("\t[DENIED] fopen failed with errno=%d (%s)\n",
                   errno, strerror(errno));
        } else {
            printf("\t[ACCESSED] fopen success\n");
            fclose(f);
        }
    }

    printf("\n[3] WRITE test: fopen(..., 'a'), then try fwrite(). (this must fail if executing user has no 'write' rights.) \n");

		for (i = 0; i < 6; i++) {
			printf("Opening %s for read, then attempting fwrite...\n", files[i]);
			f = fopen(files[i], "a");
			if (!f) {
				printf("\t[FOPEN DENIED] fopen failed with errno=%d (%s)\n",
					errno, strerror(errno));
				continue;
			}

			const char *msg = "attempted write\n";
			size_t len = strlen(msg);
			size_t written = fwrite(msg, 1, len, f);

			if (written != len) {
				printf("\t[FWRITE DENIED] fwrite wrote %zu of %zu bytes\n",
					written, len);
			} else {
				printf("\t[FWRITE SUCCESS]\n");
			}

			fclose(f);
		}


	printf("\n[4] WRITE test: fopen(..., 'r'), then try fwrite() (this must fail for all)\n");

		for (i = 0; i < 2; i++) {
			printf("Opening %s for read, then attempting fwrite...\n", files[i]);
			f = fopen(files[i], "r");
			if (!f) {
				printf("\t[DENIED-OPEN] fopen failed with errno=%d (%s)\n",
					errno, strerror(errno));
				continue;
			}

			const char *msg = "attempted write\n";
			size_t len = strlen(msg);
			size_t written = fwrite(msg, 1, len, f);

			if (written != len) {
				printf("  [DENIED-WRITE] fwrite wrote %zu of %zu bytes\n",
					written, len);
			} else {
				printf("  [ALLOWED-WRITE] fwrite unexpectedly succeeded\n");
			}

			fclose(f);
		}


    printf("\nDone.\n");
    return 0;
}
