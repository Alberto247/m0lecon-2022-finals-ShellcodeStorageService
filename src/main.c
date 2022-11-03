

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <linux/seccomp.h>  /* Definition of SECCOMP_* constants */
#include <sys/stat.h>
#include <linux/filter.h>   /* Definition of struct sock_fprog */
#include <linux/audit.h>    /* Definition of AUDIT_* constants */
#include <signal.h>   /* Definition of SIG* constants */
#include <sys/syscall.h>    /* Definition of SYS_* constants */
#include <sys/prctl.h>
#include <fcntl.h>
#include <stddef.h>
#include <dirent.h> 
#include "sha256.h"
#include "base64.h"

FILE* pwdfile;
int tot_shellcodes_run=0;

static int install_shellcode_protections(char* path)
{
    if(chroot(path)){
        perror("Cannot chroot");
        exit(-1);
    }
	struct sock_filter filter[] = {
        /* validate arch */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, (offsetof(struct seccomp_data, arch))),
	    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
	    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),
		/* Grab the system call number. */
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr))),
		/* List allowed syscalls. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lseek, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_stat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fstat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lstat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_nanosleep, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chdir, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 3), //IF NOT WRITE, BLOCK
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[0]))), //IF WRITE GET FIRST ARG
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 3, 1, 0), // IF GREATER OR EQUAL TO 3, BLOCK, ELSE ALLOW
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(-1);
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		exit(-1);
	}
	return 0;
}

void sha256(char* data, int size, char* hash){
    SHA256_CTX context;
    sha256_init(&context);
    sha256_update(&context, data, size);
    sha256_final(&context, hash);
}

static void handler(int sig, siginfo_t *si, void *unused)
{
    puts("Got SIGSEGV or SIGILL or SIGBUS or SIGFPE, looks like your shellcode is broken.");
    exit(-1);
}

void listFiles(char* dirname){
    DIR *d;
    struct dirent *dir;
    d = opendir(dirname);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if(strncmp(dir->d_name, ".", 1)!=0 && strncmp(dir->d_name, "..", 2)!=0){
                printf(" - %s\n", dir->d_name);
            }
        }
        closedir(d);
    }
    return;
}

void printFile(char* dirname){
    char filepath[32+128];
    char filename[128];
    puts("Which shellcode do you want to read?");
    printf("> ");
    fgets(filename, 127, stdin);
    filename[strcspn(filename, "\n")] = 0;
    filename[strcspn(filename, ".")] = 0;
    strncpy(filepath, dirname, 32);
    strcat(filepath, "/");
    strcat(filepath, filename);
    FILE* f = fopen(filepath, "r");
    if(f==NULL){
        puts("Shellcode not found.");
        return;
    }
    char c = fgetc(f);
    while (feof(f)==0)
    {
        printf ("%c", c);
        c = fgetc(f);
    }
    fclose(f);
}

void saveFile(char* dirname){
    char filepath[32+128];
    char filename[128];
    puts("What's the name of your shellcode?");
    printf("> ");
    fgets(filename, 127, stdin);
    filename[strcspn(filename, "\n")] = 0;
    filename[strcspn(filename, ".")] = 0;
    strncpy(filepath, dirname, 32);
    strcat(filepath, "/");
    strcat(filepath, filename);
    FILE* f = fopen(filepath, "w");
    if(f==NULL){
        puts("Could not create a shellcode with that name.");
        return;
    }
    puts("Please send your shellcode.");
    unsigned char encoded_code[256] = {0};
    fgets(encoded_code, 255, stdin);
    size_t out_len;
    char* code = base64_decode(encoded_code, strlen(encoded_code), &out_len);
    if(code==NULL){
        exit(-1);
    }
    fwrite(code, 255, 1, f);
    fclose(f);
    free(code);
}

void runFile(char* dirname){
    char filepath[32+128];
    char filename[128];
    puts("What's the name of your shellcode?");
    printf("> ");
    fgets(filename, 127, stdin);
    filename[strcspn(filename, "\n")] = 0;
    filename[strcspn(filename, ".")] = 0;
    strncpy(filepath, dirname, 32);
    strcat(filepath, "/");
    strcat(filepath, filename);
    FILE* f = fopen(filepath, "r");
    if(f==NULL){
        puts("Could not load a shellcode with that name.");
        return;
    }
    puts("Running your shellcode.");
    unsigned char code[256] = {0};
    read(fileno(f), code, 255);
    fclose(f);
    void (*shellcode) (void) = NULL;
    shellcode = mmap (0, 256, PROT_READ|PROT_WRITE|PROT_EXEC,
          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(shellcode, code, 256);
    __builtin___clear_cache (shellcode, shellcode + sizeof(shellcode));
    if(!fork()){
        struct sigaction action;
        memset(&action, 0, sizeof(struct sigaction));
        action.sa_flags = SA_SIGINFO;
        action.sa_sigaction=handler;
        sigaction(SIGSEGV, &action, NULL);
        sigaction(SIGILL, &action, NULL);
        sigaction(SIGBUS, &action, NULL);
        sigaction(SIGFPE, &action, NULL);
        strncpy(filepath, dirname, 32);
        strcat(filepath, "/");
        install_shellcode_protections(filepath);
        shellcode();
        exit(0);
    }
    sleep(5);
    puts("Your shellcode should have been run!");
}

void runShellcode(char* dirname){
    char filepath[32+128];
    void (*shellcode) (void) = NULL;
    shellcode = mmap (0, 256, PROT_READ|PROT_WRITE|PROT_EXEC,
          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    puts("Send the bytes of your shellcode!");
    unsigned char encoded_code[256] = {0};
    fgets(encoded_code, 255, stdin);
    size_t out_len;
    char* code = base64_decode(encoded_code, strlen(encoded_code), &out_len);
    if(code==NULL){
        exit(-1);
    }
    memcpy(shellcode, code, 256);
    __builtin___clear_cache (shellcode, shellcode + sizeof(shellcode));
    if(!fork()){
        struct sigaction action;
        memset(&action, 0, sizeof(struct sigaction));
        action.sa_flags = SA_SIGINFO;
        action.sa_sigaction=handler;
        sigaction(SIGSEGV, &action, NULL);
        sigaction(SIGILL, &action, NULL);
        sigaction(SIGBUS, &action, NULL);
        sigaction(SIGFPE, &action, NULL);
        strncpy(filepath, dirname, 32);
        strcat(filepath, "/");
        install_shellcode_protections(filepath);
        shellcode();
        exit(0);
    }
    sleep(5);
    puts("Your shellcode should have been run!");
    free(code);
}

void userMenu(int id){
        puts("");
        printf("Welcome to your private area user %d!\n", id);
        puts("1. List your shellcodes");
        puts("2. Print a shellcode");
        puts("3. Save a shellcode");
        puts("4. Execute a shellcode");
        puts("5. Execute a shellcode without saving it");
        puts("6. Logout");
        printf("> ");
}

void userHandler(int id){
    char choice;
    char dirname[32];
    sprintf(dirname, "./data/%d", id);
    while(1){
        userMenu(id);
        read(STDIN_FILENO, &choice, 1);
        getchar();
        if(choice=='6'){
            puts("Goodbye!");
            return;
        }else if(choice=='1'){
            listFiles(dirname);
        }else if(choice=='2'){
            printFile(dirname);
        }else if(choice=='3'){
            saveFile(dirname);
        }else if(choice=='4'){
            if(tot_shellcodes_run<5){
                tot_shellcodes_run++;
                runFile(dirname);
            }else{
                puts("Sorry, only 5 shellcodes can be run. Please disconnect and reconnect to run more.");
            }
        }else if(choice=='5'){
            if(tot_shellcodes_run<5){
                tot_shellcodes_run++;
                runShellcode(dirname);
            }else{
                puts("Sorry, only 5 shellcodes can be run. Please disconnect and reconnect to run more.");
            }
        }else{
            puts("Unknown option.");
        }
    }
}

void initialize(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void banner(){
    printf(" _______________________\n");
    printf("/                       \\\n");
    printf("|   _________________   |\n|  /   _____/\\_____  \\  |\n|  \\_____  \\   _(__  <  |\n| /_________//________/ |\n");
    printf("\\_______________________/\n");
}

void mainMenu(){
    puts("");
    puts("Welcome to S3 (Shellcode Storage Service)!");
    puts("1. Log In");
    puts("2. Register");
    puts("3. Exit");
    printf("> ");
}

void loginUser(){
    int id;
    printf("Please insert your ID: ");
    fscanf(stdin, "%d", &id);
    getchar();
    lseek(fileno(pwdfile), id<<5, SEEK_SET);
    printf("Please insert your password: ");
    char userpwd[64];
    char hash[32];
    fgets(userpwd, 63, stdin);
    userpwd[strcspn(userpwd, "\n")] = 0;
    sha256(userpwd, strlen(userpwd), hash); //hash password
    char correct_hash[32];
    read(fileno(pwdfile), correct_hash, 32);
    if(memcmp(hash, correct_hash, 32)==0){
       userHandler(id); 
    }else{
        puts("Wrong password!");
    }
}

void registerUser(){
    char userpwd[64];
    char hash[32];
    printf("Please insert your password: ");
    fgets(userpwd, 63, stdin);
    userpwd[strcspn(userpwd, "\n")] = 0;
    sha256(userpwd, strlen(userpwd), hash); //hash password
    struct flock f;
    f.l_type=F_WRLCK;
    f.l_whence=SEEK_END;
    f.l_start=0;
    f.l_len=32;
    if(fcntl(fileno(pwdfile), F_SETLKW, &f)){ //lock file from end 32 bytes
        perror("Cannot lock file");
        exit(-1);
    }
    struct stat s;
    lseek(fileno(pwdfile), 0, SEEK_END); //move to end
    fstat(fileno(pwdfile), &s); //get file size now
    int id = s.st_size >> 5; //calculate user's id
    write(fileno(pwdfile), hash, 32); //write pwd
    f.l_type=F_UNLCK;
    f.l_whence=SEEK_SET;
    f.l_start=s.st_size;
    f.l_len=32;
    if(fcntl(fileno(pwdfile), F_SETLKW, &f)){ //unlock file, use old size and not seek_end as size changes
        perror("Cannot unlock file");
        exit(-1);
    }
    char dirname[32];
    sprintf(dirname, "./data/%d", id);
    mkdir(dirname, 0777);
    printf("Your user's ID is: %d\n", id);
}

int main(){
    initialize();
    banner();
    char choice;
    pwdfile = fopen("passwords", "a+");
    struct stat st;
    if (stat("./data", &st) == -1) {
        mkdir("./data", 0777);
    }
    while(1){
        mainMenu();
        read(STDIN_FILENO, &choice, 1);
        getchar();
        if(choice=='3'){
            printf("Goodbye!");
            exit(0);
        }else if(choice=='1'){
            loginUser();
        }else if(choice=='2'){
            registerUser();
        }else{
            puts("Unknown option.");
        }
    }
}